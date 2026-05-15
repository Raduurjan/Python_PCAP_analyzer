"""Credential access detection module."""

from typing import Dict, List, Any
from collections import defaultdict


class CredentialAccessDetector:
    """Detect credential theft and access patterns."""

    # Brute force: many short failed connections to auth ports from one source
    BRUTE_FORCE_THRESHOLD = 15       # flows to same target:port
    BRUTE_FORCE_FLOW_DURATION = 5.0  # seconds — failed auth flows are short
    BRUTE_FORCE_PORTS = {22, 23, 3389, 445, 139, 21, 25, 110, 143, 5900, 5985, 5986}

    # Password spray: same source, same port, many *different* targets
    SPRAY_HOST_THRESHOLD = 10        # distinct hosts hit on same port

    # LDAP enumeration threshold
    LDAP_FLOW_THRESHOLD = 20

    # SMB admin share strings indicating credential dumping
    SMB_ADMIN_SHARES = (b'ADMIN$', b'admin$', b'C$', b'c$', b'IPC$', b'ipc$')

    def __init__(self):
        self.alerts: List[Dict] = []

    def analyze(self, flows, packets, parser) -> List[Dict]:
        """Analyze for credential access patterns."""
        self.alerts = []

        self._detect_brute_force(flows)
        self._detect_password_spray(flows)
        self._detect_ldap_enumeration(flows)
        self._detect_smb_admin_share_access(flows, packets)

        return self.alerts

    def _detect_brute_force(self, flows) -> None:
        """Detect brute force: many short flows from one source to same target:port."""
        # key: (src_ip, dst_ip, dst_port) -> evidence
        attempts: Dict = defaultdict(lambda: {'flows': 0, 'total_bytes': 0, 'short_flows': 0})

        for flow in flows.values():
            if flow.dst_port not in self.BRUTE_FORCE_PORTS:
                continue
            key = (flow.src_ip, flow.dst_ip, flow.dst_port)
            attempts[key]['flows'] += 1
            attempts[key]['total_bytes'] += flow.total_bytes
            if flow.duration <= self.BRUTE_FORCE_FLOW_DURATION:
                attempts[key]['short_flows'] += 1

        for (src, dst, port), data in attempts.items():
            if data['flows'] >= self.BRUTE_FORCE_THRESHOLD and data['short_flows'] >= self.BRUTE_FORCE_THRESHOLD * 0.6:
                service = self._port_to_service(port)
                self.alerts.append({
                    'type': 'brute_force',
                    'severity': 'critical',
                    'source_ip': src,
                    'destination': f"{dst}:{port}",
                    'description': (
                        f"Brute force attack from {src} against {dst}:{port} ({service}): "
                        f"{data['flows']} attempts"
                    ),
                    'evidence': {
                        'target': dst,
                        'port': port,
                        'service': service,
                        'total_flows': data['flows'],
                        'short_flows': data['short_flows'],
                        'total_bytes': data['total_bytes'],
                    },
                    'confidence': min(0.95, 0.70 + data['flows'] * 0.005),
                })

    def _detect_password_spray(self, flows) -> None:
        """Detect password spray: one source hits same port on many different hosts."""
        # key: (src_ip, dst_port) -> set of target IPs
        spray: Dict = defaultdict(lambda: {'targets': set(), 'short_flows': 0, 'total_flows': 0})

        for flow in flows.values():
            if flow.dst_port not in self.BRUTE_FORCE_PORTS:
                continue
            key = (flow.src_ip, flow.dst_port)
            spray[key]['targets'].add(flow.dst_ip)
            spray[key]['total_flows'] += 1
            if flow.duration <= self.BRUTE_FORCE_FLOW_DURATION:
                spray[key]['short_flows'] += 1

        for (src, port), data in spray.items():
            if len(data['targets']) >= self.SPRAY_HOST_THRESHOLD:
                service = self._port_to_service(port)
                self.alerts.append({
                    'type': 'password_spray',
                    'severity': 'critical',
                    'source_ip': src,
                    'description': (
                        f"Password spray from {src} on port {port} ({service}): "
                        f"{len(data['targets'])} hosts targeted"
                    ),
                    'evidence': {
                        'port': port,
                        'service': service,
                        'hosts_targeted': len(data['targets']),
                        'sample_targets': sorted(data['targets'])[:10],
                        'total_flows': data['total_flows'],
                        'short_flows': data['short_flows'],
                    },
                    'confidence': min(0.93, 0.72 + len(data['targets']) * 0.01),
                })

    def _detect_ldap_enumeration(self, flows) -> None:
        """Detect LDAP enumeration — attacker mapping Active Directory structure."""
        LDAP_PORTS = {389, 636, 3268, 3269}  # LDAP, LDAPS, GC, GC-SSL
        ldap_by_src: Dict = defaultdict(lambda: {'targets': set(), 'flows': 0, 'total_bytes': 0})

        for flow in flows.values():
            if flow.dst_port in LDAP_PORTS:
                ldap_by_src[flow.src_ip]['targets'].add(flow.dst_ip)
                ldap_by_src[flow.src_ip]['flows'] += 1
                ldap_by_src[flow.src_ip]['total_bytes'] += flow.total_bytes

        for src, data in ldap_by_src.items():
            if data['flows'] >= self.LDAP_FLOW_THRESHOLD:
                self.alerts.append({
                    'type': 'ldap_enumeration',
                    'severity': 'high',
                    'source_ip': src,
                    'description': f"LDAP enumeration from {src}: {data['flows']} LDAP queries to {len(data['targets'])} hosts",
                    'evidence': {
                        'ldap_flows': data['flows'],
                        'target_hosts': list(data['targets'])[:10],
                        'total_bytes': data['total_bytes'],
                    },
                    'confidence': min(0.90, 0.65 + data['flows'] * 0.01),
                })

    def _detect_smb_admin_share_access(self, flows, packets) -> None:
        """Detect access to admin shares (ADMIN$, C$, IPC$) — credential dumping precursor."""
        share_access: Dict = defaultdict(lambda: {'targets': set(), 'shares': set(), 'evidence': []})

        for flow in flows.values():
            if flow.dst_port != 445:
                continue
            for pkt in flow.packets:
                if not pkt.payload:
                    continue
                payload = pkt.payload if isinstance(pkt.payload, bytes) else pkt.payload.encode('latin-1', errors='replace')
                for share in self.SMB_ADMIN_SHARES:
                    if share in payload:
                        share_access[flow.src_ip]['targets'].add(flow.dst_ip)
                        share_access[flow.src_ip]['shares'].add(share.decode('ascii', errors='replace').rstrip('$') + '$')
                        share_access[flow.src_ip]['evidence'].append({
                            'target': flow.dst_ip,
                            'share': share.decode('ascii', errors='replace'),
                            'timestamp': str(pkt.timestamp),
                        })
                        break  # One match per packet

        for src, data in share_access.items():
            self.alerts.append({
                'type': 'smb_admin_share_access',
                'severity': 'critical',
                'source_ip': src,
                'description': f"Admin share access from {src}: {', '.join(data['shares'])} on {len(data['targets'])} host(s)",
                'evidence': {
                    'shares_accessed': list(data['shares']),
                    'targets': list(data['targets'])[:10],
                    'access_count': len(data['evidence']),
                },
                'confidence': 0.88,
            })

    @staticmethod
    def _port_to_service(port: int) -> str:
        """Map port to service name."""
        return {
            22: 'SSH', 23: 'Telnet', 21: 'FTP', 25: 'SMTP',
            110: 'POP3', 143: 'IMAP', 445: 'SMB', 139: 'NetBIOS',
            3389: 'RDP', 5900: 'VNC', 5985: 'WinRM-HTTP', 5986: 'WinRM-HTTPS',
        }.get(port, str(port))
