"""Lateral movement detection module."""

from typing import Dict, List, Set, Any
from collections import defaultdict


class LateralMovementDetector:
    """Detect lateral movement patterns."""
    
    # Protocols commonly used for lateral movement
    LM_PROTOCOLS = {
        445: 'SMB',
        139: 'NetBIOS',
        135: 'MSRPC',
        3389: 'RDP',
        22: 'SSH',
        23: 'Telnet',
        5900: 'VNC',
        5985: 'WinRM_HTTP',
        5986: 'WinRM_HTTPS',
    }
    
    # Suspicious SMB operations (simplified detection)
    SUSPICIOUS_SMB_PATTERNS = [
        b'\\\\\x00\\x00',  # Null session pattern
    ]
    
    def __init__(self):
        self.alerts: List[Dict] = []
        
    def analyze(self, flows, packets, parser) -> List[Dict]:
        """Analyze for lateral movement patterns."""
        self.alerts = []

        self._detect_rdp_anomalies(flows)
        self._detect_rdp_subnet_sweep(flows)
        self._detect_external_rdp_controller(flows)
        self._detect_psexec_patterns(flows, packets)
        self._detect_ssh_lateral(flows)
        self._detect_remote_access_tools(packets)
        self._detect_kerberoasting(flows)
        self._detect_ntlm_relay(flows)
        self._detect_winrm(flows)

        return self.alerts
        
    def _detect_rdp_anomalies(self, flows) -> None:
        """Detect suspicious RDP activity."""
        rdp_activity = defaultdict(lambda: {
            'targets': set(),
            'connections': 0,
            'short_sessions': 0,
        })
        
        for flow in flows.values():
            if flow.dst_port == 3389:
                source = flow.src_ip
                rdp_activity[source]['targets'].add(flow.dst_ip)
                rdp_activity[source]['connections'] += 1
                
                # Short RDP sessions may indicate failed auth or scanning
                if flow.duration < 30:
                    rdp_activity[source]['short_sessions'] += 1
                    
        for source, data in rdp_activity.items():
            if len(data['targets']) >= 3 or data['short_sessions'] >= 5:
                self.alerts.append({
                    'type': 'rdp_lateral_movement',
                    'severity': 'high',
                    'source_ip': source,
                    'description': f"Suspicious RDP activity from {source}",
                    'evidence': {
                        'rdp_targets': len(data['targets']),
                        'sample_targets': list(data['targets'])[:10],
                        'total_connections': data['connections'],
                        'short_sessions': data['short_sessions'],
                    },
                    'confidence': 0.8,
                })
                
    def _detect_psexec_patterns(self, flows, packets) -> None:
        """Detect PsExec-like service installation patterns."""
        # PsExec typically uses SMB to create a service
        # Pattern: SMB to ADMIN$ share, then service creation
        
        psexec_candidates = defaultdict(lambda: {
            'targets': set(),
            'evidence': [],
        })
        
        for flow in flows.values():
            if flow.dst_port == 445:
                # Look for service control manager patterns
                for pkt in flow.packets:
                    if pkt.payload:
                        # Check for SCM pipe patterns (simplified)
                        payload_str = str(pkt.payload)
                        if 'svcctl' in payload_str.lower() or 'CreateService' in payload_str:
                            psexec_candidates[flow.src_ip]['targets'].add(flow.dst_ip)
                            psexec_candidates[flow.src_ip]['evidence'].append({
                                'target': flow.dst_ip,
                                'timestamp': str(pkt.timestamp),
                            })
                            
        for source, data in psexec_candidates.items():
            if len(data['targets']) >= 2:
                self.alerts.append({
                    'type': 'possible_psexec',
                    'severity': 'critical',
                    'source_ip': source,
                    'description': f"Possible PsExec service installation from {source}",
                    'evidence': {
                        'targets': list(data['targets']),
                        'installation_attempts': len(data['evidence']),
                    },
                    'confidence': 0.85,
                })
                
    def _detect_rdp_subnet_sweep(self, flows) -> None:
        """Detect RDP sweeps across a /24 subnet — attacker pivoting through the host."""
        rdp_by_src = defaultdict(lambda: {'targets': set(), 'subnets': defaultdict(set)})
        for flow in flows.values():
            if flow.dst_port == 3389:
                src = flow.src_ip
                dst = flow.dst_ip
                rdp_by_src[src]['targets'].add(dst)
                # Group by /24
                subnet = '.'.join(dst.split('.')[:3])
                rdp_by_src[src]['subnets'][subnet].add(dst)

        for src, data in rdp_by_src.items():
            for subnet, hosts in data['subnets'].items():
                if len(hosts) >= 10:  # 10+ hosts in same /24
                    self.alerts.append({
                        'type': 'rdp_subnet_sweep',
                        'severity': 'critical',
                        'source_ip': src,
                        'description': f"RDP subnet sweep from {src} targeting {subnet}.0/24 ({len(hosts)} hosts)",
                        'evidence': {
                            'subnet': f"{subnet}.0/24",
                            'hosts_targeted': len(hosts),
                            'sample_targets': sorted(hosts)[:10],
                            'total_rdp_targets': len(data['targets']),
                        },
                        'confidence': min(0.97, 0.80 + len(hosts) * 0.002),
                    })

    def _detect_external_rdp_controller(self, flows) -> None:
        """Detect inbound RDP from external IPs — attacker controlling the host via RDP."""
        def is_internal(ip: str) -> bool:
            p = ip.split('.')
            if len(p) != 4:
                return False
            try:
                a, b = int(p[0]), int(p[1])
                return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
            except ValueError:
                return False

        rdp_controllers = defaultdict(lambda: {'targets': set(), 'flows': 0, 'total_bytes': 0})
        for flow in flows.values():
            if flow.dst_port == 3389 and not is_internal(flow.src_ip):
                rdp_controllers[flow.src_ip]['targets'].add(flow.dst_ip)
                rdp_controllers[flow.src_ip]['flows'] += 1
                rdp_controllers[flow.src_ip]['total_bytes'] += flow.total_bytes

        for src, data in rdp_controllers.items():
            if data['flows'] >= 2 or data['total_bytes'] > 500 * 1024:  # 2+ flows or >500KB
                self.alerts.append({
                    'type': 'external_rdp_controller',
                    'severity': 'critical',
                    'source_ip': src,
                    'description': f"External IP {src} controlling host via inbound RDP",
                    'evidence': {
                        'rdp_targets': list(data['targets']),
                        'rdp_flows': data['flows'],
                        'total_bytes': data['total_bytes'],
                    },
                    'confidence': 0.88,
                })

    def _detect_remote_access_tools(self, packets) -> None:
        """Detect AnyDesk, TeamViewer, ScreenConnect DNS queries — attacker persistent GUI access."""
        RAT_DOMAINS = {
            'anydesk.com': 'AnyDesk',
            'teamviewer.com': 'TeamViewer',
            'screenconnect.com': 'ScreenConnect',
            'logmein.com': 'LogMeIn',
            'trassir.com': 'TRASSIR (Russian surveillance)',
        }
        rat_hits = defaultdict(lambda: {'tool': '', 'domains': set(), 'queried_by': set()})
        for pkt in packets:
            if pkt.dns_query:
                q = pkt.dns_query.get('query', '').lower()
                for domain, tool in RAT_DOMAINS.items():
                    if domain in q:
                        rat_hits[domain]['tool'] = tool
                        rat_hits[domain]['domains'].add(q)
                        rat_hits[domain]['queried_by'].add(pkt.src_ip)

        for domain, data in rat_hits.items():
            self.alerts.append({
                'type': 'remote_access_tool_detected',
                'severity': 'high',
                'source_ip': list(data['queried_by'])[0] if data['queried_by'] else '?',
                'description': f"{data['tool']} remote access tool detected via DNS: {domain}",
                'evidence': {
                    'tool': data['tool'],
                    'domains_queried': list(data['domains'])[:5],
                    'queried_by': list(data['queried_by']),
                },
                'confidence': 0.85,
            })

    def _detect_winrm(self, flows) -> None:
        """Detect WinRM usage — almost always attacker tooling (Evil-WinRM) when from external IPs.

        Ports 5985 (HTTP) and 5986 (HTTPS). Legitimate WinRM is internal only.
        Any external source using WinRM is near-certain compromise.
        """
        def is_internal(ip: str) -> bool:
            p = ip.split('.')
            if len(p) != 4:
                return False
            try:
                a, b = int(p[0]), int(p[1])
                return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
            except ValueError:
                return False

        WINRM_PORTS = {5985: 'WinRM-HTTP', 5986: 'WinRM-HTTPS'}
        winrm_by_src: Dict = defaultdict(lambda: {'targets': set(), 'flows': 0, 'total_bytes': 0, 'ports': set()})

        for flow in flows.values():
            if flow.dst_port in WINRM_PORTS:
                winrm_by_src[flow.src_ip]['targets'].add(flow.dst_ip)
                winrm_by_src[flow.src_ip]['flows'] += 1
                winrm_by_src[flow.src_ip]['total_bytes'] += flow.total_bytes
                winrm_by_src[flow.src_ip]['ports'].add(flow.dst_port)

        for src, data in winrm_by_src.items():
            is_external = not is_internal(src)
            if data['flows'] >= 1:  # Any WinRM from external = alert; internal needs >= 3 targets
                if is_external or len(data['targets']) >= 3:
                    severity = 'critical' if is_external else 'high'
                    confidence = 0.92 if is_external else min(0.85, 0.65 + data['flows'] * 0.02)
                    protocols = [WINRM_PORTS[p] for p in data['ports']]
                    self.alerts.append({
                        'type': 'winrm_lateral_movement',
                        'severity': severity,
                        'source_ip': src,
                        'description': (
                            f"{'External' if is_external else 'Internal'} WinRM access from {src} "
                            f"to {len(data['targets'])} host(s) ({', '.join(protocols)})"
                        ),
                        'evidence': {
                            'source_is_external': is_external,
                            'protocols': protocols,
                            'targets': list(data['targets'])[:10],
                            'flows': data['flows'],
                            'total_bytes': data['total_bytes'],
                        },
                        'confidence': confidence,
                    })

    def _detect_kerberoasting(self, flows) -> None:
        """Detect Kerberoasting / AS-REP Roasting attempts.

        Kerberoasting: attacker requests many TGS tickets (port 88) to a DC.
        Signature: single source sending many short Kerberos flows to the same DC IP.
        AS-REP Roasting: similar pattern but with PREAUTH-disabled accounts.
        """
        kerb_by_src: Dict = defaultdict(lambda: {'dcs': set(), 'flows': 0})
        for flow in flows.values():
            if flow.dst_port == 88:  # Kerberos
                kerb_by_src[flow.src_ip]['dcs'].add(flow.dst_ip)
                kerb_by_src[flow.src_ip]['flows'] += 1

        for src, data in kerb_by_src.items():
            if data['flows'] >= 10:  # Many Kerberos requests from single source
                self.alerts.append({
                    'type': 'possible_kerberoasting',
                    'severity': 'critical',
                    'source_ip': src,
                    'description': f"Possible Kerberoasting/AS-REP Roasting from {src} ({data['flows']} Kerberos flows)",
                    'evidence': {
                        'kerberos_flows': data['flows'],
                        'target_dcs': list(data['dcs']),
                    },
                    'confidence': min(0.90, 0.65 + data['flows'] * 0.01),
                })

    def _detect_ntlm_relay(self, flows) -> None:
        """Detect NTLM relay setup: source connecting to SMB on multiple hosts near-simultaneously.

        Classic relay: attacker sits between two hosts, forwarding NTLM auth.
        Signature: same source IP opens SMB (445) to 2+ distinct hosts within a short window,
        with short flows (relay completes quickly once auth is captured).
        """
        smb_flows_by_src: Dict = defaultdict(list)
        for flow in flows.values():
            if flow.dst_port == 445 and flow.start_time:
                smb_flows_by_src[flow.src_ip].append(flow)

        for src, flist in smb_flows_by_src.items():
            if len(flist) < 2:
                continue
            flist_sorted = sorted(flist, key=lambda f: f.start_time)
            # Sliding window: look for 2+ SMB connections to different hosts within 5s
            for i in range(len(flist_sorted) - 1):
                f1 = flist_sorted[i]
                f2 = flist_sorted[i + 1]
                delta = (f2.start_time - f1.start_time).total_seconds()
                if delta <= 5 and f1.dst_ip != f2.dst_ip:
                    # Both flows are short (relay, not real usage)
                    if f1.packet_count <= 20 and f2.packet_count <= 20:
                        self.alerts.append({
                            'type': 'possible_ntlm_relay',
                            'severity': 'critical',
                            'source_ip': src,
                            'description': (
                                f"Possible NTLM relay from {src}: SMB to "
                                f"{f1.dst_ip} and {f2.dst_ip} within {delta:.1f}s"
                            ),
                            'evidence': {
                                'smb_target_1': f1.dst_ip,
                                'smb_target_2': f2.dst_ip,
                                'delta_seconds': round(delta, 2),
                                'flow1_packets': f1.packet_count,
                                'flow2_packets': f2.packet_count,
                            },
                            'confidence': 0.78,
                        })
                        break  # One alert per source per analysis

    def _detect_ssh_lateral(self, flows) -> None:
        """Detect SSH-based lateral movement."""
        ssh_activity = defaultdict(lambda: {
            'targets': set(),
            'connections': 0,
            'successful': 0,
        })
        
        for flow in flows.values():
            if flow.dst_port == 22:
                source = flow.src_ip
                ssh_activity[source]['targets'].add(flow.dst_ip)
                ssh_activity[source]['connections'] += 1
                
                # Longer flows indicate successful connection
                if flow.packet_count > 10 and flow.duration > 10:
                    ssh_activity[source]['successful'] += 1
                    
        for source, data in ssh_activity.items():
            if len(data['targets']) >= 5 or (data['successful'] >= 3 and len(data['targets']) >= 3):
                self.alerts.append({
                    'type': 'ssh_lateral_movement',
                    'severity': 'high',
                    'source_ip': source,
                    'description': f"SSH lateral movement suspected from {source}",
                    'evidence': {
                        'ssh_targets': len(data['targets']),
                        'sample_targets': list(data['targets'])[:10],
                        'total_connections': data['connections'],
                        'successful_connections': data['successful'],
                    },
                    'confidence': 0.8,
                })
