"""Reconnaissance and scanning detection module."""

from typing import Dict, List, Set, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class ScanSignature:
    """Detected scanning signature."""
    scanner_ip: str
    target_ip: str
    scan_type: str
    ports_scanned: Set[int]
    timestamp_start: Any
    timestamp_end: Any
    packet_count: int
    confidence: float


class ReconnaissanceDetector:
    """Detect network reconnaissance activities."""
    
    # Thresholds for scan detection
    SYN_SCAN_THRESHOLD = 10
    CONNECT_SCAN_THRESHOLD = 10
    PING_SWEEP_THRESHOLD = 5
    PORT_SCAN_WINDOW = 60  # seconds
    
    def __init__(self):
        self.syn_packets: Dict[str, List[Tuple[Any, int, str]]] = defaultdict(list)
        self.icmp_requests: Dict[str, List[Any]] = defaultdict(list)
        self.udp_probes: Dict[str, List[Tuple[Any, int]]] = defaultdict(list)
        self.alerts: List[Dict] = []
        
    # Detection modules enabled/disabled
    DETECT_SYN_SCAN = False  # Disabled - too noisy from internet background
    DETECT_UDP_SCAN = False  # Disabled - too noisy
    DETECT_OS_FINGERPRINTING = False  # Disabled - 74% false positives
    DETECT_PING_SWEEP = True
    DETECT_PORT_SCAN_PATTERNS = True
    DETECT_SERVICE_SWEEP = True
    
    def analyze(self, flows, packets, parser) -> List[Dict]:
        """Analyze flows and packets for reconnaissance patterns."""
        self.alerts = []

        if self.DETECT_SYN_SCAN:
            self._detect_syn_scan(flows)
        if self.DETECT_PING_SWEEP:
            self._detect_ping_sweep(packets)
        if self.DETECT_UDP_SCAN:
            self._detect_udp_scan(flows)
        if self.DETECT_OS_FINGERPRINTING:
            self._detect_os_fingerprinting(flows)
        if self.DETECT_PORT_SCAN_PATTERNS:
            self._detect_port_scan_patterns(flows)
        if self.DETECT_SERVICE_SWEEP:
            self._detect_service_sweep(flows)

        return self.alerts
        
    def _detect_syn_scan(self, flows) -> None:
        """Detect SYN scan (half-open scanning)."""
        syn_scans = defaultdict(lambda: {'targets': set(), 'ports': set(), 'packets': 0})
        
        for flow in flows.values():
            if flow.protocol == "TCP":
                # Check for SYN-only patterns (no completion)
                syn_count = sum(1 for p in flow.packets if p.flags.get('SYN') and not p.flags.get('ACK'))
                ack_count = sum(1 for p in flow.packets if p.flags.get('ACK') and not p.flags.get('SYN'))
                
                # SYN scan: many SYNs, few/no ACKs
                if syn_count > 0 and ack_count == 0 and flow.packet_count <= 3:
                    scanner = flow.src_ip
                    target = flow.dst_ip
                    port = flow.dst_port
                    
                    if port:
                        syn_scans[scanner]['targets'].add(target)
                        syn_scans[scanner]['ports'].add(port)
                        syn_scans[scanner]['packets'] += flow.packet_count
                        
        # Generate alerts for significant SYN scans
        for scanner, data in syn_scans.items():
            if len(data['ports']) >= self.SYN_SCAN_THRESHOLD:
                self.alerts.append({
                    'type': 'syn_scan',
                    'severity': 'high',
                    'source_ip': scanner,
                    'description': f"Possible SYN scan detected from {scanner}",
                    'evidence': {
                        'unique_targets': len(data['targets']),
                        'ports_scanned': len(data['ports']),
                        'sample_ports': list(data['ports'])[:10],
                        'total_packets': data['packets'],
                    },
                    'confidence': min(0.95, 0.7 + (len(data['ports']) / 100)),
                })
                
    def _detect_ping_sweep(self, packets) -> None:
        """Detect ICMP ping sweeps by counting unique ICMP targets per source."""
        icmp_sources = defaultdict(lambda: {'targets': set(), 'count': 0})

        for pkt in packets:
            if pkt.protocol == "ICMP" and pkt.src_ip and pkt.dst_ip:
                icmp_sources[pkt.src_ip]['targets'].add(pkt.dst_ip)
                icmp_sources[pkt.src_ip]['count'] += 1

        for source, data in icmp_sources.items():
            if len(data['targets']) >= self.PING_SWEEP_THRESHOLD:
                self.alerts.append({
                    'type': 'ping_sweep',
                    'severity': 'medium',
                    'source_ip': source,
                    'description': f"Possible ping sweep detected from {source}",
                    'evidence': {
                        'targets_swept': len(data['targets']),
                        'sample_targets': list(data['targets'])[:10],
                        'icmp_packets': data['count'],
                    },
                    'confidence': min(0.9, 0.6 + (len(data['targets']) / 50)),
                })
                
    def _detect_udp_scan(self, flows) -> None:
        """Detect UDP port scanning."""
        udp_scans = defaultdict(lambda: {'targets': set(), 'ports': set()})
        
        for flow in flows.values():
            if flow.protocol == "UDP":
                # UDP scans typically have low packet count per port
                if flow.packet_count <= 2:
                    scanner = flow.src_ip
                    target = flow.dst_ip
                    port = flow.dst_port
                    
                    if port:
                        udp_scans[scanner]['targets'].add(target)
                        udp_scans[scanner]['ports'].add(port)
                        
        # Generate alerts for UDP scans
        for scanner, data in udp_scans.items():
            if len(data['ports']) >= 15:
                self.alerts.append({
                    'type': 'udp_scan',
                    'severity': 'medium',
                    'source_ip': scanner,
                    'description': f"Possible UDP scan detected from {scanner}",
                    'evidence': {
                        'unique_targets': len(data['targets']),
                        'ports_scanned': len(data['ports']),
                        'sample_ports': list(data['ports'])[:10],
                    },
                    'confidence': min(0.85, 0.6 + (len(data['ports']) / 100)),
                })
                
    def _detect_os_fingerprinting(self, flows) -> None:
        """Detect OS fingerprinting attempts (e.g., Nmap OS detection)."""
        fingerprinting_hosts = defaultdict(lambda: {
            'targets': set(),
            'unusual_flags': 0,
            'tcp_options_seen': set(),
        })
        
        for flow in flows.values():
            if flow.protocol == "TCP":
                # Check for unusual flag combinations
                unusual_flags = 0
                for pkt in flow.packets:
                    flags = pkt.flags
                    # Check for weird flag combos used in OS detection
                    if flags.get('FIN') and flags.get('PSH') and flags.get('URG'):
                        unusual_flags += 1  # Christmas scan
                    if flags.get('FIN') and not flags.get('SYN') and not flags.get('RST'):
                        unusual_flags += 1  # FIN scan
                    if not any(flags.values()):
                        unusual_flags += 1  # Null scan
                        
                if unusual_flags > 0:
                    fingerprinting_hosts[flow.src_ip]['targets'].add(flow.dst_ip)
                    fingerprinting_hosts[flow.src_ip]['unusual_flags'] += unusual_flags
                    
        # Generate alerts
        for source, data in fingerprinting_hosts.items():
            if data['unusual_flags'] >= 5:
                self.alerts.append({
                    'type': 'os_fingerprinting',
                    'severity': 'high',
                    'source_ip': source,
                    'description': f"Possible OS fingerprinting from {source}",
                    'evidence': {
                        'targets': len(data['targets']),
                        'unusual_flag_packets': data['unusual_flags'],
                    },
                    'confidence': 0.85,
                })
                
    def _detect_port_scan_patterns(self, flows) -> None:
        """Detect sequential/consecutive port scanning patterns."""
        scanner_targets = defaultdict(lambda: defaultdict(list))

        for flow in flows.values():
            if flow.dst_port:
                scanner_targets[flow.src_ip][flow.dst_ip].append(flow.dst_port)

        for scanner, targets in scanner_targets.items():
            for target, ports in targets.items():
                if len(ports) >= 20:
                    sorted_ports = sorted(set(ports))
                    consecutive = 1
                    max_consecutive = 1

                    for i in range(1, len(sorted_ports)):
                        if sorted_ports[i] == sorted_ports[i-1] + 1:
                            consecutive += 1
                            max_consecutive = max(max_consecutive, consecutive)
                        else:
                            consecutive = 1

                    if max_consecutive >= 10:
                        self.alerts.append({
                            'type': 'sequential_port_scan',
                            'severity': 'high',
                            'source_ip': scanner,
                            'target_ip': target,
                            'description': f"Sequential port scan detected: {scanner} -> {target}",
                            'evidence': {
                                'ports_scanned': len(ports),
                                'max_consecutive_ports': max_consecutive,
                                'port_range': f"{sorted_ports[0]}-{sorted_ports[-1]}",
                            },
                            'confidence': min(0.97, 0.80 + max_consecutive * 0.005),
                        })

    def _detect_service_sweep(self, flows) -> None:
        """Detect same-port sweeps across many hosts (e.g. SSH sweep, RDP sweep, SMB sweep).

        Distinct from sequential port scan: one port, many hosts.
        Threshold: single source hitting 15+ distinct hosts on the same port.
        """
        NOISY_PORTS = {80, 443, 53}  # Exclude ports that are legitimately hit en-masse
        # key: (src_ip, dst_port) -> set of target hosts
        sweep: Dict[Tuple[str, int], Set[str]] = defaultdict(set)

        for flow in flows.values():
            if flow.dst_port and flow.dst_port not in NOISY_PORTS:
                sweep[(flow.src_ip, flow.dst_port)].add(flow.dst_ip)

        for (src, port), hosts in sweep.items():
            if len(hosts) >= 15:
                service = {
                    22: 'SSH', 23: 'Telnet', 25: 'SMTP', 445: 'SMB',
                    3389: 'RDP', 5900: 'VNC', 6379: 'Redis', 27017: 'MongoDB',
                    1433: 'MSSQL', 3306: 'MySQL', 5432: 'PostgreSQL',
                }.get(port, str(port))
                self.alerts.append({
                    'type': 'service_sweep',
                    'severity': 'high',
                    'source_ip': src,
                    'description': f"{service} service sweep from {src}: {len(hosts)} hosts on port {port}",
                    'evidence': {
                        'port': port,
                        'service': service,
                        'hosts_targeted': len(hosts),
                        'sample_targets': sorted(hosts)[:10],
                    },
                    'confidence': min(0.95, 0.70 + len(hosts) * 0.01),
                })
