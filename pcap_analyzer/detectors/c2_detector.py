"""Command and Control (C2) detection module."""

import re
from typing import Dict, List, Set, Tuple, Any, Optional
from collections import defaultdict
from datetime import timedelta


class C2Detector:
    """Detect command and control communication patterns."""
    
    # Timing thresholds for beaconing detection
    BEACON_TOLERANCE = 0.1  # 10% variance
    MIN_BEACON_PACKETS = 5
    
    # Suspicious User-Agent patterns
    SUSPICIOUS_UAS = [
        r'curl/',
        r'wget/',
        r'python-requests/',
        r'powershell',
        r'meterpreter',
        r'empire',
        r'cobaltstrike',
        r'metasploit',
    ]
    
    def __init__(self):
        self.alerts: List[Dict] = []
        
    def analyze(self, flows, packets, parser) -> List[Dict]:
        """Analyze for C2 patterns."""
        self.alerts = []

        self._detect_keepalive_beacon(flows)
        self._detect_suspicious_user_agents(packets)
        self._detect_http_c2_uri(packets)
        self._detect_non_std_port_tls(flows)
        self._detect_low_and_slow_c2(flows)

        return self.alerts
        
    def _detect_keepalive_beacon(self, flows) -> None:
        """Detect persistent long-lived flows with periodic small keep-alive packets.

        Real C2 implants (Cobalt Strike default: 60s sleep) maintain a long TCP session
        and send tiny heartbeat packets at regular intervals within that single flow.
        Signature: high duration, low total_bytes relative to packet_count, regular spacing.
        """
        for flow in flows.values():
            if flow.packet_count < self.MIN_BEACON_PACKETS:
                continue
            if flow.duration < 60:  # Need at least 1 minute to see keep-alive pattern
                continue
            avg_bytes_per_pkt = flow.total_bytes / flow.packet_count if flow.packet_count else 0
            # Keep-alive packets are tiny (< 200 bytes avg) but flow is long-lived
            if avg_bytes_per_pkt > 500:
                continue

            outgoing = [p.timestamp for p in flow.packets if p.src_ip == flow.src_ip]
            if len(outgoing) < self.MIN_BEACON_PACKETS:
                continue

            intervals = [
                (outgoing[i] - outgoing[i-1]).total_seconds()
                for i in range(1, len(outgoing))
            ]
            if not intervals:
                continue

            mean_interval = sum(intervals) / len(intervals)
            if mean_interval <= 0:
                continue

            variance = sum((iv - mean_interval) ** 2 for iv in intervals) / len(intervals)
            cv = (variance ** 0.5) / mean_interval

            if cv < self.BEACON_TOLERANCE and mean_interval >= 5:
                self.alerts.append({
                    'type': 'keepalive_c2_beacon',
                    'severity': 'critical',
                    'source_ip': flow.src_ip,
                    'destination': f"{flow.dst_ip}:{flow.dst_port}",
                    'description': (
                        f"Persistent keep-alive C2 beacon from {flow.src_ip} "
                        f"(~{mean_interval:.0f}s interval, {flow.duration:.0f}s session)"
                    ),
                    'evidence': {
                        'interval_seconds': round(mean_interval, 2),
                        'jitter_percent': round(cv * 100, 2),
                        'beacon_count': len(outgoing),
                        'flow_duration_seconds': round(flow.duration, 2),
                        'avg_packet_bytes': round(avg_bytes_per_pkt, 1),
                        'protocol': flow.protocol,
                    },
                    'confidence': min(0.95, 0.80 + (len(outgoing) * 0.01) - cv),
                })
                
    def _detect_suspicious_user_agents(self, packets) -> None:
        """Detect suspicious User-Agent strings.

        Threshold raised to 10+ requests, or 3+ requests to the same external destination,
        to suppress monitoring-agent noise (curl health checks, etc.).
        """
        # key: (source_ip, matched_pattern) -> evidence
        hits: Dict = defaultdict(lambda: {'count': 0, 'targets': set(), 'ua_strings': set()})

        for pkt in packets:
            if not (pkt.http_request and pkt.http_request.get('user_agent')):
                continue
            ua = pkt.http_request['user_agent']
            for pattern in self.SUSPICIOUS_UAS:
                if re.search(pattern, ua, re.IGNORECASE):
                    key = (pkt.src_ip, pattern)
                    hits[key]['count'] += 1
                    hits[key]['targets'].add(pkt.dst_ip)
                    hits[key]['ua_strings'].add(ua)

        # Aggregate per source
        by_source: Dict = defaultdict(lambda: {'count': 0, 'targets': set(), 'ua_strings': set()})
        for (src, _), data in hits.items():
            by_source[src]['count'] += data['count']
            by_source[src]['targets'].update(data['targets'])
            by_source[src]['ua_strings'].update(data['ua_strings'])

        for source, data in by_source.items():
            # Alert if: 10+ requests total, OR 3+ requests to the same single external IP
            single_target_heavy = any(
                sum(1 for (s, _), d in hits.items() if s == source and ip in d['targets']) >= 3
                for ip in data['targets']
            )
            if data['count'] >= 10 or single_target_heavy:
                confidence = min(0.93, 0.70 + data['count'] * 0.005)
                self.alerts.append({
                    'type': 'suspicious_user_agent',
                    'severity': 'high',
                    'source_ip': source,
                    'description': f"Suspicious User-Agent detected from {source}",
                    'evidence': {
                        'request_count': data['count'],
                        'unique_targets': len(data['targets']),
                        'targets': list(data['targets'])[:10],
                        'user_agents': list(data['ua_strings'])[:5],
                    },
                    'confidence': confidence,
                })
                
    def _detect_non_std_port_tls(self, flows) -> None:
        """Detect TLS on non-standard ports — common in Cobalt Strike/Metasploit malleable C2.

        Only triggers on dst_port (attacker-controlled listener), never on ephemeral src ports.
        Requires sustained flows: >= 10 packets, > 30s duration.
        """
        STANDARD_PORTS = {
            20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587,
            993, 995, 3389, 5900, 5985, 5986, 8080, 8443, 8888, 4443,
            # XMPP / Firebase Cloud Messaging / Google Talk
            5222, 5223, 5228, 5229, 5230,
            # Common messaging / gaming / app ports
            1194, 1723, 4500, 500, 1080, 3128,
        }
        # Ports >= 30000 are effectively ephemeral for C2 listener detection purposes.
        # Real C2 listeners use well-known or low registered ports to blend in.
        EPHEMERAL_CUTOFF = 30000

        for flow in flows.values():
            dst = flow.dst_port
            if not dst:
                continue
            if dst in STANDARD_PORTS:
                continue
            if dst >= EPHEMERAL_CUTOFF:
                continue
            if flow.packet_count < 20 or flow.duration < 60 or flow.total_bytes == 0:
                continue
            avg_pkt = flow.total_bytes / flow.packet_count
            if 80 < avg_pkt < 3000:
                self.alerts.append({
                    'type': 'non_standard_port_c2',
                    'severity': 'high',
                    'source_ip': flow.src_ip,
                    'destination': f"{flow.dst_ip}:{dst}",
                    'description': f"Encrypted C2-like traffic on non-standard port {dst} from {flow.src_ip}",
                    'evidence': {
                        'port': dst,
                        'avg_packet_size': round(avg_pkt, 1),
                        'packet_count': flow.packet_count,
                        'duration_seconds': round(flow.duration, 2),
                        'total_bytes': flow.total_bytes,
                    },
                    'confidence': 0.75,
                })
                
    def _detect_low_and_slow_c2(self, flows) -> None:
        """Detect low-and-slow C2: same dst_ip contacted in multiple separate flows with regular spacing."""
        # Group flows by (src_ip, dst_ip) pair
        flow_groups: Dict[Tuple[str, str], List[Any]] = defaultdict(list)
        for flow in flows.values():
            if flow.start_time and flow.dst_port in (80, 443, 8080, 8443):
                flow_groups[(flow.src_ip, flow.dst_ip)].append(flow)

        for (src, dst), flist in flow_groups.items():
            if len(flist) < 4:
                continue
            flist_sorted = sorted(flist, key=lambda f: f.start_time)
            intervals = [
                (flist_sorted[i].start_time - flist_sorted[i-1].start_time).total_seconds()
                for i in range(1, len(flist_sorted))
            ]
            if not intervals:
                continue
            mean_iv = sum(intervals) / len(intervals)
            if mean_iv < 30:  # Too fast — covered by beaconing detector
                continue
            variance = sum((iv - mean_iv) ** 2 for iv in intervals) / len(intervals)
            cv = (variance ** 0.5) / mean_iv if mean_iv > 0 else float('inf')
            if cv < 0.25 and mean_iv >= 30:  # Regular spacing, at least 30s apart
                dst_port = flist_sorted[0].dst_port
                self.alerts.append({
                    'type': 'low_and_slow_c2',
                    'severity': 'high',
                    'source_ip': src,
                    'destination': f"{dst}:{dst_port}",
                    'description': f"Low-and-slow C2 beaconing from {src} to {dst} ({len(flist)} flows, ~{mean_iv:.0f}s apart)",
                    'evidence': {
                        'flow_count': len(flist),
                        'avg_interval_seconds': round(mean_iv, 1),
                        'jitter_percent': round(cv * 100, 1),
                        'dst_port': dst_port,
                    },
                    'confidence': min(0.92, 0.75 + (len(flist) * 0.02) - cv),
                })
        
    def _detect_http_c2_uri(self, packets) -> None:
        """Detect repeated HTTP POSTs/GETs to the same short fixed URI — implant check-in pattern.

        Many C2 frameworks (Metasploit, Empire, Sliver) use fixed short paths like
        /submit, /api/update, /ping, /beacon. Detecting: same source + same URI + 5+ requests.
        """
        uri_hits: Dict = defaultdict(lambda: {'count': 0, 'methods': set(), 'hosts': set()})

        for pkt in packets:
            if not pkt.http_request:
                continue
            uri = pkt.http_request.get('uri', '')
            method = pkt.http_request.get('method', '')
            if not uri or len(uri) > 60:  # Long URIs are browser/CDN, not C2
                continue
            if method not in ('POST', 'GET'):
                continue
            # Skip obvious browser paths
            if any(x in uri for x in ('.js', '.css', '.png', '.ico', '.html', '.woff')):
                continue
            key = (pkt.src_ip, pkt.dst_ip, uri)
            uri_hits[key]['count'] += 1
            uri_hits[key]['methods'].add(method)
            uri_hits[key]['hosts'].add(pkt.dst_ip)

        for (src, dst, uri), data in uri_hits.items():
            if data['count'] >= 5:
                confidence = min(0.90, 0.65 + data['count'] * 0.01)
                self.alerts.append({
                    'type': 'http_c2_checkin',
                    'severity': 'high',
                    'source_ip': src,
                    'destination': dst,
                    'description': f"Repeated HTTP C2 check-in from {src}: {uri} ({data['count']}x)",
                    'evidence': {
                        'uri': uri,
                        'request_count': data['count'],
                        'methods': list(data['methods']),
                        'destination': dst,
                    },
                    'confidence': confidence,
                })
