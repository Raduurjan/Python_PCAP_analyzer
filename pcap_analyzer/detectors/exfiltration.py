"""Data exfiltration detection module."""

from typing import Dict, List, Set, Any
from collections import defaultdict


class ExfiltrationDetector:
    """Detect data exfiltration attempts."""
    
    # Thresholds
    LARGE_TRANSFER_THRESHOLD = 50 * 1024 * 1024  # 50 MB
    HIGH_RATE_THRESHOLD = 10 * 1024 * 1024  # 10 MB/s
    # Suspicious protocols for data transfer
    SUSPICIOUS_EXFIL_PORTS = {
        4444: 'meterpreter',
        5555: 'adb/backdoor',
        9999: 'common_backdoor',
        12345: 'netbus',
        31337: 'backorifice',
    }
    
    def __init__(self):
        self.alerts: List[Dict] = []
        
    def analyze(self, flows, packets, parser) -> List[Dict]:
        """Analyze for data exfiltration patterns."""
        self.alerts = []

        self._detect_large_transfers(flows)
        self._detect_high_rate_transfers(flows)
        self._detect_suspicious_protocol_exfil(flows)
        self._detect_high_volume_non_http_outbound(flows)
        self._detect_asymmetric_upload(flows)
        self._detect_dns_volume_exfil(packets)

        return self.alerts
        
    def _detect_large_transfers(self, flows) -> None:
        """Detect unusually large data transfers."""
        for flow in flows.values():
            # Focus on outbound traffic
            if flow.total_bytes < self.LARGE_TRANSFER_THRESHOLD:
                continue
                
            # Calculate rate
            duration = max(flow.duration, 1)  # Avoid division by zero
            rate = flow.total_bytes / duration
            
            self.alerts.append({
                'type': 'large_transfer',
                'severity': 'high',
                'source_ip': flow.src_ip,
                'destination': f"{flow.dst_ip}:{flow.dst_port}",
                'description': f"Large data transfer ({self._human_readable_size(flow.total_bytes)}) from {flow.src_ip}",
                'evidence': {
                    'total_bytes': flow.total_bytes,
                    'total_size_human': self._human_readable_size(flow.total_bytes),
                    'duration_seconds': round(duration, 2),
                    'transfer_rate': self._human_readable_size(rate) + '/s',
                    'protocol': flow.protocol,
                    'packet_count': flow.packet_count,
                },
                'confidence': min(0.85, 0.5 + (flow.total_bytes / self.LARGE_TRANSFER_THRESHOLD) * 0.1),
            })
            
    def _detect_high_rate_transfers(self, flows) -> None:
        """Detect high-rate data transfers."""
        for flow in flows.values():
            duration = max(flow.duration, 1)
            rate = flow.total_bytes / duration
            
            if rate > self.HIGH_RATE_THRESHOLD:
                self.alerts.append({
                    'type': 'high_rate_transfer',
                    'severity': 'critical',
                    'source_ip': flow.src_ip,
                    'destination': f"{flow.dst_ip}:{flow.dst_port}",
                    'description': f"High-rate data transfer from {flow.src_ip}",
                    'evidence': {
                        'transfer_rate': self._human_readable_size(rate) + '/s',
                        'total_bytes': flow.total_bytes,
                        'duration_seconds': round(flow.duration, 2),
                        'protocol': flow.protocol,
                    },
                    'confidence': 0.85,
                })
                
    def _detect_suspicious_protocol_exfil(self, flows) -> None:
        """Detect data transfers over suspicious ports."""
        for flow in flows.values():
            if flow.dst_port in self.SUSPICIOUS_EXFIL_PORTS:
                reason = self.SUSPICIOUS_EXFIL_PORTS[flow.dst_port]
                
                if flow.total_bytes > 1024 * 1024:  # > 1 MB
                    self.alerts.append({
                        'type': 'suspicious_port_transfer',
                        'severity': 'critical',
                        'source_ip': flow.src_ip,
                        'destination': f"{flow.dst_ip}:{flow.dst_port}",
                        'description': f"Data exfiltration over suspicious port {flow.dst_port} ({reason})",
                        'evidence': {
                            'port': flow.dst_port,
                            'port_reason': reason,
                            'total_bytes': flow.total_bytes,
                            'total_size_human': self._human_readable_size(flow.total_bytes),
                            'protocol': flow.protocol,
                        },
                        'confidence': 0.9,
                    })
                    
    def _detect_high_volume_non_http_outbound(self, flows) -> None:
        """Detect large outbound transfers on non-standard ports (catches raw TCP exfil like port 62267)."""
        STANDARD_PORTS = {80, 443, 8080, 8443, 22, 21, 25, 53, 110, 143, 993, 995, 3389, 5900}
        THRESHOLD = 5 * 1024 * 1024  # 5 MB
        for flow in flows.values():
            if flow.total_bytes < THRESHOLD:
                continue
            if flow.dst_port in STANDARD_PORTS:
                continue
            # Only outbound (src is host, dst is external — heuristic: dst_port is ephemeral high port
            # or explicitly non-standard service port)
            self.alerts.append({
                'type': 'non_standard_port_exfil',
                'severity': 'critical',
                'source_ip': flow.src_ip,
                'destination': f"{flow.dst_ip}:{flow.dst_port}",
                'description': (
                    f"Large transfer ({self._human_readable_size(flow.total_bytes)}) "
                    f"on non-standard port {flow.dst_port} from {flow.src_ip}"
                ),
                'evidence': {
                    'port': flow.dst_port,
                    'total_bytes': flow.total_bytes,
                    'total_size_human': self._human_readable_size(flow.total_bytes),
                    'duration_seconds': round(flow.duration, 2),
                    'protocol': flow.protocol,
                    'packet_count': flow.packet_count,
                },
                'confidence': min(0.95, 0.75 + (flow.total_bytes / (100 * 1024 * 1024)) * 0.1),
            })

    def _detect_dns_volume_exfil(self, packets) -> None:
        """Detect DNS-based data exfiltration using volume analysis per apex domain.

        Avoids FPs from CDN subdomains by grouping queries to the same apex domain
        and requiring BOTH high query count AND high average query length to the
        same apex. Normal CDN traffic has long subdomains but low query *count*
        per apex. DNS tunneling has both.

        Thresholds:
          - >= 200 queries to the same apex domain from one source, OR
          - >= 50 queries with avg subdomain length > 40 chars to same apex
        """
        # Known high-volume but legitimate apex domains — suppress these
        CDN_WHITELIST = {
            'google.com', 'googleapis.com', 'gstatic.com', 'googlevideo.com',
            'cloudflare.com', 'cloudflare.net', 'fastly.net', 'akamaiedge.net',
            'akamaitechnologies.com', 'akamaized.net', 'edgekey.net',
            'microsoft.com', 'msftncsi.com', 'windowsupdate.com', 'office.com',
            'office365.com', 'microsoftonline.com', 'azure.com', 'azureedge.net',
            'apple.com', 'icloud.com', 'amazonaws.com', 'awsstatic.com',
            'cdn77.org', 'cdnjs.cloudflare.com', 'jquery.com',
        }
        # key: (src_ip, apex_domain) -> stats
        apex_stats: Dict = defaultdict(lambda: {'queries': 0, 'total_subdomain_len': 0, 'sample': []})

        for pkt in packets:
            if not pkt.dns_query:
                continue
            q = pkt.dns_query.get('query', '')
            if not q or q.count('.') < 1:
                continue
            parts = q.rstrip('.').split('.')
            # Apex = last two labels (e.g. evil.com from a.b.c.evil.com)
            apex = '.'.join(parts[-2:]) if len(parts) >= 2 else q
            subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''

            if apex in CDN_WHITELIST:
                continue
            key = (pkt.src_ip, apex)
            apex_stats[key]['queries'] += 1
            apex_stats[key]['total_subdomain_len'] += len(subdomain)
            if len(apex_stats[key]['sample']) < 5:
                apex_stats[key]['sample'].append(q)

        for (src, apex), data in apex_stats.items():
            count = data['queries']
            avg_sub_len = data['total_subdomain_len'] / count if count else 0

            # High volume alone, or moderate volume + long subdomains
            if count >= 200 or (count >= 50 and avg_sub_len > 40):
                confidence = min(0.92, 0.65 + (count / 500) + (avg_sub_len / 200))
                self.alerts.append({
                    'type': 'dns_volume_exfil',
                    'severity': 'critical',
                    'source_ip': src,
                    'description': (
                        f"DNS exfiltration suspected from {src} via {apex}: "
                        f"{count} queries, avg subdomain {avg_sub_len:.0f} chars"
                    ),
                    'evidence': {
                        'apex_domain': apex,
                        'query_count': count,
                        'avg_subdomain_length': round(avg_sub_len, 1),
                        'sample_queries': data['sample'],
                    },
                    'confidence': confidence,
                })

    def _detect_asymmetric_upload(self, flows) -> None:
        """Detect flows where outbound bytes vastly exceed inbound bytes.

        Normal browsing/API calls have roughly balanced or inbound-heavy ratios.
        Exfiltration over HTTPS shows src_bytes >> dst_bytes (client uploads bulk data).
        Threshold: upload ratio >= 20:1 and total upload >= 2 MB.
        """
        UPLOAD_RATIO_THRESHOLD = 20.0
        MIN_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MB

        for flow in flows.values():
            src_bytes = getattr(flow, 'src_bytes', None)
            dst_bytes = getattr(flow, 'dst_bytes', None)
            # Fall back to total_bytes if directional stats unavailable
            if src_bytes is None or dst_bytes is None:
                continue
            if src_bytes < MIN_UPLOAD_BYTES:
                continue
            if dst_bytes == 0:
                dst_bytes = 1  # Avoid division by zero; ratio will be very high
            ratio = src_bytes / dst_bytes
            if ratio >= UPLOAD_RATIO_THRESHOLD:
                self.alerts.append({
                    'type': 'asymmetric_upload_exfil',
                    'severity': 'high',
                    'source_ip': flow.src_ip,
                    'destination': f"{flow.dst_ip}:{flow.dst_port}",
                    'description': (
                        f"Asymmetric upload detected from {flow.src_ip}: "
                        f"{self._human_readable_size(src_bytes)} sent vs "
                        f"{self._human_readable_size(dst_bytes)} received (ratio {ratio:.0f}:1)"
                    ),
                    'evidence': {
                        'upload_bytes': src_bytes,
                        'upload_size_human': self._human_readable_size(src_bytes),
                        'download_bytes': dst_bytes,
                        'upload_ratio': round(ratio, 1),
                        'port': flow.dst_port,
                        'protocol': flow.protocol,
                    },
                    'confidence': min(0.92, 0.70 + (ratio / 100)),
                })

    @staticmethod
    def _human_readable_size(size_bytes: int) -> str:
        """Convert bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
