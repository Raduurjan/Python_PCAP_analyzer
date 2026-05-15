"""PCAP packet parsing and flow reconstruction."""

from typing import Dict, List, Optional, Iterator, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import hashlib

from scapy.all import PcapReader, Packet, IP, TCP, UDP, ICMP, ARP, Ether
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR


@dataclass
class PacketInfo:
    """Structured packet information for analysis."""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    payload: bytes
    payload_len: int
    flags: Dict[str, bool] = field(default_factory=dict)
    ttl: Optional[int] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    http_request: Optional[Dict] = None
    http_response: Optional[Dict] = None
    dns_query: Optional[Dict] = None
    raw_packet: Optional[Packet] = field(default=None, repr=False)
    packet_hash: str = ""
    
    def __post_init__(self):
        if not self.packet_hash and self.raw_packet:
            self.packet_hash = hashlib.md5(
                bytes(self.raw_packet)
            ).hexdigest()[:16]


@dataclass  
class Flow:
    """Network flow representation."""
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packets: List[PacketInfo] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    total_bytes: int = 0
    
    @property
    def flow_id(self) -> str:
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"
    
    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    @property
    def packet_count(self) -> int:
        return len(self.packets)
    
    @property
    def byte_rate(self) -> float:
        if self.duration > 0:
            return self.total_bytes / self.duration
        return 0.0


class PacketParser:
    """Parse PCAP files and extract structured packet information."""
    
    PROTO_MAP = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
    }
    
    def __init__(self, progress_callback: Optional[Callable] = None):
        self.progress_callback = progress_callback
        self.flows: Dict[str, Flow] = {}
        self.packets: List[PacketInfo] = []
        self.hosts: set = set()
        self.ports_seen: Dict[int, int] = defaultdict(int)
        
    def parse_pcap(self, filepath: str, max_packets: Optional[int] = None) -> None:
        """Parse a PCAP file and build flow table."""
        packet_count = 0
        
        with PcapReader(filepath) as reader:
            for packet in reader:
                if max_packets and packet_count >= max_packets:
                    break
                    
                pkt_info = self._extract_packet_info(packet)
                if pkt_info:
                    self.packets.append(pkt_info)
                    self._update_flow(pkt_info)
                    self._update_statistics(pkt_info)
                    
                packet_count += 1
                
                if self.progress_callback and packet_count % 1000 == 0:
                    self.progress_callback(packet_count)
                    
        if self.progress_callback:
            self.progress_callback(packet_count, done=True)
            
    def _extract_packet_info(self, packet: Packet) -> Optional[PacketInfo]:
        """Extract structured info from a scapy packet."""
        if not packet.haslayer(Ether):
            return None
            
        timestamp = datetime.fromtimestamp(float(packet.time))
        
        # Initialize with defaults
        src_ip = ""
        dst_ip = ""
        src_port = None
        dst_port = None
        protocol = "OTHER"
        ttl = None
        flags = {}
        tcp_seq = None
        tcp_ack = None
        http_request = None
        http_response = None
        dns_query = None
        
        # IP layer processing
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ttl = ip_layer.ttl
            proto_num = ip_layer.proto
            protocol = self.PROTO_MAP.get(proto_num, f"PROTO_{proto_num}")
            
            # TCP processing
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                
                flags = {
                    'SYN': bool(tcp_layer.flags.S),
                    'ACK': bool(tcp_layer.flags.A),
                    'PSH': bool(tcp_layer.flags.P),
                    'RST': bool(tcp_layer.flags.R),
                    'FIN': bool(tcp_layer.flags.F),
                    'URG': bool(tcp_layer.flags.U),
                }
                tcp_seq = tcp_layer.seq
                tcp_ack = tcp_layer.ack
                
                # HTTP detection
                if packet.haslayer(HTTPRequest):
                    http_layer = packet[HTTPRequest]
                    http_request = {
                        'method': http_layer.Method.decode() if hasattr(http_layer.Method, 'decode') else str(http_layer.Method),
                        'path': http_layer.Path.decode() if hasattr(http_layer.Path, 'decode') else str(http_layer.Path),
                        'host': http_layer.Host.decode() if hasattr(http_layer.Host, 'decode') and http_layer.Host else None,
                        'user_agent': http_layer.User_Agent.decode() if hasattr(http_layer, 'User_Agent') and http_layer.User_Agent else None,
                    }
                
                if packet.haslayer(HTTPResponse):
                    http_layer = packet[HTTPResponse]
                    http_response = {
                        'status_code': http_layer.Status_Code.decode() if hasattr(http_layer.Status_Code, 'decode') else str(http_layer.Status_Code),
                        'reason_phrase': http_layer.Reason_Phrase.decode() if hasattr(http_layer.Reason_Phrase, 'decode') and http_layer.Reason_Phrase else None,
                    }
                    
            # UDP processing
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                
                # DNS detection
                if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                    dns = packet[DNS]
                    if dns.qd:
                        qname = dns.qd.qname
                        if isinstance(qname, bytes):
                            qname = qname.decode(errors='ignore').rstrip('.')
                        dns_query = {
                            'query': qname,
                            'type': dns.qd.qtype,
                        }
                        
        # ICMP processing
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
        # ARP processing
        elif packet.haslayer(ARP):
            protocol = "ARP"
            arp = packet[ARP]
            src_ip = arp.psrc
            dst_ip = arp.pdst
            
        # Extract payload
        payload = b""
        if packet.haslayer(TCP) and packet[TCP].payload:
            payload = bytes(packet[TCP].payload)
        elif packet.haslayer(UDP) and packet[UDP].payload:
            payload = bytes(packet[UDP].payload)
            
        return PacketInfo(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=len(packet),
            payload=payload,
            payload_len=len(payload),
            flags=flags,
            ttl=ttl,
            tcp_seq=tcp_seq,
            tcp_ack=tcp_ack,
            http_request=http_request,
            http_response=http_response,
            dns_query=dns_query,
            raw_packet=packet,
        )
        
    def _update_flow(self, pkt_info: PacketInfo) -> None:
        """Update flow table with packet information."""
        flow_id = f"{pkt_info.src_ip}:{pkt_info.src_port}-{pkt_info.dst_ip}:{pkt_info.dst_port}-{pkt_info.protocol}"
        
        if flow_id not in self.flows:
            self.flows[flow_id] = Flow(
                src_ip=pkt_info.src_ip,
                dst_ip=pkt_info.dst_ip,
                src_port=pkt_info.src_port,
                dst_port=pkt_info.dst_port,
                protocol=pkt_info.protocol,
                start_time=pkt_info.timestamp,
            )
            
        flow = self.flows[flow_id]
        flow.packets.append(pkt_info)
        flow.end_time = pkt_info.timestamp
        flow.total_bytes += pkt_info.length
        
    def _update_statistics(self, pkt_info: PacketInfo) -> None:
        """Update global statistics."""
        self.hosts.add(pkt_info.src_ip)
        self.hosts.add(pkt_info.dst_ip)
        
        if pkt_info.src_port:
            self.ports_seen[pkt_info.src_port] += 1
        if pkt_info.dst_port:
            self.ports_seen[pkt_info.dst_port] += 1
            
    def get_flows_by_ip(self, ip: str) -> List[Flow]:
        """Get all flows involving a specific IP."""
        return [
            flow for flow in self.flows.values()
            if flow.src_ip == ip or flow.dst_ip == ip
        ]
        
    def get_flows_by_port(self, port: int) -> List[Flow]:
        """Get all flows involving a specific port."""
        return [
            flow for flow in self.flows.values()
            if flow.src_port == port or flow.dst_port == port
        ]
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get parsing statistics."""
        return {
            'total_packets': len(self.packets),
            'total_flows': len(self.flows),
            'unique_hosts': len(self.hosts),
            'protocols': self._get_protocol_distribution(),
            'top_ports': self._get_top_ports(10),
        }
        
    def _get_protocol_distribution(self) -> Dict[str, int]:
        """Get packet count by protocol."""
        counts = defaultdict(int)
        for pkt in self.packets:
            counts[pkt.protocol] += 1
        return dict(counts)
        
    def _get_top_ports(self, n: int) -> List[tuple]:
        """Get most common ports."""
        sorted_ports = sorted(
            self.ports_seen.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_ports[:n]
