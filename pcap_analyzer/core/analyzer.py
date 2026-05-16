"""Main PCAP analyzer orchestrator."""

from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime
import json
import time

from pcap_analyzer.core.packet_parser import PacketParser
from pcap_analyzer.rules.rule_engine import RuleEngine
from pcap_analyzer.detectors.reconnaissance import ReconnaissanceDetector
from pcap_analyzer.detectors.c2_detector import C2Detector
from pcap_analyzer.detectors.exfiltration import ExfiltrationDetector
from pcap_analyzer.detectors.lateral_movement import LateralMovementDetector
from pcap_analyzer.detectors.credential_access import CredentialAccessDetector
from pcap_analyzer.reporters.json_reporter import JSONReporter


class PCAPAnalyzer:
    """Main analyzer that orchestrates detection and reporting."""
    
    def __init__(self, 
                 rules_path: Optional[str] = None,
                 progress_callback: Optional[Any] = None,
                 confidence_threshold: float = 0.7):
        self.parser = PacketParser(progress_callback=progress_callback)
        self.rule_engine = RuleEngine()
        self.detectors = {
            'reconnaissance': ReconnaissanceDetector(),
            'c2': C2Detector(),
            'exfiltration': ExfiltrationDetector(),
            'lateral_movement': LateralMovementDetector(),
            'credential_access': CredentialAccessDetector(),
        }
        self.confidence_threshold = confidence_threshold
        self.results: Dict[str, Any] = {}
        
        # Load rules if provided
        if rules_path:
            self._load_rules(rules_path)
            
    def _load_rules(self, rules_path: str) -> None:
        """Load detection rules from path."""
        path = Path(rules_path)
        
        if path.is_file():
            self.rule_engine.load_rule_file(path)
        elif path.is_dir():
            count = self.rule_engine.load_rules_directory(path)
            print(f"Loaded {count} rule files")
            
    def analyze(self, 
                pcap_path: str,
                max_packets: Optional[int] = None) -> Dict[str, Any]:
        """Run complete analysis on a PCAP file."""
        print(f"\n[*] Analyzing: {pcap_path}")
        
        # Parse PCAP
        print("[+] Parsing packets...")
        self.parser.parse_pcap(pcap_path, max_packets=max_packets)
        
        stats = self.parser.get_statistics()
        print(f"[+] Parsed {stats['total_packets']:,} packets, {stats['total_flows']:,} flows")
        
        # Run rule-based detection
        print("[+] Running rule-based detection...")
        rule_matches = self._run_rule_detection()
        print(f"[+] Found {len(rule_matches)} rule matches")
        
        # Run specialized detectors
        print("[+] Running specialized detectors...")
        findings = self._run_detectors()
        print(f"[+] Found {len(findings)} security findings")

        # Merge rule matches into findings
        rule_findings = [self._match_to_dict(m) for m in rule_matches]
        all_findings = findings + rule_findings

        # Compile results
        self.results = {
            'pcap_file': pcap_path,
            'analysis_time': datetime.now().isoformat(),
            'summary': self._generate_summary(all_findings),
            'statistics': stats,
            'findings': all_findings,
            'flows': self._flows_to_dict(),
        }
        
        return self.results
        
    def _run_rule_detection(self) -> List[Any]:
        """Run rule engine on all packets and flows."""
        matches = []
        start_time = time.time()
        
        print(f"    [DEBUG] Starting rule detection on {len(self.parser.packets)} packets, {len(self.parser.flows)} flows")
        
        # Build packet-to-flow index for O(1) lookup
        packet_flow_map: Dict[str, Any] = {}
        idx_start = time.time()
        for flow in self.parser.flows.values():
            for p in flow.packets:
                packet_flow_map[p.packet_hash] = flow
        print(f"    [DEBUG] Built flow index in {time.time() - idx_start:.2f}s ({len(packet_flow_map)} packets mapped)")
        
        # Check packets
        packet_start = time.time()
        total_packets = len(self.parser.packets)
        for i, packet in enumerate(self.parser.packets):
            # Progress every 10000 packets
            if i > 0 and i % 10000 == 0:
                elapsed = time.time() - packet_start
                rate = i / elapsed if elapsed > 0 else 0
                print(f"    [DEBUG] Processed {i}/{total_packets} packets ({rate:.0f} pkt/s)")
            
            # Fast O(1) flow lookup
            flow = packet_flow_map.get(packet.packet_hash)
                    
            matches.extend(self.rule_engine.evaluate_packet(packet, flow))
        print(f"    [DEBUG] Packet rule evaluation: {time.time() - packet_start:.2f}s")
            
        # Check flows
        flow_start = time.time()
        for flow in self.parser.flows.values():
            matches.extend(self.rule_engine.evaluate_flow(flow))
        print(f"    [DEBUG] Flow rule evaluation: {time.time() - flow_start:.2f}s")
        
        print(f"    [DEBUG] Total rule detection: {time.time() - start_time:.2f}s, {len(matches)} matches")
            
        return matches
        
    def _run_detectors(self) -> List[Dict]:
        """Run all specialized detectors with confidence filtering."""
        all_findings = []
        
        for name, detector in self.detectors.items():
            print(f"    - Running {name} detector...")
            findings = detector.analyze(
                self.parser.flows,
                self.parser.packets,
                self.parser
            )
            # Filter by confidence threshold
            high_confidence = [
                f for f in findings 
                if f.get('confidence', 0.5) >= self.confidence_threshold
            ]
            print(f"      {len(high_confidence)}/{len(findings)} high confidence findings")
            all_findings.extend(high_confidence)
            
        return all_findings
        
    def _generate_summary(self, findings: List[Dict]) -> Dict[str, Any]:
        """Generate analysis summary."""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            severity = finding.get('severity', 'info')
            if severity in severity_counts:
                severity_counts[severity] += 1
                
        # Count categories
        categories = {}
        for finding in findings:
            cat = finding.get('type', 'unknown')
            categories[cat] = categories.get(cat, 0) + 1
            
        return {
            'total_findings': len(findings),
            'severity_counts': severity_counts,
            'categories': categories,
            'risk_score': self._calculate_risk_score(severity_counts),
        }
        
    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> int:
        """Calculate overall risk score (0-100)."""
        weights = {'critical': 40, 'high': 20, 'medium': 10, 'low': 5, 'info': 1}
        score = sum(severity_counts.get(s, 0) * w for s, w in weights.items())
        return min(100, score)
        
    def _match_to_dict(self, match) -> Dict:
        """Convert RuleMatch to dictionary."""
        return {
            'type': match.rule_name,
            'rule_name': match.rule_name,
            'severity': match.severity.value,
            'description': match.description,
            'category': match.category,
            'matched_packets': match.matched_packets,
            'matched_flows': match.matched_flows,
            'evidence': match.evidence,
            'confidence': match.confidence,
        }
        
    def _flows_to_dict(self) -> List[Dict]:
        """Convert flows to list of dictionaries."""
        flow_list = []
        for flow in self.parser.flows.values():
            flow_list.append({
                'flow_id': flow.flow_id,
                'src_ip': flow.src_ip,
                'dst_ip': flow.dst_ip,
                'src_port': flow.src_port,
                'dst_port': flow.dst_port,
                'protocol': flow.protocol,
                'packet_count': flow.packet_count,
                'total_bytes': flow.total_bytes,
                'duration': flow.duration,
                'start_time': str(flow.start_time),
                'end_time': str(flow.end_time),
            })
        return sorted(flow_list, key=lambda x: x['total_bytes'], reverse=True)
        
    def generate_report(self, output_dir: str, formats: List[str] = None) -> Dict[str, str]:
        """Generate reports in specified formats."""
        if formats is None:
            formats = ['json']

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        reports = {}

        if 'json' in formats:
            reporter = JSONReporter(str(output_path))
            reports['json'] = reporter.generate(self.results)
            print(f"[+] JSON report: {reports['json']}")

        return reports
        
    def print_summary(self) -> None:
        """Print console summary of findings."""
        summary = self.results.get('summary', {})
        findings = self.results.get('findings', [])
        
        print("\n" + "=" * 60)
        print("ANALYSIS SUMMARY")
        print("=" * 60)
        print(f"Total Findings: {summary.get('total_findings', 0)}")
        print(f"Risk Score: {summary.get('risk_score', 0)}/100")
        print("\nSeverity Breakdown:")
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = summary.get('severity_counts', {}).get(severity, 0)
            if count > 0:
                print(f"  - {severity.upper()}: {count}")
                
        if findings:
            print("\nTop Findings:")
            for finding in findings[:5]:
                print(f"  [{finding.get('severity', 'INFO').upper()}] {finding.get('type', 'Unknown')}: {finding.get('description', '')[:80]}...")
