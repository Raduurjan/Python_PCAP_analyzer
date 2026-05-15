"""YARA-like rule engine for network traffic analysis."""

import re
import yaml
import json
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
import hashlib


class Severity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RuleMatch:
    """Result of a rule match."""
    rule_name: str
    severity: Severity
    description: str
    category: str
    matched_packets: List[str] = field(default_factory=list)
    matched_flows: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0


@dataclass
class Rule:
    """Detection rule definition."""
    name: str
    description: str
    category: str
    severity: Severity
    conditions: List[Dict[str, Any]]
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Rule":
        """Create Rule from dictionary."""
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            category=data.get("category", "general"),
            severity=Severity(data.get("severity", "medium")),
            conditions=data.get("conditions", []),
            enabled=data.get("enabled", True),
            metadata=data.get("metadata", {}),
        )


class RuleCondition:
    """Base class for rule conditions."""
    
    # Cache compiled regex patterns
    _regex_cache: Dict[str, Any] = {}
    # Cache decoded payloads to avoid re-decoding bytes on every rule check
    _payload_cache: Dict[int, str] = {}
    
    @classmethod
    def _get_regex(cls, pattern: str):
        """Get compiled regex from cache or compile new."""
        if pattern not in cls._regex_cache:
            cls._regex_cache[pattern] = re.compile(pattern)
        return cls._regex_cache[pattern]
    
    OPERATORS = {
        'eq': lambda x, y: x == y,
        'ne': lambda x, y: x != y,
        'gt': lambda x, y: x > y,
        'lt': lambda x, y: x < y,
        'gte': lambda x, y: x >= y,
        'lte': lambda x, y: x <= y,
        'contains': lambda x, y: (y in x.decode('utf-8', errors='replace') if isinstance(x, bytes) else y in x) if x else False,
        'matches': lambda x, y: bool(RuleCondition._get_regex(y).search(str(x))) if x else False,
        'in': lambda x, y: x in y if y else False,
        'exists': lambda x, y: x is not None,
    }
    
    @staticmethod
    def evaluate(packet_info: Any, flow: Any, condition: Dict[str, Any]) -> bool:
        """Evaluate a single condition against packet/flow."""
        field_path = condition.get('field', '')
        operator = condition.get('operator', 'eq')
        value = condition.get('value')
        negate = condition.get('negate', False)
        
        # Get field value from packet or flow
        actual_value = RuleCondition._get_field_value(packet_info, flow, field_path)
        
        # Evaluate condition
        if operator == 'exists':
            result = actual_value is not None
        elif operator in RuleCondition.OPERATORS:
            try:
                result = RuleCondition.OPERATORS[operator](actual_value, value)
            except Exception:
                result = False
        else:
            result = False
            
        return not result if negate else result
    
    @staticmethod
    def _get_field_value(packet_info: Any, flow: Any, field_path: str) -> Any:
        """Extract field value using dot notation (e.g., 'packet.src_ip')."""
        if not field_path:
            return None
            
        parts = field_path.split('.')
        if not parts:
            return None
            
        # Fast path: packet.payload — return cached decoded string
        if field_path == 'packet.payload' and packet_info:
            pid = id(packet_info)
            if pid not in RuleCondition._payload_cache:
                raw = getattr(packet_info, 'payload', b'')
                RuleCondition._payload_cache[pid] = raw.decode('utf-8', errors='replace') if isinstance(raw, bytes) else (raw or '')
            return RuleCondition._payload_cache[pid]
            
        # Determine source object
        if parts[0] == 'packet' and packet_info:
            obj = packet_info
            parts = parts[1:]
        elif parts[0] == 'flow' and flow:
            obj = flow
            parts = parts[1:]
        elif hasattr(packet_info, parts[0]):
            obj = packet_info
        elif flow and hasattr(flow, parts[0]):
            obj = flow
        else:
            return None
            
        # Navigate through attributes
        for part in parts:
            if obj is None:
                return None
            if hasattr(obj, part):
                obj = getattr(obj, part)
            elif isinstance(obj, dict) and part in obj:
                obj = obj[part]
            else:
                return None
                
        return obj


class RuleEngine:
    """Engine for loading and evaluating detection rules."""
    
    def __init__(self):
        self.rules: List[Rule] = []
        self.compiled_rules: Dict[str, Any] = {}
        self._protocol_index: Dict[str, List[Rule]] = {}  # protocol -> rules
        self._any_protocol_rules: List[Rule] = []  # rules with no protocol condition

    def _build_protocol_index(self) -> None:
        """Index rules by protocol for fast pre-filtering."""
        self._protocol_index = {}
        self._any_protocol_rules = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            proto = None
            for cond in rule.conditions:
                if cond.get('field') == 'packet.protocol' and cond.get('operator') == 'eq':
                    proto = str(cond.get('value', '')).upper()
                    break
            if proto:
                self._protocol_index.setdefault(proto, []).append(rule)
            else:
                self._any_protocol_rules.append(rule)
        
    def load_rule_file(self, filepath: Union[str, Path]) -> None:
        """Load rules from YAML or JSON file."""
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"Rule file not found: {filepath}")
            
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            if filepath.suffix in ['.yaml', '.yml']:
                data = yaml.safe_load(f)
            elif filepath.suffix == '.json':
                data = json.load(f)
            else:
                raise ValueError(f"Unsupported rule file format: {filepath.suffix}")
                
        if isinstance(data, dict):
            # Single rule or rules list
            if 'rules' in data:
                rules_data = data['rules']
            else:
                rules_data = [data]
        elif isinstance(data, list):
            rules_data = data
        else:
            raise ValueError("Invalid rule file format")
            
        for rule_data in rules_data:
            try:
                rule = Rule.from_dict(rule_data)
                self.rules.append(rule)
            except Exception as e:
                print(f"Failed to load rule: {e}")
        self._build_protocol_index()
                
    def load_rules_directory(self, directory: Union[str, Path]) -> int:
        """Load all rule files from a directory."""
        directory = Path(directory)
        count = 0
        
        for pattern in ['*.yaml', '*.yml', '*.json']:
            for rule_file in directory.glob(pattern):
                try:
                    self.load_rule_file(rule_file)
                    count += 1
                except Exception as e:
                    print(f"Failed to load {rule_file}: {e}")
        self._build_protocol_index()
        return count
        
    def evaluate_packet(self, packet_info: Any, flow: Optional[Any] = None) -> List[RuleMatch]:
        """Evaluate all rules against a single packet (protocol-indexed for speed)."""
        matches = []
        
        proto = getattr(packet_info, 'protocol', '').upper() if packet_info else ''
        dst_port = getattr(packet_info, 'dst_port', None)
        src_port = getattr(packet_info, 'src_port', None)
        http = getattr(packet_info, 'http_request', None)
        dns  = getattr(packet_info, 'dns_query', None)

        seen = set()
        candidate_rules = list(self._any_protocol_rules)

        def _add(key):
            if key not in seen:
                seen.add(key)
                candidate_rules.extend(self._protocol_index.get(key, []))

        # Transport protocol
        _add(proto)
        # Application protocol via layer detection
        if http is not None:
            _add('HTTP')
        if dns is not None:
            _add('DNS')
        # Application protocol via port heuristics
        for port in (dst_port, src_port):
            if port is None:
                continue
            if port in (443, 8443):
                _add('TLS')
            elif port == 22:
                _add('SSH')
            elif port in (25, 465, 587):
                _add('SMTP')
            elif port == 21:
                _add('FTP')
            elif port in (445, 139):
                _add('SMB')
            elif port == 53:
                _add('DNS')
        
        for rule in candidate_rules:
            if not rule.enabled:
                continue
                
            if self._evaluate_conditions(rule.conditions, packet_info, flow):
                match = RuleMatch(
                    rule_name=rule.name,
                    severity=rule.severity,
                    description=rule.description,
                    category=rule.category,
                    matched_packets=[packet_info.packet_hash] if hasattr(packet_info, 'packet_hash') else [],
                    matched_flows=[flow.flow_id] if flow and hasattr(flow, 'flow_id') else [],
                    evidence=self._build_evidence(packet_info, flow, rule),
                    confidence=self._calculate_confidence(rule, packet_info),
                )
                matches.append(match)
                
        return matches
        
    def evaluate_flow(self, flow: Any) -> List[RuleMatch]:
        """Evaluate rules against a flow (protocol-indexed for speed)."""
        matches = []
        
        proto = getattr(flow, 'protocol', '').upper() if flow else ''
        dst_port = getattr(flow, 'dst_port', None)
        src_port = getattr(flow, 'src_port', None)

        seen = set()
        candidate_rules = list(self._any_protocol_rules)

        def _add(key):
            if key not in seen:
                seen.add(key)
                candidate_rules.extend(self._protocol_index.get(key, []))

        _add(proto)
        for port in (dst_port, src_port):
            if port is None:
                continue
            if port in (80, 8080, 8000, 8008, 8888):
                _add('HTTP')
            elif port in (443, 8443):
                _add('TLS')
            elif port == 22:
                _add('SSH')
            elif port in (25, 465, 587):
                _add('SMTP')
            elif port == 21:
                _add('FTP')
            elif port in (445, 139):
                _add('SMB')
            elif port == 53:
                _add('DNS')
        
        for rule in candidate_rules:
            if not rule.enabled:
                continue
                
            # Check if any packet in flow matches, or if flow-level conditions match
            flow_match = self._evaluate_conditions(rule.conditions, None, flow)
            
            if flow_match:
                match = RuleMatch(
                    rule_name=rule.name,
                    severity=rule.severity,
                    description=rule.description,
                    category=rule.category,
                    matched_flows=[flow.flow_id],
                    evidence=self._build_evidence(None, flow, rule),
                    confidence=self._calculate_confidence(rule, None),
                )
                matches.append(match)
                
        return matches
        
    def _evaluate_conditions(self, conditions: List[Dict], packet_info: Any, flow: Any) -> bool:
        """Evaluate a list of conditions with AND/OR logic."""
        if not conditions:
            return False
            
        logic = conditions[0].get('logic', 'and') if conditions else 'and'
        
        results = []
        for condition in conditions:
            if 'conditions' in condition:
                # Nested condition group
                result = self._evaluate_conditions(
                    condition['conditions'], packet_info, flow
                )
            else:
                result = RuleCondition.evaluate(packet_info, flow, condition)
            results.append(result)
            
        if logic == 'and':
            return all(results)
        elif logic == 'or':
            return any(results)
        elif logic == 'not':
            return not any(results)
        else:
            return all(results)
            
    def _build_evidence(self, packet_info: Any, flow: Any, rule: Rule) -> Dict[str, Any]:
        """Build evidence dictionary for a match."""
        evidence = {
            'rule': rule.name,
            'category': rule.category,
        }
        
        if packet_info:
            evidence['packet'] = {
                'src_ip': getattr(packet_info, 'src_ip', None),
                'dst_ip': getattr(packet_info, 'dst_ip', None),
                'src_port': getattr(packet_info, 'src_port', None),
                'dst_port': getattr(packet_info, 'dst_port', None),
                'protocol': getattr(packet_info, 'protocol', None),
                'timestamp': str(getattr(packet_info, 'timestamp', None)),
            }
            
        if flow:
            evidence['flow'] = {
                'flow_id': getattr(flow, 'flow_id', None),
                'packet_count': getattr(flow, 'packet_count', None),
                'duration': getattr(flow, 'duration', None),
                'total_bytes': getattr(flow, 'total_bytes', None),
            }
            
        return evidence
        
    def _calculate_confidence(self, rule: Rule, packet_info: Any) -> float:
        """Calculate confidence score for a match."""
        base_confidence = 0.7
        
        # Adjust based on number of conditions
        condition_count = len(rule.conditions)
        if condition_count > 3:
            base_confidence += 0.1
        if condition_count > 5:
            base_confidence += 0.1
            
        # Cap at 0.95
        return min(base_confidence, 0.95)
        
    def get_rule_stats(self) -> Dict[str, Any]:
        """Get statistics about loaded rules."""
        categories = {}
        severities = {}
        
        for rule in self.rules:
            categories[rule.category] = categories.get(rule.category, 0) + 1
            severities[rule.severity.value] = severities.get(rule.severity.value, 0) + 1
            
        return {
            'total_rules': len(self.rules),
            'enabled_rules': sum(1 for r in self.rules if r.enabled),
            'categories': categories,
            'severities': severities,
        }
