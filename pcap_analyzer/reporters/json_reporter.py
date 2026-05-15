"""JSON report generator."""

import json
from typing import Dict, List, Any
from datetime import datetime
from pathlib import Path


class JSONReporter:
    """Generate JSON format reports."""
    
    def __init__(self, output_path: str):
        self.output_path = Path(output_path)
        
    def generate(self, analysis_results: Dict[str, Any]) -> str:
        """Generate JSON report."""
        # Convert datetime objects to strings
        serializable_results = self._make_serializable(analysis_results)
        
        # Add metadata
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool': 'PCAP Security Analyzer',
                'version': '1.0.0',
            },
            'summary': serializable_results.get('summary', {}),
            'statistics': serializable_results.get('statistics', {}),
            'findings': serializable_results.get('findings', []),
            'rule_matches': serializable_results.get('rule_matches', []),
            'flows': serializable_results.get('flows', []),
        }
        
        # Write to file
        output_file = self.output_path / 'report.json'
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        return str(output_file)
        
    def _make_serializable(self, obj: Any) -> Any:
        """Convert objects to JSON-serializable format."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif hasattr(obj, '__dict__'):
            return self._make_serializable(obj.__dict__)
        else:
            return obj
