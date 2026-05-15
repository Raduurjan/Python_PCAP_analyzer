# PCAP Security Analyzer

Offline network forensics tool. Point it at a `.pcap` file and it detects C2 beaconing, data exfiltration, lateral movement, reconnaissance, and credential attacks. Outputs a `report.json` per file. No cloud lookups, no network calls.

---

## Deploy

**Local (Python)**
```bash
pip install -r requirements.txt   # Python 3.11+ required
```

**Docker**
```bash
docker build -t pcap-analyzer .

# Mount your PCAPs and output folder at runtime — never bake them into the image
docker run --rm \
  -v /path/to/pcaps:/data \
  -v /path/to/output:/app/reports \
  pcap-analyzer analyze /data/capture.pcap --output /app/reports
```

---

## Commands

### `analyze` — single file

```bash
python analyze.py analyze <PCAP_FILE> [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--output / -o` | `./reports` | Folder to write the report into |
| `--confidence / -c` | `0.7` | Minimum detector confidence to include a finding (0.0–1.0). Lower = more findings, more noise. |
| `--severity-filter` | `low` | Drop findings below this level: `low` `medium` `high` `critical` |
| `--rules / -r` | _(none)_ | Path to a YAML rules file or folder. **If omitted, the rule engine is skipped entirely** — only the 5 behavioral detectors run. |
| `--max-packets` | _(all)_ | Process only the first N packets. Useful for quick triage on large files. |
| `--no-progress` | off | Suppress the progress bar (cleaner output in scripts/CI). |
| `--verbose / -v` | off | Print full stack traces on errors. |

Report is written to `<output>/<pcap_stem>/report.json`.

**Examples:**
```bash
# Detectors only (no rules)
docker run --rm -v /path/to/pcaps:/data -v /path/to/output:/app/reports \
  pcap-analyzer analyze /data/capture.pcap

# Detectors + bundled rules
docker run --rm -v /path/to/pcaps:/data -v /path/to/output:/app/reports \
  pcap-analyzer analyze /data/capture.pcap --rules /app/rules/malware_detection.yaml

# High-confidence, high-severity only
docker run --rm -v /path/to/pcaps:/data -v /path/to/output:/app/reports \
  pcap-analyzer analyze /data/capture.pcap --rules /app/rules/malware_detection.yaml \
  --confidence 0.9 --severity-filter high

# Quick triage — first 50k packets only
docker run --rm -v /path/to/pcaps:/data -v /path/to/output:/app/reports \
  pcap-analyzer analyze /data/capture.pcap --max-packets 50000
```

---

### `batch-analyze` — whole directory

Processes every `.pcap` in a directory using parallel worker processes.

```bash
docker run --rm -v /path/to/pcaps:/data -v /path/to/output:/app/reports \
  pcap-analyzer batch-analyze <INPUT_DIR> [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--output / -o` | `./reports` | Root output folder — each file gets its own subfolder |
| `--workers / -w` | `8` | Number of parallel worker processes |
| `--batch / -b` | `8` | Files dispatched per batch before waiting for results. Keeps memory bounded. |
| `--confidence / -c` | `0.7` | Minimum confidence threshold |
| `--ext` | `.pcap` | File extension to match (e.g. `.pcapng`) |

Each file produces `<output>/<pcap_stem>/report/report.json`. Corrupt or unreadable files are logged and skipped — they do not stop the rest.

**Examples:**
```bash
# Analyze a full directory, 8 workers
docker run --rm -v /path/to/pcaps:/data -v /path/to/output:/app/reports \
  pcap-analyzer batch-analyze /data --output /app/reports --workers 8

# High-confidence findings only
docker run --rm -v /path/to/pcaps:/data -v /path/to/output:/app/reports \
  pcap-analyzer batch-analyze /data --output /app/reports --workers 8 --confidence 0.85
```

---

### `validate-rules` — check rule files

Parses and validates YAML rule files without running any analysis.

```bash
docker run --rm pcap-analyzer validate-rules /app/rules/
docker run --rm pcap-analyzer validate-rules /app/rules/malware_detection.yaml
```

Prints rule counts by category and severity, and exits non-zero on any parse error.

---

## Detectors vs Rules

The tool has two independent detection mechanisms that can be used together or separately:

**Behavioral detectors** (always run) — 5 Python modules that analyse flow-level patterns: timing, volumes, port behaviour, protocol anomalies. They catch things rules can't express, like beacon intervals or brute force rate.

**Rule engine** (opt-in via `--rules`) — evaluates your YAML rules against every packet and flow. The bundled `rules/malware_detection.yaml` contains 3,447 signature rules converted from Emerging Threats. Pass `--rules` to enable it; omit it to run detectors only.

| Scenario | Command |
|---|---|
| Detectors only (fast) | `pcap-analyzer analyze /data/capture.pcap` |
| Rules only (signature match) | `pcap-analyzer analyze /data/capture.pcap --rules /app/rules/malware_detection.yaml --confidence 0.5` |
| Both (full coverage) | `pcap-analyzer analyze /data/capture.pcap --rules /app/rules/malware_detection.yaml` |

---

## Report format

`report.json` structure:
```json
{
  "summary": {
    "total_findings": 12,
    "risk_score": 74,
    "severity_counts": { "critical": 2, "high": 5, "medium": 4, "low": 1 }
  },
  "findings": [
    {
      "type": "low_and_slow_c2",
      "severity": "high",
      "confidence": 0.85,
      "source_ip": "1.2.3.4",
      "destination": "5.6.7.8:443",
      "description": "...",
      "evidence": { "flows": 5, "avg_interval_seconds": 732 }
    }
  ]
}
```

- **`type`** — which detector or rule triggered
- **`severity`** — `low` / `medium` / `high` / `critical`
- **`confidence`** — 0.0–1.0; filter with `--confidence`
- **`evidence`** — raw numbers behind the alert

---

## Project Structure

```
├── analyze.py                  # CLI entry point
├── Dockerfile
├── requirements.txt
├── rules/
│   └── malware_detection.yaml  # 3,447 merged ET rules
└── pcap_analyzer/
    ├── cli.py
    ├── core/
    │   ├── packet_parser.py    # Parses .pcap, rebuilds flows
    │   └── analyzer.py         # Orchestrates detectors + rules + reporter
    ├── detectors/
    │   ├── c2_detector.py
    │   ├── exfiltration.py
    │   ├── lateral_movement.py
    │   ├── credential_access.py
    │   └── reconnaissance.py
    ├── rules/
    │   └── rule_engine.py      # YAML rule parser and evaluator
    └── reporters/
        └── json_reporter.py
```
