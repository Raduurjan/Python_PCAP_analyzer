"""Command-line interface for PCAP Analyzer."""

import click
import sys
import os
import time
import traceback
from pathlib import Path
from typing import List, Optional
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm

from pcap_analyzer.core.analyzer import PCAPAnalyzer


def print_banner():
    """Print application banner."""
    banner = """
    ____   ____ ____   ____  _            _             
   |  _ \\/ ___/ ___| / ___|| | ___   ___| | __  _ __   
   | |_) \\___ \\___ \\| |    | |/ _ \\ / __| |/ / | '_ \\  
   |  __/ ___) |__) | |___ | | (_) | (__|   < _| |_) | 
   |_|   |____/____/ \\____||_|\\___/ \\___|_|\\_(_) .__/  
                                                  |_|    
            Security Analyzer for Incident Response
    """
    click.echo(click.style(banner, fg='cyan', bold=True))


@click.command()
@click.argument('pcap_files', nargs=-1, required=True, type=click.Path(exists=True))
@click.option('--output', '-o', default='./reports', help='Output directory for reports')
@click.option('--format', 'report_format', default='json',
              type=click.Choice(['json'], case_sensitive=False),
              help='Report format (json)')
@click.option('--rules', '-r', type=click.Path(exists=True), help='Path to rules file or directory')
@click.option('--max-packets', type=int, help='Maximum packets to process per file')
@click.option('--severity-filter', default='low',
              type=click.Choice(['critical', 'high', 'medium', 'low', 'info'], case_sensitive=False),
              help='Minimum severity level to report')
@click.option('--confidence', '-c', default=0.7, type=float,
              help='Minimum confidence threshold for detector findings (0.0-1.0)')
@click.option('--no-progress', is_flag=True, help='Disable progress bar')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def analyze(pcap_files: List[str], output: str, report_format: str, 
            rules: Optional[str], max_packets: Optional[int],
            severity_filter: str, confidence: float, no_progress: bool, verbose: bool):
    """Analyze PCAP file(s) for security threats.
    
    PCAP_FILES: One or more PCAP files to analyze
    """
    print_banner()
    
    # Setup output directory
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    
    formats = ['json']
        
    # Severity filter mapping
    severity_levels = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    min_level = severity_levels.get(severity_filter.lower(), 3)
    
    all_results = []
    
    for pcap_file in pcap_files:
        click.echo(f"\n{'=' * 60}")
        click.echo(f"Processing: {pcap_file}")
        click.echo(f"{'=' * 60}")
        
        # Progress callback
        _show_progress = no_progress is False and sys.stdout.isatty()
        progress_bar = None
        last_count = [0]
        def progress_callback(count, done=False):
            nonlocal progress_bar
            if _show_progress:
                if done:
                    if progress_bar:
                        progress_bar.close()
                        progress_bar = None
                    last_count[0] = 0
                elif count > 0:
                    if progress_bar is None:
                        progress_bar = tqdm(desc="Processing", unit=" packets", total=None, dynamic_ncols=True)
                    delta = count - last_count[0]
                    if delta > 0:
                        progress_bar.update(delta)
                    last_count[0] = count
        
        try:
            # Create analyzer with confidence threshold
            analyzer = PCAPAnalyzer(
                rules_path=rules,
                progress_callback=progress_callback if not no_progress else None,
                confidence_threshold=confidence
            )
            
            # Run analysis
            results = analyzer.analyze(pcap_file, max_packets=max_packets)
            
            # Filter findings by severity
            if 'findings' in results:
                filtered = [
                    f for f in results['findings']
                    if severity_levels.get(f.get('severity', 'info').lower(), 5) <= min_level
                ]
                results['findings'] = filtered
                results['summary']['total_findings'] = len(filtered)
            
            all_results.append(results)
            
            # Print summary
            analyzer.print_summary()
            
            # Generate reports
            click.echo(f"\n[+] Generating reports...")
            reports = analyzer.generate_report(
                str(output_path / Path(pcap_file).stem),
                formats=formats
            )
            
            click.echo(f"\n[+] Reports saved to:")
            for fmt, path in reports.items():
                click.echo(f"    - {fmt.upper()}: {path}")
                
        except Exception as e:
            click.echo(click.style(f"\n[!] Error analyzing {pcap_file}: {e}", fg='red', bold=True))
            if verbose:
                import traceback
                traceback.print_exc()
            continue
    
    # Print final summary
    click.echo(f"\n{'=' * 60}")
    click.echo("ANALYSIS COMPLETE")
    click.echo(f"{'=' * 60}")
    click.echo(f"Files processed: {len(pcap_files)}")
    
    total_findings = sum(r.get('summary', {}).get('total_findings', 0) for r in all_results)
    click.echo(f"Total findings: {total_findings}")
    
    if all_results:
        max_risk = max(r.get('summary', {}).get('risk_score', 0) for r in all_results)
        risk_color = 'green' if max_risk < 30 else 'yellow' if max_risk < 70 else 'red'
        click.echo(f"Highest risk score: {click.style(str(max_risk), fg=risk_color, bold=True)}/100")


@click.command()
@click.argument('rules_path', type=click.Path(exists=True))
def validate_rules(rules_path: str):
    """Validate rule file(s)."""
    from pcap_analyzer.rules.rule_engine import RuleEngine
    
    click.echo(f"Validating rules in: {rules_path}")
    
    engine = RuleEngine()
    path = Path(rules_path)
    
    try:
        if path.is_file():
            engine.load_rule_file(path)
        else:
            count = engine.load_rules_directory(path)
            click.echo(f"Loaded {count} rule files")
            
        stats = engine.get_rule_stats()
        
        click.echo(f"\nRule Statistics:")
        click.echo(f"  Total rules: {stats['total_rules']}")
        click.echo(f"  Enabled rules: {stats['enabled_rules']}")
        
        if stats['categories']:
            click.echo(f"\nCategories:")
            for cat, count in stats['categories'].items():
                click.echo(f"  - {cat}: {count}")
                
        if stats['severities']:
            click.echo(f"\nSeverities:")
            for sev, count in stats['severities'].items():
                click.echo(f"  - {sev}: {count}")
                
        click.echo(click.style("\n[+] Rules validated successfully", fg='green'))
        
    except Exception as e:
        click.echo(click.style(f"\n[!] Validation failed: {e}", fg='red', bold=True))
        sys.exit(1)


def _analyze_single(args):
    """Worker function executed in a subprocess for one PCAP file."""
    pcap_file, output_dir, report_format, confidence = args
    try:
        analyzer = PCAPAnalyzer(confidence_threshold=confidence)
        results = analyzer.analyze(pcap_file)
        stem = Path(pcap_file).stem
        out = Path(output_dir) / stem
        out.mkdir(parents=True, exist_ok=True)
        formats = ['json']
        analyzer.generate_report(str(out / 'report'), formats=formats)
        total = results.get('summary', {}).get('total_findings', 0)
        risk  = results.get('summary', {}).get('risk_score', 0)
        return (pcap_file, True, total, risk, None)
    except Exception as e:
        return (pcap_file, False, 0, 0, str(e))


@click.command()
@click.argument('input_dir', type=click.Path(exists=True, file_okay=False))
@click.option('--output', '-o', default='./reports', help='Output directory for reports')
@click.option('--format', 'report_format', default='json',
              type=click.Choice(['json'], case_sensitive=False),
              help='Report format (json)')
@click.option('--workers', '-w', default=8, type=int, help='Parallel worker processes')
@click.option('--batch', '-b', default=8, type=int, help='Files per batch')
@click.option('--confidence', '-c', default=0.7, type=float,
              help='Minimum confidence threshold (0.0-1.0)')
@click.option('--ext', default='.pcap', help='File extension to match (default: .pcap)')
def batch_analyze(input_dir, output, report_format, workers, batch, confidence, ext):
    """Analyze all PCAP files in a directory using parallel workers.

    INPUT_DIR: Directory containing PCAP files to analyze
    """
    print_banner()

    pcap_files = sorted([
        str(p) for p in Path(input_dir).iterdir()
        if p.suffix.lower() == ext.lower()
    ])

    if not pcap_files:
        click.echo(click.style(f'[!] No {ext} files found in {input_dir}', fg='red'))
        sys.exit(1)

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    click.echo(f'[*] Found {len(pcap_files)} files  |  workers={workers}  batch={batch}  conf>={confidence}')
    click.echo(f'[*] Output: {output_path.resolve()}\n')

    args_list = [(f, str(output_path), report_format, confidence) for f in pcap_files]

    ok = err = total_findings = 0
    start = time.time()

    with tqdm(total=len(pcap_files), unit='file', ncols=80) as pbar:
        # Process in batches to keep memory bounded
        for batch_start in range(0, len(args_list), batch):
            chunk = args_list[batch_start:batch_start + batch]
            with ProcessPoolExecutor(max_workers=min(workers, len(chunk))) as ex:
                futures = {ex.submit(_analyze_single, a): a[0] for a in chunk}
                for fut in as_completed(futures):
                    pcap_file, success, findings, risk, error = fut.result()
                    name = Path(pcap_file).name
                    if success:
                        ok += 1
                        total_findings += findings
                        pbar.set_postfix_str(f'ok={ok} err={err} findings={total_findings}')
                    else:
                        err += 1
                        tqdm.write(click.style(f'  [ERR] {name}: {error}', fg='red'))
                    pbar.update(1)

    elapsed = time.time() - start
    click.echo(f'\n{"="*60}')
    click.echo(f'BATCH COMPLETE  ({elapsed:.1f}s)')
    click.echo(f'{"="*60}')
    click.echo(f'  Files processed : {ok + err}')
    click.echo(f'  Succeeded       : {ok}')
    click.echo(f'  Failed          : {err}')
    click.echo(f'  Total findings  : {total_findings}')
    click.echo(f'  Reports in      : {output_path.resolve()}')


@click.group()
def cli():
    """PCAP Security Analyzer - Detect threats in network traffic."""
    pass


cli.add_command(analyze)
cli.add_command(validate_rules)
cli.add_command(batch_analyze)


if __name__ == '__main__':
    cli()
