#!/usr/bin/env python3
"""
Generate Security Report from Scan Results
Aggregates results from multiple scanners and generates unified reports
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List


def load_scan_results(input_dir: Path) -> Dict:
    """
    Load all scan results from input directory

    Args:
        input_dir: Directory containing scan result files

    Returns:
        Dictionary with aggregated results
    """
    results = {
        'sast': {},
        'dependency': {},
        'container': {},
        'secrets': {},
        'summary': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'total': 0
        }
    }

    # Load SAST results
    sast_files = list(input_dir.rglob('**/semgrep-results.json'))
    sast_files.extend(input_dir.rglob('**/bandit-results.json'))

    for sast_file in sast_files:
        try:
            with open(sast_file, 'r') as f:
                data = json.load(f)
                if 'semgrep' in sast_file.name:
                    results['sast']['semgrep'] = data
                elif 'bandit' in sast_file.name:
                    results['sast']['bandit'] = data
        except Exception as e:
            print(f"Warning: Failed to load {sast_file}: {e}")

    # Load dependency results
    dep_files = list(input_dir.rglob('**/snyk-results.json'))
    dep_files.extend(input_dir.rglob('**/safety-results.json'))

    for dep_file in dep_files:
        try:
            with open(dep_file, 'r') as f:
                data = json.load(f)
                if 'snyk' in dep_file.name:
                    results['dependency']['snyk'] = data
                elif 'safety' in dep_file.name:
                    results['dependency']['safety'] = data
        except Exception as e:
            print(f"Warning: Failed to load {dep_file}: {e}")

    # Load container results
    container_files = list(input_dir.rglob('**/trivy-results.json'))

    for container_file in container_files:
        try:
            with open(container_file, 'r') as f:
                results['container']['trivy'] = json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load {container_file}: {e}")

    # Calculate summary
    results['summary'] = calculate_summary(results)

    return results


def calculate_summary(results: Dict) -> Dict:
    """
    Calculate vulnerability summary from all results

    Args:
        results: Aggregated scan results

    Returns:
        Summary dictionary
    """
    summary = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0,
        'total': 0
    }

    # Count from Semgrep results
    if 'semgrep' in results.get('sast', {}):
        semgrep_results = results['sast']['semgrep'].get('results', [])
        for result in semgrep_results:
            severity = result.get('extra', {}).get('severity', 'INFO').upper()
            if severity == 'ERROR':
                summary['high'] += 1
            elif severity == 'WARNING':
                summary['medium'] += 1
            else:
                summary['low'] += 1

    # Count from Snyk results
    if 'snyk' in results.get('dependency', {}):
        snyk_vulns = results['dependency']['snyk'].get('vulnerabilities', [])
        for vuln in snyk_vulns:
            severity = vuln.get('severity', 'low').lower()
            summary[severity] = summary.get(severity, 0) + 1

    # Count from Trivy results
    if 'trivy' in results.get('container', {}):
        trivy_results = results['container']['trivy'].get('Results', [])
        for result in trivy_results:
            for vuln in result.get('Vulnerabilities', []):
                severity = vuln.get('Severity', 'UNKNOWN').lower()
                if severity == 'critical':
                    summary['critical'] += 1
                elif severity == 'high':
                    summary['high'] += 1
                elif severity == 'medium':
                    summary['medium'] += 1
                elif severity == 'low':
                    summary['low'] += 1

    summary['total'] = sum(summary.values())

    return summary


def generate_html_report(results: Dict, output_file: Path):
    """
    Generate HTML security report

    Args:
        results: Aggregated scan results
        output_file: Output HTML file path
    """
    summary = results['summary']

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px; }}
            .summary {{ margin: 20px 0; }}
            .severity {{ display: inline-block; padding: 10px 20px; margin: 10px;
                       border-radius: 4px; color: white; font-weight: bold; }}
            .critical {{ background: #e74c3c; }}
            .high {{ background: #e67e22; }}
            .medium {{ background: #f39c12; }}
            .low {{ background: #3498db; }}
            .info {{ background: #95a5a6; }}
            .section {{ margin: 30px 0; padding: 20px; background: #ecf0f1; border-radius: 8px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ Security Scan Report</h1>
            <p>Comprehensive security analysis results</p>
        </div>

        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="severity critical">Critical: {summary['critical']}</div>
            <div class="severity high">High: {summary['high']}</div>
            <div class="severity medium">Medium: {summary['medium']}</div>
            <div class="severity low">Low: {summary['low']}</div>
            <div class="severity info">Info: {summary.get('info', 0)}</div>
        </div>

        <div class="section">
            <h3>Total Vulnerabilities: {summary['total']}</h3>
            <p>This report aggregates findings from SAST, dependency scanning, and container security analysis.</p>
        </div>

        <div class="section">
            <h3>Recommendations</h3>
            <ul>
                {'<li>⚠️ CRITICAL: Address critical vulnerabilities immediately</li>' if summary['critical'] > 0 else ''}
                {'<li>⚠️ HIGH: Address high-severity vulnerabilities as priority</li>' if summary['high'] > 0 else ''}
                {'<li>Review and remediate medium and low severity findings</li>' if summary['medium'] + summary['low'] > 0 else ''}
                {'<li>✅ No critical or high vulnerabilities found</li>' if summary['critical'] == 0 and summary['high'] == 0 else ''}
            </ul>
        </div>
    </body>
    </html>
    """

    with open(output_file, 'w') as f:
        f.write(html)

    print(f"HTML report generated: {output_file}")


def generate_markdown_summary(results: Dict, output_file: Path):
    """
    Generate Markdown summary for PR comments

    Args:
        results: Aggregated scan results
        output_file: Output markdown file path
    """
    summary = results['summary']

    markdown = f"""
## 🛡️ Security Scan Results

### Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {summary['critical']} |
| 🟠 High | {summary['high']} |
| 🟡 Medium | {summary['medium']} |
| 🔵 Low | {summary['low']} |
| **Total** | **{summary['total']}** |

### Status

{'❌ **FAILED** - Critical vulnerabilities detected!' if summary['critical'] > 0 else ''}
{'⚠️ **WARNING** - High severity vulnerabilities found' if summary['high'] > 5 and summary['critical'] == 0 else ''}
{'✅ **PASSED** - No critical or high vulnerabilities' if summary['critical'] == 0 and summary['high'] <= 5 else ''}

### Recommendations

{f"- 🚨 Address {summary['critical']} critical vulnerabilities immediately" if summary['critical'] > 0 else ""}
{f"- ⚠️ Review {summary['high']} high-severity findings" if summary['high'] > 0 else ""}
{f"- 📋 {summary['medium']} medium and {summary['low']} low severity issues found" if summary['medium'] + summary['low'] > 0 else ""}

---
*Generated by DevSecOps Pipeline Guardian*
"""

    with open(output_file, 'w') as f:
        f.write(markdown)

    print(f"Markdown summary generated: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Generate security report from scan results'
    )
    parser.add_argument('--input', required=True, help='Input directory with scan results')
    parser.add_argument('--output', required=True, help='Output file path')
    parser.add_argument('--format', choices=['html', 'markdown', 'json'],
                       default='html', help='Output format')

    args = parser.parse_args()

    input_dir = Path(args.input)
    output_file = Path(args.output)

    if not input_dir.exists():
        print(f"Error: Input directory {input_dir} does not exist")
        sys.exit(1)

    # Load scan results
    print(f"Loading scan results from {input_dir}...")
    results = load_scan_results(input_dir)

    # Generate report
    print(f"Generating {args.format} report...")

    if args.format == 'html':
        generate_html_report(results, output_file)
    elif args.format == 'markdown':
        generate_markdown_summary(results, output_file)
    elif args.format == 'json':
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"JSON report generated: {output_file}")

    # Print summary
    summary = results['summary']
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Critical: {summary['critical']}")
    print(f"High:     {summary['high']}")
    print(f"Medium:   {summary['medium']}")
    print(f"Low:      {summary['low']}")
    print(f"Total:    {summary['total']}")
    print("=" * 60)

    # Exit with error if critical vulnerabilities found
    if summary['critical'] > 0:
        print("\n❌ FAILED: Critical vulnerabilities detected!")
        sys.exit(1)
    elif summary['high'] > 10:
        print("\n⚠️  WARNING: High number of high-severity vulnerabilities")
        sys.exit(0)
    else:
        print("\n✅ PASSED: No critical vulnerabilities found")
        sys.exit(0)


if __name__ == '__main__':
    main()
