"""
CLI - Command Line Interface for DevSecOps Pipeline Guardian
Provides commands to run security scans from the terminal
"""

import argparse
import asyncio
import logging
import sys
import yaml
from pathlib import Path
from typing import Dict

from src.orchestrator.security_orchestrator import SecurityOrchestrator, ScanType


def load_config(config_file: str) -> Dict:
    """
    Load configuration from YAML file
    
    Args:
        config_file: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    config_path = Path(config_file)
    
    if not config_path.exists():
        logging.warning(f"Config file {config_file} not found, using defaults")
        return {}
    
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def setup_logging(verbose: bool = False):
    """Configure logging"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


async def run_scan(args):
    """
    Execute security scan
    
    Args:
        args: Parsed command line arguments
    """
    # Load configuration
    config = load_config(args.config)
    
    # Create orchestrator
    orchestrator = SecurityOrchestrator(config)
    
    # Determine scan type
    scan_type_map = {
        'full': ScanType.FULL,
        'sast': ScanType.SAST,
        'dast': ScanType.DAST,
        'dependency': ScanType.DEPENDENCY,
        'container': ScanType.CONTAINER
    }
    
    scan_type = scan_type_map.get(args.type, ScanType.FULL)
    
    # Prepare scan options
    options = {
        'include_dast': args.include_dast or args.type == 'full',
        'include_container': args.include_container or args.type == 'full',
        'evaluate_policy': args.evaluate_policy
    }
    
    # Run scan
    print(f"\n🔍 Starting {args.type} security scan on: {args.target}")
    print("=" * 70)
    
    try:
        results = await orchestrator.run_scan(scan_type, args.target, options)
        
        # Display results
        print_results(results)
        
        # Export results if requested
        if args.output:
            export_results(orchestrator, results['scan_id'], args.output, args.format)
        
        # Exit with appropriate code based on policy evaluation
        if args.fail_on_policy and results.get('policy_evaluation', {}).get('decision') == 'deny':
            print("\n❌ Security policy check FAILED - exiting with code 1")
            sys.exit(1)
        
        print("\n✅ Security scan completed successfully")
        sys.exit(0)
        
    except Exception as e:
        print(f"\n❌ Error during security scan: {str(e)}")
        sys.exit(1)


def print_results(results: Dict):
    """
    Print scan results in human-readable format
    
    Args:
        results: Scan results dictionary
    """
    print(f"\n📊 Scan Results (ID: {results.get('scan_id', 'N/A')})")
    print("-" * 70)
    
    scan_results = results.get('results', {})
    
    # Print summary for each scan type
    for scan_type, data in scan_results.items():
        if isinstance(data, dict) and 'summary' in data:
            print(f"\n{scan_type.upper()} Scan:")
            summary = data['summary']
            
            for severity, count in summary.items():
                if count > 0:
                    icon = get_severity_icon(severity)
                    print(f"  {icon} {severity.capitalize()}: {count}")
    
    # Print policy evaluation results
    if 'policy_evaluation' in results:
        policy = results['policy_evaluation']
        print(f"\n🔐 Policy Evaluation:")
        print(f"  Decision: {policy.get('decision', 'N/A')}")
        print(f"  Security Score: {policy.get('security_score', 0)}/100")
        
        violations = policy.get('violations', [])
        if violations:
            print(f"  Violations: {len(violations)}")
            for violation in violations[:5]:  # Show first 5 violations
                print(f"    - {violation}")
    
    # Print duration
    duration = results.get('duration_seconds', 0)
    print(f"\n⏱️  Scan Duration: {duration:.2f} seconds")


def get_severity_icon(severity: str) -> str:
    """Get emoji icon for severity level"""
    icons = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢',
        'info': 'ℹ️',
        'informational': 'ℹ️'
    }
    return icons.get(severity.lower(), '❔')


def export_results(orchestrator: SecurityOrchestrator, scan_id: str, output_file: str, format: str):
    """
    Export scan results to file
    
    Args:
        orchestrator: SecurityOrchestrator instance
        scan_id: Scan ID
        output_file: Output file path
        format: Output format
    """
    try:
        exported = orchestrator.export_results(scan_id, format)
        
        with open(output_file, 'w') as f:
            f.write(exported)
        
        print(f"\n💾 Results exported to: {output_file}")
    except Exception as e:
        print(f"\n⚠️  Failed to export results: {str(e)}")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='DevSecOps Pipeline Guardian - Security Scanning Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full security scan
  python -m src.cli scan --type full --target ./my-project

  # SAST only
  python -m src.cli scan --type sast --target ./my-project

  # Container scan
  python -m src.cli scan --type container --target nginx:latest

  # With policy evaluation
  python -m src.cli scan --type full --target ./my-project --evaluate-policy
        """
    )
    
    # Global options
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--config', default='security-config.yaml',
                       help='Path to configuration file (default: security-config.yaml)')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run security scan')
    scan_parser.add_argument('--type', choices=['full', 'sast', 'dast', 'dependency', 'container'],
                            default='full', help='Type of scan to run')
    scan_parser.add_argument('--target', required=True,
                            help='Target to scan (path, URL, or image name)')
    scan_parser.add_argument('--include-dast', action='store_true',
                            help='Include DAST scan (for full scan type)')
    scan_parser.add_argument('--include-container', action='store_true',
                            help='Include container scan (for full scan type)')
    scan_parser.add_argument('--evaluate-policy', action='store_true',
                            help='Evaluate results against security policies')
    scan_parser.add_argument('--fail-on-policy', action='store_true',
                            help='Exit with error if policy evaluation fails')
    scan_parser.add_argument('--output', help='Output file path for results')
    scan_parser.add_argument('--format', choices=['json', 'sarif', 'html'],
                            default='json', help='Output format')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Execute command
    if args.command == 'scan':
        asyncio.run(run_scan(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
