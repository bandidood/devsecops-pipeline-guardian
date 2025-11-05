"""
DAST Scanner - Dynamic Application Security Testing
Integrates with OWASP ZAP for runtime security testing
"""

import asyncio
import logging
import json
from typing import Dict, List, Optional
import time


class DASTScanner:
    """
    Dynamic Application Security Testing scanner
    Supports OWASP ZAP
    """
    
    def __init__(self, config: Dict):
        """
        Initialize DAST scanner
        
        Args:
            config: Scanner configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.zap_api_key = config.get('zap_api_key', '')
        self.zap_host = config.get('zap_host', 'http://localhost:8090')
        
    async def scan(self, target: str, options: Optional[Dict] = None) -> Dict:
        """
        Execute DAST scan on target URL
        
        Args:
            target: Target URL to scan
            options: Additional scan options
            
        Returns:
            Dict containing scan results
        """
        self.logger.info(f"Starting DAST scan on: {target}")
        
        results = {
            'tool': 'dast',
            'target': target,
            'vulnerabilities': [],
            'summary': {
                'high': 0,
                'medium': 0,
                'low': 0,
                'informational': 0
            }
        }
        
        # Run OWASP ZAP scan
        zap_result = await self._run_zap_scan(target, options)
        
        if 'vulnerabilities' in zap_result:
            results['vulnerabilities'] = zap_result['vulnerabilities']
            
            # Update summary
            for vuln in results['vulnerabilities']:
                risk = vuln.get('risk', 'informational').lower()
                if risk in results['summary']:
                    results['summary'][risk] += 1
        
        results['total_alerts'] = len(results['vulnerabilities'])
        
        self.logger.info(f"DAST scan completed. Found {results['total_alerts']} alerts")
        
        return results
    
    async def _run_zap_scan(self, target: str, options: Optional[Dict] = None) -> Dict:
        """
        Run OWASP ZAP scanner
        
        Args:
            target: Target URL
            options: Scan options
            
        Returns:
            ZAP scan results
        """
        self.logger.info("Running OWASP ZAP scan...")
        
        try:
            scan_type = options.get('scan_type', 'baseline') if options else 'baseline'
            
            if scan_type == 'baseline':
                return await self._run_zap_baseline(target, options)
            elif scan_type == 'full':
                return await self._run_zap_full_scan(target, options)
            else:
                raise ValueError(f"Unknown scan type: {scan_type}")
                
        except Exception as e:
            self.logger.error(f"ZAP scan error: {str(e)}")
            return {'tool': 'zap', 'error': str(e), 'vulnerabilities': []}
    
    async def _run_zap_baseline(self, target: str, options: Optional[Dict] = None) -> Dict:
        """
        Run ZAP baseline scan
        
        Args:
            target: Target URL
            options: Scan options
            
        Returns:
            Baseline scan results
        """
        self.logger.info("Running ZAP baseline scan...")
        
        try:
            # Build zap-baseline command
            cmd = [
                'docker', 'run', '--rm',
                '-v', '/tmp/zap:/zap/wrk:rw',
                'owasp/zap2docker-stable',
                'zap-baseline.py',
                '-t', target,
                '-J', 'zap-report.json',
                '-r', 'zap-report.html'
            ]
            
            # Execute scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Read JSON report
            try:
                with open('/tmp/zap/zap-report.json', 'r') as f:
                    zap_output = json.load(f)
                    vulnerabilities = self._parse_zap_results(zap_output)
                    
                    return {
                        'tool': 'zap',
                        'scan_type': 'baseline',
                        'vulnerabilities': vulnerabilities
                    }
            except FileNotFoundError:
                self.logger.error("ZAP report not found")
                return {'tool': 'zap', 'error': 'Report not found', 'vulnerabilities': []}
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse ZAP output: {str(e)}")
                return {'tool': 'zap', 'error': str(e), 'vulnerabilities': []}
            
        except Exception as e:
            self.logger.error(f"ZAP baseline scan error: {str(e)}")
            return {'tool': 'zap', 'error': str(e), 'vulnerabilities': []}
    
    async def _run_zap_full_scan(self, target: str, options: Optional[Dict] = None) -> Dict:
        """
        Run ZAP full scan (active scan with spider)
        
        Args:
            target: Target URL
            options: Scan options
            
        Returns:
            Full scan results
        """
        self.logger.info("Running ZAP full scan...")
        
        try:
            # Build zap-full-scan command
            cmd = [
                'docker', 'run', '--rm',
                '-v', '/tmp/zap:/zap/wrk:rw',
                'owasp/zap2docker-stable',
                'zap-full-scan.py',
                '-t', target,
                '-J', 'zap-report.json',
                '-r', 'zap-report.html'
            ]
            
            # Execute scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Read JSON report
            try:
                with open('/tmp/zap/zap-report.json', 'r') as f:
                    zap_output = json.load(f)
                    vulnerabilities = self._parse_zap_results(zap_output)
                    
                    return {
                        'tool': 'zap',
                        'scan_type': 'full',
                        'vulnerabilities': vulnerabilities
                    }
            except FileNotFoundError:
                self.logger.error("ZAP report not found")
                return {'tool': 'zap', 'error': 'Report not found', 'vulnerabilities': []}
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse ZAP output: {str(e)}")
                return {'tool': 'zap', 'error': str(e), 'vulnerabilities': []}
            
        except Exception as e:
            self.logger.error(f"ZAP full scan error: {str(e)}")
            return {'tool': 'zap', 'error': str(e), 'vulnerabilities': []}
    
    def _parse_zap_results(self, zap_output: Dict) -> List[Dict]:
        """
        Parse ZAP JSON output into standardized format
        
        Args:
            zap_output: Raw ZAP output
            
        Returns:
            List of standardized vulnerabilities
        """
        vulnerabilities = []
        
        # ZAP report structure: site[0].alerts[]
        sites = zap_output.get('site', [])
        
        for site in sites:
            for alert in site.get('alerts', []):
                vuln = {
                    'id': alert.get('pluginid', 'unknown'),
                    'title': alert.get('name', 'No title'),
                    'risk': alert.get('riskdesc', 'Informational').split()[0].lower(),
                    'confidence': alert.get('confidence', 'Unknown'),
                    'url': alert.get('url', ''),
                    'description': alert.get('desc', ''),
                    'solution': alert.get('solution', ''),
                    'reference': alert.get('reference', ''),
                    'cwe_id': alert.get('cweid', ''),
                    'wasc_id': alert.get('wascid', ''),
                    'tool': 'zap'
                }
                vulnerabilities.append(vuln)
        
        return vulnerabilities
