"""
Dependency Scanner - Vulnerability scanning for project dependencies
Integrates with Snyk and OWASP Dependency-Check
"""

import asyncio
import logging
import json
from typing import Dict, List, Optional
from pathlib import Path


class DependencyScanner:
    """
    Dependency vulnerability scanner
    Supports Snyk and OWASP Dependency-Check
    """
    
    def __init__(self, config: Dict):
        """
        Initialize dependency scanner
        
        Args:
            config: Scanner configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.tools = config.get('tools', ['snyk', 'dependency-check'])
        self.cvss_threshold = config.get('cvss_threshold', 7.0)
        
    async def scan(self, target: str, options: Optional[Dict] = None) -> Dict:
        """
        Execute dependency scan on target project
        
        Args:
            target: Path to project directory
            options: Additional scan options
            
        Returns:
            Dict containing scan results
        """
        self.logger.info(f"Starting dependency scan on: {target}")
        
        results = {
            'tool': 'dependency',
            'target': target,
            'vulnerabilities': [],
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        # Run configured tools
        tool_results = []
        
        if 'snyk' in self.tools:
            snyk_result = await self._run_snyk(target, options)
            tool_results.append(snyk_result)
            
        if 'dependency-check' in self.tools:
            owasp_result = await self._run_dependency_check(target, options)
            tool_results.append(owasp_result)
        
        # Aggregate results
        for tool_result in tool_results:
            if 'vulnerabilities' in tool_result:
                results['vulnerabilities'].extend(tool_result['vulnerabilities'])
                
                # Update summary
                for vuln in tool_result['vulnerabilities']:
                    severity = vuln.get('severity', 'low').lower()
                    if severity in results['summary']:
                        results['summary'][severity] += 1
        
        results['total_vulnerabilities'] = len(results['vulnerabilities'])
        
        self.logger.info(f"Dependency scan completed. Found {results['total_vulnerabilities']} vulnerabilities")
        
        return results
    
    async def _run_snyk(self, target: str, options: Optional[Dict] = None) -> Dict:
        """
        Run Snyk vulnerability scanner
        
        Args:
            target: Target directory
            options: Scan options
            
        Returns:
            Snyk scan results
        """
        self.logger.info("Running Snyk scan...")
        
        try:
            # Build snyk command
            cmd = [
                'snyk',
                'test',
                '--json',
                f'--severity-threshold={self._map_threshold_to_snyk()}',
                target
            ]
            
            # Add authentication token if available
            snyk_token = self.config.get('snyk_token')
            if snyk_token:
                cmd.insert(1, f'--token={snyk_token}')
            
            # Execute scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=target
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse JSON output (Snyk returns non-zero exit code when vulnerabilities found)
            try:
                snyk_output = json.loads(stdout.decode())
                vulnerabilities = self._parse_snyk_results(snyk_output)
                
                return {
                    'tool': 'snyk',
                    'vulnerabilities': vulnerabilities
                }
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse Snyk output: {str(e)}")
                return {'tool': 'snyk', 'error': str(e), 'vulnerabilities': []}
            
        except Exception as e:
            self.logger.error(f"Snyk scan error: {str(e)}")
            return {'tool': 'snyk', 'error': str(e), 'vulnerabilities': []}
    
    async def _run_dependency_check(self, target: str, options: Optional[Dict] = None) -> Dict:
        """
        Run OWASP Dependency-Check scanner
        
        Args:
            target: Target directory
            options: Scan options
            
        Returns:
            Dependency-Check scan results
        """
        self.logger.info("Running OWASP Dependency-Check scan...")
        
        try:
            output_format = 'JSON'
            output_dir = '/tmp/dependency-check-report'
            
            # Build dependency-check command
            cmd = [
                'dependency-check',
                '--scan', target,
                '--format', output_format,
                '--out', output_dir,
                '--failOnCVSS', str(self.cvss_threshold)
            ]
            
            # Add NVD API key if available
            nvd_api_key = self.config.get('nvd_api_key')
            if nvd_api_key:
                cmd.extend(['--nvdApiKey', nvd_api_key])
            
            # Execute scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Read and parse JSON report
            report_file = Path(output_dir) / 'dependency-check-report.json'
            if report_file.exists():
                with open(report_file, 'r') as f:
                    dc_output = json.load(f)
                    vulnerabilities = self._parse_dependency_check_results(dc_output)
                    
                    return {
                        'tool': 'dependency-check',
                        'vulnerabilities': vulnerabilities
                    }
            else:
                self.logger.warning("Dependency-Check report not found")
                return {'tool': 'dependency-check', 'vulnerabilities': []}
            
        except Exception as e:
            self.logger.error(f"Dependency-Check scan error: {str(e)}")
            return {'tool': 'dependency-check', 'error': str(e), 'vulnerabilities': []}
    
    def _parse_snyk_results(self, snyk_output: Dict) -> List[Dict]:
        """
        Parse Snyk JSON output into standardized format
        
        Args:
            snyk_output: Raw Snyk output
            
        Returns:
            List of standardized vulnerabilities
        """
        vulnerabilities = []
        
        for vuln in snyk_output.get('vulnerabilities', []):
            vulnerability = {
                'id': vuln.get('id', 'unknown'),
                'title': vuln.get('title', 'No title'),
                'severity': vuln.get('severity', 'unknown'),
                'cvss_score': vuln.get('cvssScore', 0),
                'package': vuln.get('packageName', 'unknown'),
                'version': vuln.get('version', 'unknown'),
                'fixed_in': vuln.get('fixedIn', []),
                'cve': vuln.get('identifiers', {}).get('CVE', []),
                'cwe': vuln.get('identifiers', {}).get('CWE', []),
                'tool': 'snyk',
                'description': vuln.get('description', '')
            }
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _parse_dependency_check_results(self, dc_output: Dict) -> List[Dict]:
        """
        Parse OWASP Dependency-Check JSON output into standardized format
        
        Args:
            dc_output: Raw Dependency-Check output
            
        Returns:
            List of standardized vulnerabilities
        """
        vulnerabilities = []
        
        for dependency in dc_output.get('dependencies', []):
            for vuln in dependency.get('vulnerabilities', []):
                vulnerability = {
                    'id': vuln.get('name', 'unknown'),
                    'title': vuln.get('description', 'No description'),
                    'severity': vuln.get('severity', 'unknown'),
                    'cvss_score': vuln.get('cvssv3', {}).get('baseScore', 0),
                    'package': dependency.get('fileName', 'unknown'),
                    'cve': [vuln.get('name')] if vuln.get('name', '').startswith('CVE') else [],
                    'cwe': vuln.get('cwes', []),
                    'tool': 'dependency-check',
                    'description': vuln.get('description', ''),
                    'references': vuln.get('references', [])
                }
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _map_threshold_to_snyk(self) -> str:
        """Map CVSS threshold to Snyk severity levels"""
        if self.cvss_threshold >= 9.0:
            return 'critical'
        elif self.cvss_threshold >= 7.0:
            return 'high'
        elif self.cvss_threshold >= 4.0:
            return 'medium'
        else:
            return 'low'
