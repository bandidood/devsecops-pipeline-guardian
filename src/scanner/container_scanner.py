"""
Container Scanner - Container image vulnerability scanning
Integrates with Trivy and Docker Scout
"""

import asyncio
import logging
import json
from typing import Dict, List, Optional


class ContainerScanner:
    """
    Container image vulnerability scanner
    Supports Trivy and Docker Scout
    """
    
    def __init__(self, config: Dict):
        """
        Initialize container scanner
        
        Args:
            config: Scanner configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.tools = config.get('tools', ['trivy'])
        self.severity = config.get('severity', 'CRITICAL,HIGH')
        self.ignore_unfixed = config.get('ignore_unfixed', False)
        
    async def scan(self, target: str, options: Optional[Dict] = None) -> Dict:
        """
        Execute container scan on target image
        
        Args:
            target: Container image name (e.g., nginx:latest)
            options: Additional scan options
            
        Returns:
            Dict containing scan results
        """
        self.logger.info(f"Starting container scan on: {target}")
        
        results = {
            'tool': 'container',
            'target': target,
            'vulnerabilities': [],
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'unknown': 0
            }
        }
        
        # Run configured tools
        tool_results = []
        
        if 'trivy' in self.tools:
            trivy_result = await self._run_trivy(target, options)
            tool_results.append(trivy_result)
        
        # Aggregate results
        for tool_result in tool_results:
            if 'vulnerabilities' in tool_result:
                results['vulnerabilities'].extend(tool_result['vulnerabilities'])
                
                # Update summary
                for vuln in tool_result['vulnerabilities']:
                    severity = vuln.get('severity', 'unknown').lower()
                    if severity in results['summary']:
                        results['summary'][severity] += 1
        
        results['total_vulnerabilities'] = len(results['vulnerabilities'])
        
        self.logger.info(f"Container scan completed. Found {results['total_vulnerabilities']} vulnerabilities")
        
        return results
    
    async def _run_trivy(self, target: str, options: Optional[Dict] = None) -> Dict:
        """
        Run Trivy container scanner
        
        Args:
            target: Container image
            options: Scan options
            
        Returns:
            Trivy scan results
        """
        self.logger.info("Running Trivy scan...")
        
        try:
            # Build trivy command
            cmd = [
                'trivy',
                'image',
                '--format', 'json',
                '--severity', self.severity
            ]
            
            if self.ignore_unfixed:
                cmd.append('--ignore-unfixed')
            
            # Add scan type
            scan_type = options.get('scan_type', 'os,library') if options else 'os,library'
            cmd.extend(['--vuln-type', scan_type])
            
            cmd.append(target)
            
            # Execute scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"Trivy scan failed: {stderr.decode()}")
                return {'tool': 'trivy', 'error': stderr.decode(), 'vulnerabilities': []}
            
            # Parse JSON output
            try:
                trivy_output = json.loads(stdout.decode())
                vulnerabilities = self._parse_trivy_results(trivy_output)
                
                return {
                    'tool': 'trivy',
                    'vulnerabilities': vulnerabilities
                }
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse Trivy output: {str(e)}")
                return {'tool': 'trivy', 'error': str(e), 'vulnerabilities': []}
            
        except Exception as e:
            self.logger.error(f"Trivy scan error: {str(e)}")
            return {'tool': 'trivy', 'error': str(e), 'vulnerabilities': []}
    
    def _parse_trivy_results(self, trivy_output: Dict) -> List[Dict]:
        """
        Parse Trivy JSON output into standardized format
        
        Args:
            trivy_output: Raw Trivy output
            
        Returns:
            List of standardized vulnerabilities
        """
        vulnerabilities = []
        
        # Trivy structure: Results[] -> Vulnerabilities[]
        for result in trivy_output.get('Results', []):
            target = result.get('Target', 'unknown')
            
            for vuln in result.get('Vulnerabilities', []):
                vulnerability = {
                    'id': vuln.get('VulnerabilityID', 'unknown'),
                    'title': vuln.get('Title', 'No title'),
                    'severity': vuln.get('Severity', 'UNKNOWN'),
                    'package_name': vuln.get('PkgName', 'unknown'),
                    'installed_version': vuln.get('InstalledVersion', 'unknown'),
                    'fixed_version': vuln.get('FixedVersion', 'Not available'),
                    'target': target,
                    'description': vuln.get('Description', ''),
                    'references': vuln.get('References', []),
                    'cvss_score': self._extract_cvss_score(vuln),
                    'tool': 'trivy'
                }
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _extract_cvss_score(self, vuln: Dict) -> float:
        """Extract CVSS score from vulnerability data"""
        cvss = vuln.get('CVSS', {})
        
        # Try different CVSS versions
        for version in ['nvd', 'redhat', 'v3']:
            if version in cvss:
                v3_metrics = cvss[version].get('V3Score')
                if v3_metrics:
                    return float(v3_metrics)
        
        return 0.0
