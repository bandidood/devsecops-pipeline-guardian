"""
SAST Scanner - Static Application Security Testing
Integrates with SonarQube and Semgrep for code security analysis
"""

import asyncio
import logging
import subprocess
from typing import Dict, List, Optional
from pathlib import Path
import json


class SASTScanner:
    """
    Static Application Security Testing scanner
    Supports SonarQube and Semgrep
    """
    
    def __init__(self, config: Dict):
        """
        Initialize SAST scanner
        
        Args:
            config: Scanner configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.tools = config.get('tools', ['sonarqube', 'semgrep'])
        self.severity_threshold = config.get('severity_threshold', 'HIGH')
        
    async def scan(self, target: str, options: Optional[Dict] = None) -> Dict:
        """
        Execute SAST scan on target codebase
        
        Args:
            target: Path to source code directory
            options: Additional scan options
            
        Returns:
            Dict containing scan results
        """
        self.logger.info(f"Starting SAST scan on: {target}")
        
        results = {
            'tool': 'sast',
            'target': target,
            'vulnerabilities': [],
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        # Run configured tools
        tool_results = []
        
        if 'sonarqube' in self.tools:
            sonar_result = await self._run_sonarqube(target, options)
            tool_results.append(sonar_result)
            
        if 'semgrep' in self.tools:
            semgrep_result = await self._run_semgrep(target, options)
            tool_results.append(semgrep_result)
        
        # Aggregate results
        for tool_result in tool_results:
            if 'vulnerabilities' in tool_result:
                results['vulnerabilities'].extend(tool_result['vulnerabilities'])
                
                # Update summary
                for vuln in tool_result['vulnerabilities']:
                    severity = vuln.get('severity', 'info').lower()
                    if severity in results['summary']:
                        results['summary'][severity] += 1
        
        results['total_issues'] = len(results['vulnerabilities'])
        
        self.logger.info(f"SAST scan completed. Found {results['total_issues']} issues")
        
        return results
    
    async def _run_sonarqube(self, target: str, options: Optional[Dict] = None) -> Dict:
        """
        Run SonarQube scanner
        
        Args:
            target: Target directory
            options: Scan options
            
        Returns:
            SonarQube scan results
        """
        self.logger.info("Running SonarQube scan...")
        
        try:
            # Get SonarQube configuration
            sonar_host = self.config.get('sonar_host_url', 'http://localhost:9000')
            sonar_token = self.config.get('sonar_token', '')
            project_key = options.get('project_key', 'default-project') if options else 'default-project'
            
            # Build sonar-scanner command
            cmd = [
                'sonar-scanner',
                f'-Dsonar.projectKey={project_key}',
                f'-Dsonar.sources={target}',
                f'-Dsonar.host.url={sonar_host}',
                f'-Dsonar.login={sonar_token}',
            ]
            
            # Execute scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"SonarQube scan failed: {stderr.decode()}")
                return {'tool': 'sonarqube', 'error': stderr.decode(), 'vulnerabilities': []}
            
            # Fetch results from SonarQube API
            vulnerabilities = await self._fetch_sonarqube_issues(sonar_host, sonar_token, project_key)
            
            return {
                'tool': 'sonarqube',
                'vulnerabilities': vulnerabilities
            }
            
        except Exception as e:
            self.logger.error(f"SonarQube scan error: {str(e)}")
            return {'tool': 'sonarqube', 'error': str(e), 'vulnerabilities': []}
    
    async def _run_semgrep(self, target: str, options: Optional[Dict] = None) -> Dict:
        """
        Run Semgrep scanner
        
        Args:
            target: Target directory
            options: Scan options
            
        Returns:
            Semgrep scan results
        """
        self.logger.info("Running Semgrep scan...")
        
        try:
            # Build semgrep command
            cmd = [
                'semgrep',
                '--config=auto',
                '--json',
                target
            ]
            
            # Execute scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse JSON output
            try:
                semgrep_output = json.loads(stdout.decode())
                vulnerabilities = self._parse_semgrep_results(semgrep_output)
                
                return {
                    'tool': 'semgrep',
                    'vulnerabilities': vulnerabilities
                }
            except json.JSONDecodeError as e:
                self.logger.error(f"Failed to parse Semgrep output: {str(e)}")
                return {'tool': 'semgrep', 'error': str(e), 'vulnerabilities': []}
            
        except Exception as e:
            self.logger.error(f"Semgrep scan error: {str(e)}")
            return {'tool': 'semgrep', 'error': str(e), 'vulnerabilities': []}
    
    async def _fetch_sonarqube_issues(self, host: str, token: str, project_key: str) -> List[Dict]:
        """
        Fetch issues from SonarQube API
        
        Args:
            host: SonarQube host URL
            token: Authentication token
            project_key: Project key
            
        Returns:
            List of vulnerabilities
        """
        # TODO: Implement SonarQube API integration with aiohttp
        # For now, return empty list
        return []
    
    def _parse_semgrep_results(self, semgrep_output: Dict) -> List[Dict]:
        """
        Parse Semgrep JSON output into standardized format
        
        Args:
            semgrep_output: Raw Semgrep output
            
        Returns:
            List of standardized vulnerabilities
        """
        vulnerabilities = []
        
        for result in semgrep_output.get('results', []):
            vuln = {
                'id': result.get('check_id', 'unknown'),
                'title': result.get('extra', {}).get('message', 'No description'),
                'severity': self._map_semgrep_severity(result.get('extra', {}).get('severity', 'INFO')),
                'file': result.get('path', ''),
                'line': result.get('start', {}).get('line', 0),
                'tool': 'semgrep',
                'cwe': result.get('extra', {}).get('metadata', {}).get('cwe', []),
                'owasp': result.get('extra', {}).get('metadata', {}).get('owasp', [])
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _map_semgrep_severity(self, semgrep_severity: str) -> str:
        """Map Semgrep severity to standardized levels"""
        severity_map = {
            'ERROR': 'high',
            'WARNING': 'medium',
            'INFO': 'low'
        }
        return severity_map.get(semgrep_severity.upper(), 'info')
