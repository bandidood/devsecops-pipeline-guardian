"""
Security Orchestrator
Coordinates and manages all security scanning operations
"""

import asyncio
import logging
from typing import Dict, List, Optional
from datetime import datetime
from enum import Enum
import json

from src.scanner.sast_scanner import SASTScanner
from src.scanner.dast_scanner import DASTScanner
from src.scanner.dependency_scanner import DependencyScanner
from src.scanner.container_scanner import ContainerScanner
from src.policies.policy_evaluator import PolicyEvaluator


class ScanType(Enum):
    """Available scan types"""
    SAST = "sast"
    DAST = "dast"
    DEPENDENCY = "dependency"
    CONTAINER = "container"
    FULL = "full"


class ScanStatus(Enum):
    """Scan execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SecurityOrchestrator:
    """
    Orchestrates security scanning operations across multiple tools
    Implements Shift-Left Security principles
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the security orchestrator
        
        Args:
            config: Configuration dictionary with scan settings
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize scanners
        self.sast_scanner = SASTScanner(config.get('sast', {}))
        self.dast_scanner = DASTScanner(config.get('dast', {}))
        self.dependency_scanner = DependencyScanner(config.get('dependency', {}))
        self.container_scanner = ContainerScanner(config.get('container', {}))
        
        # Initialize policy evaluator
        self.policy_evaluator = PolicyEvaluator(config.get('policy', {}))
        
        # Scan state
        self.scan_results = {}
        self.scan_status = {}
        
    async def run_scan(self, scan_type: ScanType, target: str, 
                      options: Optional[Dict] = None) -> Dict:
        """
        Execute a security scan
        
        Args:
            scan_type: Type of scan to execute
            target: Target to scan (path, URL, image, etc.)
            options: Additional scan options
            
        Returns:
            Dict containing scan results
        """
        scan_id = self._generate_scan_id()
        self.logger.info(f"Starting {scan_type.value} scan with ID: {scan_id}")
        
        self.scan_status[scan_id] = ScanStatus.RUNNING
        start_time = datetime.utcnow()
        
        try:
            if scan_type == ScanType.FULL:
                results = await self._run_full_scan(target, options)
            elif scan_type == ScanType.SAST:
                results = await self.sast_scanner.scan(target, options)
            elif scan_type == ScanType.DAST:
                results = await self.dast_scanner.scan(target, options)
            elif scan_type == ScanType.DEPENDENCY:
                results = await self.dependency_scanner.scan(target, options)
            elif scan_type == ScanType.CONTAINER:
                results = await self.container_scanner.scan(target, options)
            else:
                raise ValueError(f"Unknown scan type: {scan_type}")
            
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            
            # Store results
            self.scan_results[scan_id] = {
                'scan_id': scan_id,
                'scan_type': scan_type.value,
                'target': target,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'status': ScanStatus.COMPLETED.value,
                'results': results
            }
            
            self.scan_status[scan_id] = ScanStatus.COMPLETED
            self.logger.info(f"Scan {scan_id} completed in {duration:.2f}s")
            
            # Evaluate against policies
            policy_result = await self._evaluate_policies(scan_id)
            self.scan_results[scan_id]['policy_evaluation'] = policy_result
            
            return self.scan_results[scan_id]
            
        except Exception as e:
            self.logger.error(f"Scan {scan_id} failed: {str(e)}")
            self.scan_status[scan_id] = ScanStatus.FAILED
            
            self.scan_results[scan_id] = {
                'scan_id': scan_id,
                'scan_type': scan_type.value,
                'target': target,
                'start_time': start_time.isoformat(),
                'status': ScanStatus.FAILED.value,
                'error': str(e)
            }
            
            raise
    
    async def _run_full_scan(self, target: str, options: Optional[Dict] = None) -> Dict:
        """
        Run all security scans in parallel
        
        Args:
            target: Target to scan
            options: Scan options
            
        Returns:
            Aggregated results from all scans
        """
        self.logger.info("Running full security scan suite")
        
        # Run scans in parallel
        tasks = [
            self.sast_scanner.scan(target, options),
            self.dependency_scanner.scan(target, options),
        ]
        
        # Add optional scans based on target type
        if options and options.get('include_dast'):
            tasks.append(self.dast_scanner.scan(target, options))
        
        if options and options.get('include_container'):
            tasks.append(self.container_scanner.scan(target, options))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate results
        aggregated = {
            'sast': results[0] if not isinstance(results[0], Exception) else {'error': str(results[0])},
            'dependency': results[1] if not isinstance(results[1], Exception) else {'error': str(results[1])},
        }
        
        idx = 2
        if options and options.get('include_dast'):
            aggregated['dast'] = results[idx] if not isinstance(results[idx], Exception) else {'error': str(results[idx])}
            idx += 1
        
        if options and options.get('include_container'):
            aggregated['container'] = results[idx] if not isinstance(results[idx], Exception) else {'error': str(results[idx])}
        
        return aggregated
    
    async def _evaluate_policies(self, scan_id: str) -> Dict:
        """
        Evaluate scan results against security policies
        
        Args:
            scan_id: ID of the scan to evaluate
            
        Returns:
            Policy evaluation results
        """
        if scan_id not in self.scan_results:
            raise ValueError(f"Scan {scan_id} not found")
        
        scan_data = self.scan_results[scan_id]
        return await self.policy_evaluator.evaluate(scan_data)
    
    def get_scan_status(self, scan_id: str) -> Optional[ScanStatus]:
        """Get the status of a scan"""
        return self.scan_status.get(scan_id)
    
    def get_scan_results(self, scan_id: str) -> Optional[Dict]:
        """Get the results of a scan"""
        return self.scan_results.get(scan_id)
    
    def list_scans(self) -> List[Dict]:
        """List all scans"""
        return [
            {
                'scan_id': scan_id,
                'status': status.value,
                'details': self.scan_results.get(scan_id, {})
            }
            for scan_id, status in self.scan_status.items()
        ]
    
    def export_results(self, scan_id: str, format: str = 'json') -> str:
        """
        Export scan results in specified format
        
        Args:
            scan_id: ID of the scan
            format: Export format (json, sarif, html)
            
        Returns:
            Formatted scan results
        """
        if scan_id not in self.scan_results:
            raise ValueError(f"Scan {scan_id} not found")
        
        results = self.scan_results[scan_id]
        
        if format == 'json':
            return json.dumps(results, indent=2)
        elif format == 'sarif':
            return self._convert_to_sarif(results)
        elif format == 'html':
            return self._generate_html_report(results)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_scan_id(self) -> str:
        """Generate a unique scan ID"""
        import uuid
        return str(uuid.uuid4())
    
    def _convert_to_sarif(self, results: Dict) -> str:
        """Convert results to SARIF format"""
        # TODO: Implement SARIF conversion
        pass
    
    def _generate_html_report(self, results: Dict) -> str:
        """Generate HTML report"""
        # TODO: Implement HTML report generation
        pass
