"""
Policy Evaluator - OPA-based security policy evaluation
Evaluates scan results against security policies and determines deployment decisions
"""

import asyncio
import logging
import json
from typing import Dict, List, Optional
import aiohttp


class PolicyEvaluator:
    """
    Evaluates security scan results against OPA policies
    Implements security gates for deployment decisions
    """
    
    def __init__(self, config: Dict):
        """
        Initialize policy evaluator
        
        Args:
            config: Policy configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.opa_url = config.get('opa_url', 'http://localhost:8181')
        self.policy_package = config.get('policy_package', 'devsecops.security')
        self.enabled = config.get('enabled', True)
        
    async def evaluate(self, scan_data: Dict) -> Dict:
        """
        Evaluate scan results against security policies
        
        Args:
            scan_data: Complete scan results
            
        Returns:
            Policy evaluation results with decision
        """
        if not self.enabled:
            self.logger.info("Policy evaluation disabled")
            return {
                'enabled': False,
                'decision': 'allow',
                'message': 'Policy evaluation is disabled'
            }
        
        self.logger.info("Evaluating scan results against security policies...")
        
        try:
            # Prepare input for OPA
            opa_input = self._prepare_opa_input(scan_data)
            
            # Query OPA for decision
            decision_result = await self._query_opa(opa_input, 'allow')
            violations = await self._query_opa(opa_input, 'violations')
            security_score = await self._query_opa(opa_input, 'security_score')
            
            result = {
                'enabled': True,
                'decision': 'allow' if decision_result else 'deny',
                'violations': violations if violations else [],
                'security_score': security_score if security_score is not None else 0,
                'evaluation_time': self._get_timestamp()
            }
            
            # Add summary
            result['summary'] = self._generate_summary(result)
            
            self.logger.info(f"Policy evaluation completed: {result['decision']}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Policy evaluation error: {str(e)}")
            return {
                'enabled': True,
                'decision': 'deny',
                'error': str(e),
                'message': 'Policy evaluation failed - defaulting to deny'
            }
    
    async def _query_opa(self, input_data: Dict, query: str) -> any:
        """
        Query OPA for policy decision
        
        Args:
            input_data: Input data for OPA
            query: Query path (e.g., 'allow', 'violations')
            
        Returns:
            OPA query result
        """
        url = f"{self.opa_url}/v1/data/{self.policy_package}/{query}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json={'input': input_data}) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result.get('result')
                    else:
                        error_text = await response.text()
                        self.logger.error(f"OPA query failed: {error_text}")
                        return None
                        
        except aiohttp.ClientError as e:
            self.logger.error(f"OPA connection error: {str(e)}")
            raise
    
    def _prepare_opa_input(self, scan_data: Dict) -> Dict:
        """
        Prepare scan data for OPA evaluation
        
        Args:
            scan_data: Raw scan results
            
        Returns:
            Formatted input for OPA
        """
        results = scan_data.get('results', {})
        
        # Extract vulnerability summaries
        vulnerabilities = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        # Aggregate from different scan types
        for scan_type in ['sast', 'dast', 'dependency', 'container']:
            if scan_type in results:
                summary = results[scan_type].get('summary', {})
                for severity in vulnerabilities.keys():
                    vulnerabilities[severity] += summary.get(severity, 0)
        
        # Prepare OPA input
        opa_input = {
            'scan_id': scan_data.get('scan_id'),
            'scan_type': scan_data.get('scan_type'),
            'target': scan_data.get('target'),
            'vulnerabilities': vulnerabilities,
            'results': results
        }
        
        return opa_input
    
    def _generate_summary(self, result: Dict) -> Dict:
        """
        Generate human-readable summary of policy evaluation
        
        Args:
            result: Policy evaluation result
            
        Returns:
            Summary dict
        """
        summary = {
            'decision': result['decision'],
            'security_score': result.get('security_score', 0),
            'total_violations': len(result.get('violations', []))
        }
        
        if result['decision'] == 'deny':
            summary['message'] = 'Deployment blocked due to security policy violations'
        else:
            summary['message'] = 'Deployment approved - all security checks passed'
        
        return summary
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.utcnow().isoformat()
    
    def calculate_security_score(self, vulnerabilities: Dict) -> int:
        """
        Calculate security score based on vulnerabilities
        
        Formula: 100 - (CRITICAL × 25 + HIGH × 10 + MEDIUM × 5 + LOW × 1)
        
        Args:
            vulnerabilities: Dict with counts by severity
            
        Returns:
            Security score (0-100)
        """
        score = 100
        score -= vulnerabilities.get('critical', 0) * 25
        score -= vulnerabilities.get('high', 0) * 10
        score -= vulnerabilities.get('medium', 0) * 5
        score -= vulnerabilities.get('low', 0) * 1
        
        return max(0, score)  # Ensure score doesn't go below 0
