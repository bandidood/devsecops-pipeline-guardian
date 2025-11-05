"""
Unit tests for PolicyEvaluator
"""

import pytest
from unittest.mock import patch, AsyncMock
from src.policies.policy_evaluator import PolicyEvaluator


@pytest.fixture
def config():
    """Test configuration"""
    return {
        'opa_url': 'http://localhost:8181',
        'policy_package': 'devsecops.security',
        'enabled': True
    }


@pytest.fixture
def evaluator(config):
    """Create evaluator instance"""
    return PolicyEvaluator(config)


@pytest.fixture
def scan_data():
    """Sample scan data"""
    return {
        'scan_id': 'test-scan-123',
        'scan_type': 'full',
        'target': '/test/project',
        'results': {
            'sast': {
                'summary': {'critical': 0, 'high': 2, 'medium': 5, 'low': 10}
            },
            'dependency': {
                'summary': {'critical': 1, 'high': 3, 'medium': 8, 'low': 15}
            }
        }
    }


class TestPolicyEvaluator:
    """Test PolicyEvaluator functionality"""
    
    def test_initialization(self, evaluator, config):
        """Test evaluator initialization"""
        assert evaluator.config == config
        assert evaluator.opa_url == config['opa_url']
        assert evaluator.policy_package == config['policy_package']
        assert evaluator.enabled == True
    
    def test_calculate_security_score(self, evaluator):
        """Test security score calculation"""
        vulnerabilities = {
            'critical': 1,
            'high': 2,
            'medium': 3,
            'low': 5
        }
        
        # Score = 100 - (1*25 + 2*10 + 3*5 + 5*1) = 100 - 65 = 35
        score = evaluator.calculate_security_score(vulnerabilities)
        assert score == 35
    
    def test_calculate_security_score_no_vulns(self, evaluator):
        """Test security score with no vulnerabilities"""
        vulnerabilities = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        score = evaluator.calculate_security_score(vulnerabilities)
        assert score == 100
    
    def test_calculate_security_score_minimum(self, evaluator):
        """Test security score doesn't go below 0"""
        vulnerabilities = {
            'critical': 10,
            'high': 20,
            'medium': 30,
            'low': 50
        }
        
        score = evaluator.calculate_security_score(vulnerabilities)
        assert score == 0
    
    def test_prepare_opa_input(self, evaluator, scan_data):
        """Test OPA input preparation"""
        opa_input = evaluator._prepare_opa_input(scan_data)
        
        assert opa_input['scan_id'] == 'test-scan-123'
        assert opa_input['scan_type'] == 'full'
        assert opa_input['target'] == '/test/project'
        assert 'vulnerabilities' in opa_input
        assert opa_input['vulnerabilities']['critical'] == 1
        assert opa_input['vulnerabilities']['high'] == 5  # 2 + 3
        assert opa_input['vulnerabilities']['medium'] == 13  # 5 + 8
        assert opa_input['vulnerabilities']['low'] == 25  # 10 + 15
    
    @pytest.mark.asyncio
    async def test_evaluate_disabled(self, config, scan_data):
        """Test evaluation when disabled"""
        config['enabled'] = False
        evaluator = PolicyEvaluator(config)
        
        result = await evaluator.evaluate(scan_data)
        
        assert result['enabled'] == False
        assert result['decision'] == 'allow'
        assert 'message' in result
    
    @pytest.mark.asyncio
    async def test_evaluate_allow(self, evaluator, scan_data):
        """Test evaluation that allows deployment"""
        with patch.object(evaluator, '_query_opa', new_callable=AsyncMock) as mock_query:
            # Mock OPA responses
            async def query_side_effect(input_data, query):
                if query == 'allow':
                    return True
                elif query == 'violations':
                    return []
                elif query == 'security_score':
                    return 85
                return None
            
            mock_query.side_effect = query_side_effect
            
            result = await evaluator.evaluate(scan_data)
            
            assert result['enabled'] == True
            assert result['decision'] == 'allow'
            assert result['security_score'] == 85
            assert result['violations'] == []
    
    @pytest.mark.asyncio
    async def test_evaluate_deny(self, evaluator, scan_data):
        """Test evaluation that denies deployment"""
        with patch.object(evaluator, '_query_opa', new_callable=AsyncMock) as mock_query:
            # Mock OPA responses
            async def query_side_effect(input_data, query):
                if query == 'allow':
                    return False
                elif query == 'violations':
                    return ['Critical vulnerabilities detected']
                elif query == 'security_score':
                    return 35
                return None
            
            mock_query.side_effect = query_side_effect
            
            result = await evaluator.evaluate(scan_data)
            
            assert result['enabled'] == True
            assert result['decision'] == 'deny'
            assert result['security_score'] == 35
            assert len(result['violations']) == 1
    
    @pytest.mark.asyncio
    async def test_evaluate_error_handling(self, evaluator, scan_data):
        """Test error handling during evaluation"""
        with patch.object(evaluator, '_query_opa', new_callable=AsyncMock) as mock_query:
            mock_query.side_effect = Exception("OPA connection failed")
            
            result = await evaluator.evaluate(scan_data)
            
            assert result['decision'] == 'deny'
            assert 'error' in result
    
    def test_generate_summary_allow(self, evaluator):
        """Test summary generation for allowed deployment"""
        result = {
            'decision': 'allow',
            'security_score': 90,
            'violations': []
        }
        
        summary = evaluator._generate_summary(result)
        
        assert summary['decision'] == 'allow'
        assert summary['security_score'] == 90
        assert summary['total_violations'] == 0
        assert 'approved' in summary['message'].lower()
    
    def test_generate_summary_deny(self, evaluator):
        """Test summary generation for denied deployment"""
        result = {
            'decision': 'deny',
            'security_score': 40,
            'violations': ['Violation 1', 'Violation 2']
        }
        
        summary = evaluator._generate_summary(result)
        
        assert summary['decision'] == 'deny'
        assert summary['security_score'] == 40
        assert summary['total_violations'] == 2
        assert 'blocked' in summary['message'].lower()
