"""
Unit tests for SecurityOrchestrator
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from src.orchestrator.security_orchestrator import SecurityOrchestrator, ScanType, ScanStatus


@pytest.fixture
def config():
    """Test configuration"""
    return {
        'sast': {'tools': ['semgrep']},
        'dast': {'tools': ['zap']},
        'dependency': {'tools': ['snyk']},
        'container': {'tools': ['trivy']},
        'policy': {'enabled': True}
    }


@pytest.fixture
def orchestrator(config):
    """Create orchestrator instance"""
    return SecurityOrchestrator(config)


class TestSecurityOrchestrator:
    """Test SecurityOrchestrator functionality"""
    
    def test_initialization(self, orchestrator, config):
        """Test orchestrator initialization"""
        assert orchestrator.config == config
        assert orchestrator.sast_scanner is not None
        assert orchestrator.dast_scanner is not None
        assert orchestrator.dependency_scanner is not None
        assert orchestrator.container_scanner is not None
        assert orchestrator.policy_evaluator is not None
    
    def test_generate_scan_id(self, orchestrator):
        """Test scan ID generation"""
        scan_id = orchestrator._generate_scan_id()
        assert isinstance(scan_id, str)
        assert len(scan_id) == 36  # UUID format
    
    @pytest.mark.asyncio
    async def test_run_sast_scan(self, orchestrator):
        """Test SAST scan execution"""
        with patch.object(orchestrator.sast_scanner, 'scan', new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = {
                'tool': 'sast',
                'vulnerabilities': [],
                'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            }
            
            with patch.object(orchestrator.policy_evaluator, 'evaluate', new_callable=AsyncMock) as mock_policy:
                mock_policy.return_value = {'decision': 'allow', 'security_score': 100}
                
                result = await orchestrator.run_scan(ScanType.SAST, '/test/path')
                
                assert result['scan_type'] == 'sast'
                assert result['status'] == 'completed'
                assert 'scan_id' in result
                assert 'policy_evaluation' in result
                mock_scan.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_run_full_scan(self, orchestrator):
        """Test full scan execution"""
        with patch.object(orchestrator.sast_scanner, 'scan', new_callable=AsyncMock) as mock_sast:
            with patch.object(orchestrator.dependency_scanner, 'scan', new_callable=AsyncMock) as mock_dep:
                mock_sast.return_value = {'tool': 'sast', 'vulnerabilities': []}
                mock_dep.return_value = {'tool': 'dependency', 'vulnerabilities': []}
                
                with patch.object(orchestrator.policy_evaluator, 'evaluate', new_callable=AsyncMock):
                    result = await orchestrator.run_scan(ScanType.FULL, '/test/path')
                    
                    assert result['scan_type'] == 'full'
                    assert 'sast' in result['results']
                    assert 'dependency' in result['results']
                    mock_sast.assert_called_once()
                    mock_dep.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_run_scan_with_error(self, orchestrator):
        """Test scan error handling"""
        with patch.object(orchestrator.sast_scanner, 'scan', new_callable=AsyncMock) as mock_scan:
            mock_scan.side_effect = Exception("Scanner error")
            
            with pytest.raises(Exception):
                await orchestrator.run_scan(ScanType.SAST, '/test/path')
    
    def test_get_scan_status(self, orchestrator):
        """Test retrieving scan status"""
        scan_id = 'test-scan-id'
        orchestrator.scan_status[scan_id] = ScanStatus.RUNNING
        
        status = orchestrator.get_scan_status(scan_id)
        assert status == ScanStatus.RUNNING
    
    def test_get_scan_results(self, orchestrator):
        """Test retrieving scan results"""
        scan_id = 'test-scan-id'
        expected_results = {'scan_id': scan_id, 'status': 'completed'}
        orchestrator.scan_results[scan_id] = expected_results
        
        results = orchestrator.get_scan_results(scan_id)
        assert results == expected_results
    
    def test_list_scans(self, orchestrator):
        """Test listing all scans"""
        orchestrator.scan_status['scan-1'] = ScanStatus.COMPLETED
        orchestrator.scan_status['scan-2'] = ScanStatus.RUNNING
        orchestrator.scan_results['scan-1'] = {'data': 'test1'}
        orchestrator.scan_results['scan-2'] = {'data': 'test2'}
        
        scans = orchestrator.list_scans()
        assert len(scans) == 2
        assert scans[0]['scan_id'] == 'scan-1'
        assert scans[0]['status'] == 'completed'
    
    def test_export_results_json(self, orchestrator):
        """Test exporting results as JSON"""
        scan_id = 'test-scan-id'
        orchestrator.scan_results[scan_id] = {'test': 'data'}
        
        exported = orchestrator.export_results(scan_id, 'json')
        assert isinstance(exported, str)
        assert 'test' in exported
    
    def test_export_results_invalid_format(self, orchestrator):
        """Test export with invalid format"""
        scan_id = 'test-scan-id'
        orchestrator.scan_results[scan_id] = {'test': 'data'}
        
        with pytest.raises(ValueError):
            orchestrator.export_results(scan_id, 'invalid')
    
    def test_export_results_scan_not_found(self, orchestrator):
        """Test export with non-existent scan"""
        with pytest.raises(ValueError):
            orchestrator.export_results('non-existent-scan', 'json')
