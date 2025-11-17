"""
Unit tests for security scanners
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, mock_open
from src.scanner.sast_scanner import SASTScanner
from src.scanner.container_scanner import ContainerScanner
from src.scanner.dependency_scanner import DependencyScanner
from src.scanner.dast_scanner import DASTScanner


# ========== SAST Scanner Tests ==========

@pytest.fixture
def sast_config():
    """SAST scanner configuration"""
    return {
        'tools': ['semgrep'],
        'severity_threshold': 'HIGH',
        'sonar_host_url': 'http://localhost:9000',
        'sonar_token': 'test-token'
    }


@pytest.fixture
def sast_scanner(sast_config):
    """Create SAST scanner instance"""
    return SASTScanner(sast_config)


class TestSASTScanner:
    """Test SAST Scanner functionality"""

    def test_initialization(self, sast_scanner, sast_config):
        """Test SAST scanner initialization"""
        assert sast_scanner.config == sast_config
        assert sast_scanner.tools == ['semgrep']
        assert sast_scanner.severity_threshold == 'HIGH'

    @pytest.mark.asyncio
    async def test_scan_with_semgrep(self, sast_scanner):
        """Test SAST scan with Semgrep"""
        with patch.object(sast_scanner, '_run_semgrep', new_callable=AsyncMock) as mock_semgrep:
            mock_semgrep.return_value = {
                'tool': 'semgrep',
                'vulnerabilities': [
                    {
                        'id': 'test-rule-1',
                        'title': 'Test vulnerability',
                        'severity': 'high',
                        'file': 'test.py',
                        'line': 10
                    }
                ]
            }

            result = await sast_scanner.scan('/test/path')

            assert result['tool'] == 'sast'
            assert result['total_issues'] == 1
            assert result['summary']['high'] == 1

    def test_parse_semgrep_results(self, sast_scanner):
        """Test parsing Semgrep results"""
        semgrep_output = {
            'results': [
                {
                    'check_id': 'python.lang.security.sql-injection',
                    'extra': {
                        'message': 'Potential SQL injection',
                        'severity': 'ERROR',
                        'metadata': {
                            'cwe': ['CWE-89'],
                            'owasp': ['A1']
                        }
                    },
                    'path': 'app/db.py',
                    'start': {'line': 42}
                }
            ]
        }

        vulnerabilities = sast_scanner._parse_semgrep_results(semgrep_output)

        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]['id'] == 'python.lang.security.sql-injection'
        assert vulnerabilities[0]['severity'] == 'high'
        assert vulnerabilities[0]['file'] == 'app/db.py'
        assert vulnerabilities[0]['line'] == 42

    def test_map_semgrep_severity(self, sast_scanner):
        """Test Semgrep severity mapping"""
        assert sast_scanner._map_semgrep_severity('ERROR') == 'high'
        assert sast_scanner._map_semgrep_severity('WARNING') == 'medium'
        assert sast_scanner._map_semgrep_severity('INFO') == 'low'

    def test_map_sonar_severity(self, sast_scanner):
        """Test SonarQube severity mapping"""
        assert sast_scanner._map_sonar_severity('BLOCKER') == 'critical'
        assert sast_scanner._map_sonar_severity('CRITICAL') == 'critical'
        assert sast_scanner._map_sonar_severity('MAJOR') == 'high'
        assert sast_scanner._map_sonar_severity('MINOR') == 'medium'
        assert sast_scanner._map_sonar_severity('INFO') == 'low'


# ========== Container Scanner Tests ==========

@pytest.fixture
def container_config():
    """Container scanner configuration"""
    return {
        'tools': ['trivy'],
        'severity': 'CRITICAL,HIGH',
        'ignore_unfixed': False
    }


@pytest.fixture
def container_scanner(container_config):
    """Create container scanner instance"""
    return ContainerScanner(container_config)


class TestContainerScanner:
    """Test Container Scanner functionality"""

    def test_initialization(self, container_scanner, container_config):
        """Test container scanner initialization"""
        assert container_scanner.config == container_config
        assert container_scanner.tools == ['trivy']
        assert container_scanner.severity == 'CRITICAL,HIGH'

    def test_parse_trivy_results(self, container_scanner):
        """Test parsing Trivy results"""
        trivy_output = {
            'Results': [
                {
                    'Target': 'nginx:latest (alpine 3.14.0)',
                    'Vulnerabilities': [
                        {
                            'VulnerabilityID': 'CVE-2024-1234',
                            'Title': 'Test vulnerability',
                            'Severity': 'HIGH',
                            'PkgName': 'openssl',
                            'InstalledVersion': '1.1.1',
                            'FixedVersion': '1.1.2',
                            'Description': 'Test description',
                            'References': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234'],
                            'CVSS': {
                                'nvd': {
                                    'V3Score': 7.5
                                }
                            }
                        }
                    ]
                }
            ]
        }

        vulnerabilities = container_scanner._parse_trivy_results(trivy_output)

        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]['id'] == 'CVE-2024-1234'
        assert vulnerabilities[0]['severity'] == 'HIGH'
        assert vulnerabilities[0]['package_name'] == 'openssl'
        assert vulnerabilities[0]['cvss_score'] == 7.5

    def test_extract_cvss_score(self, container_scanner):
        """Test CVSS score extraction"""
        vuln_with_nvd = {
            'CVSS': {
                'nvd': {
                    'V3Score': 8.5
                }
            }
        }

        vuln_without_cvss = {}

        assert container_scanner._extract_cvss_score(vuln_with_nvd) == 8.5
        assert container_scanner._extract_cvss_score(vuln_without_cvss) == 0.0


# ========== Dependency Scanner Tests ==========

@pytest.fixture
def dependency_config():
    """Dependency scanner configuration"""
    return {
        'tools': ['snyk'],
        'cvss_threshold': 7.0,
        'snyk_token': 'test-token'
    }


@pytest.fixture
def dependency_scanner(dependency_config):
    """Create dependency scanner instance"""
    return DependencyScanner(dependency_config)


class TestDependencyScanner:
    """Test Dependency Scanner functionality"""

    def test_initialization(self, dependency_scanner, dependency_config):
        """Test dependency scanner initialization"""
        assert dependency_scanner.config == dependency_config
        assert dependency_scanner.cvss_threshold == 7.0

    def test_parse_snyk_results(self, dependency_scanner):
        """Test parsing Snyk results"""
        snyk_output = {
            'vulnerabilities': [
                {
                    'id': 'SNYK-PY-REQUESTS-1234',
                    'title': 'Insecure requests library',
                    'severity': 'high',
                    'cvssScore': 7.5,
                    'packageName': 'requests',
                    'version': '2.25.0',
                    'fixedIn': ['2.31.0'],
                    'identifiers': {
                        'CVE': ['CVE-2024-1234'],
                        'CWE': ['CWE-20']
                    },
                    'description': 'Test vulnerability description'
                }
            ]
        }

        vulnerabilities = dependency_scanner._parse_snyk_results(snyk_output)

        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]['id'] == 'SNYK-PY-REQUESTS-1234'
        assert vulnerabilities[0]['severity'] == 'high'
        assert vulnerabilities[0]['package'] == 'requests'
        assert vulnerabilities[0]['cvss_score'] == 7.5

    def test_map_threshold_to_snyk(self, dependency_scanner):
        """Test threshold mapping to Snyk severity"""
        dependency_scanner.cvss_threshold = 9.0
        assert dependency_scanner._map_threshold_to_snyk() == 'critical'

        dependency_scanner.cvss_threshold = 7.0
        assert dependency_scanner._map_threshold_to_snyk() == 'high'

        dependency_scanner.cvss_threshold = 4.0
        assert dependency_scanner._map_threshold_to_snyk() == 'medium'

        dependency_scanner.cvss_threshold = 2.0
        assert dependency_scanner._map_threshold_to_snyk() == 'low'


# ========== DAST Scanner Tests ==========

@pytest.fixture
def dast_config():
    """DAST scanner configuration"""
    return {
        'zap_host': 'http://localhost:8090',
        'zap_api_key': 'test-key'
    }


@pytest.fixture
def dast_scanner(dast_config):
    """Create DAST scanner instance"""
    return DASTScanner(dast_config)


class TestDASTScanner:
    """Test DAST Scanner functionality"""

    def test_initialization(self, dast_scanner, dast_config):
        """Test DAST scanner initialization"""
        assert dast_scanner.config == dast_config
        assert dast_scanner.zap_host == 'http://localhost:8090'

    def test_parse_zap_results(self, dast_scanner):
        """Test parsing ZAP results"""
        zap_output = {
            'site': [
                {
                    'alerts': [
                        {
                            'pluginid': '40012',
                            'name': 'Cross Site Scripting (Reflected)',
                            'riskdesc': 'High (Medium)',
                            'confidence': 'High',
                            'url': 'http://example.com/page',
                            'desc': 'XSS vulnerability detected',
                            'solution': 'Encode user input',
                            'reference': 'https://owasp.org/xss',
                            'cweid': '79',
                            'wascid': '8'
                        }
                    ]
                }
            ]
        }

        vulnerabilities = dast_scanner._parse_zap_results(zap_output)

        assert len(vulnerabilities) == 1
        assert vulnerabilities[0]['id'] == '40012'
        assert vulnerabilities[0]['title'] == 'Cross Site Scripting (Reflected)'
        assert vulnerabilities[0]['risk'] == 'high'
        assert vulnerabilities[0]['url'] == 'http://example.com/page'
        assert vulnerabilities[0]['cwe_id'] == '79'
