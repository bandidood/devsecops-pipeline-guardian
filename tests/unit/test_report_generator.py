"""
Unit tests for ReportGenerator
"""

import pytest
import json
from pathlib import Path
from src.reporting.report_generator import ReportGenerator


@pytest.fixture
def sample_scan_results():
    """Sample scan results for testing"""
    return {
        'scan_id': 'test-scan-123',
        'scan_type': 'full',
        'target': '/test/project',
        'status': 'completed',
        'start_time': '2025-01-17T10:00:00',
        'end_time': '2025-01-17T10:05:00',
        'duration_seconds': 300,
        'results': {
            'sast': {
                'tool': 'sast',
                'summary': {'critical': 1, 'high': 3, 'medium': 5, 'low': 10, 'info': 2},
                'vulnerabilities': [
                    {
                        'id': 'SAST-001',
                        'title': 'SQL Injection vulnerability',
                        'severity': 'critical',
                        'file': 'app/db.py',
                        'line': 42,
                        'tool': 'semgrep'
                    },
                    {
                        'id': 'SAST-002',
                        'title': 'XSS vulnerability',
                        'severity': 'high',
                        'file': 'app/views.py',
                        'line': 15,
                        'tool': 'semgrep'
                    }
                ]
            },
            'dependency': {
                'tool': 'dependency',
                'summary': {'critical': 0, 'high': 2, 'medium': 8, 'low': 5},
                'vulnerabilities': [
                    {
                        'id': 'CVE-2024-1234',
                        'title': 'Vulnerable package version',
                        'severity': 'high',
                        'package': 'requests',
                        'version': '2.25.0',
                        'fixed_in': ['2.31.0'],
                        'cvss_score': 7.5,
                        'tool': 'snyk'
                    }
                ]
            }
        },
        'policy_evaluation': {
            'decision': 'deny',
            'security_score': 65,
            'violations': [
                'Critical vulnerabilities found',
                'Security score below threshold'
            ]
        }
    }


@pytest.fixture
def report_generator(tmp_path):
    """Create ReportGenerator with temporary output directory"""
    return ReportGenerator(output_dir=str(tmp_path))


class TestReportGenerator:
    """Test ReportGenerator functionality"""

    def test_initialization(self, tmp_path):
        """Test report generator initialization"""
        generator = ReportGenerator(output_dir=str(tmp_path))
        assert generator.output_dir == tmp_path
        assert tmp_path.exists()

    def test_generate_json_report(self, report_generator, sample_scan_results):
        """Test JSON report generation"""
        report = report_generator.generate(sample_scan_results, format='json')

        assert isinstance(report, str)
        parsed = json.loads(report)
        assert parsed['scan_id'] == 'test-scan-123'
        assert parsed['scan_type'] == 'full'

    def test_generate_sarif_report(self, report_generator, sample_scan_results):
        """Test SARIF report generation"""
        report = report_generator.generate(sample_scan_results, format='sarif')

        assert isinstance(report, str)
        parsed = json.loads(report)
        assert parsed['version'] == '2.1.0'
        assert '$schema' in parsed
        assert 'runs' in parsed
        assert len(parsed['runs']) > 0

    def test_generate_html_report(self, report_generator, sample_scan_results):
        """Test HTML report generation"""
        report = report_generator.generate(sample_scan_results, format='html')

        assert isinstance(report, str)
        assert '<!DOCTYPE html>' in report
        assert 'test-scan-123' in report
        assert 'Security Scan Report' in report

    def test_generate_pdf_report(self, report_generator, sample_scan_results):
        """Test PDF report generation"""
        report = report_generator.generate(sample_scan_results, format='pdf')

        assert isinstance(report, bytes)
        assert report.startswith(b'%PDF')  # PDF header

    def test_unsupported_format(self, report_generator, sample_scan_results):
        """Test error handling for unsupported format"""
        with pytest.raises(ValueError, match="Unsupported format"):
            report_generator.generate(sample_scan_results, format='invalid')

    def test_save_report(self, report_generator, sample_scan_results, tmp_path):
        """Test saving report to file"""
        report = report_generator.generate(
            sample_scan_results,
            format='json',
            save=True,
            filename='test_report.json'
        )

        report_file = tmp_path / 'test_report.json'
        assert report_file.exists()

        with open(report_file, 'r') as f:
            content = f.read()
            assert 'test-scan-123' in content

    def test_generate_summary(self, report_generator, sample_scan_results):
        """Test summary generation"""
        summary = report_generator.generate_summary(sample_scan_results)

        assert summary['scan_id'] == 'test-scan-123'
        assert summary['scan_type'] == 'full'
        assert summary['vulnerabilities']['critical'] == 1
        assert summary['vulnerabilities']['high'] == 5  # 3 from sast + 2 from dependency
        assert summary['vulnerabilities']['total'] > 0
        assert 'sast' in summary['scans_performed']
        assert 'dependency' in summary['scans_performed']
