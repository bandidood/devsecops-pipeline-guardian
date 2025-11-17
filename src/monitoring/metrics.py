"""
Metrics Collector - Prometheus metrics for security scans
"""

from prometheus_client import Counter, Histogram, Gauge, Info, CollectorRegistry, generate_latest
from prometheus_client import CONTENT_TYPE_LATEST
import time
from typing import Dict


class MetricsCollector:
    """
    Collects and exposes Prometheus metrics for security scanning operations
    """

    def __init__(self, registry=None):
        """
        Initialize metrics collector

        Args:
            registry: Optional Prometheus registry (creates default if not provided)
        """
        self.registry = registry or CollectorRegistry()

        # Scan metrics
        self.scans_total = Counter(
            'devsecops_scans_total',
            'Total number of security scans performed',
            ['scan_type', 'status'],
            registry=self.registry
        )

        self.scan_duration_seconds = Histogram(
            'devsecops_scan_duration_seconds',
            'Duration of security scans in seconds',
            ['scan_type'],
            buckets=(1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600),
            registry=self.registry
        )

        # Vulnerability metrics
        self.vulnerabilities_found = Counter(
            'devsecops_vulnerabilities_found_total',
            'Total vulnerabilities found by severity',
            ['scan_type', 'severity'],
            registry=self.registry
        )

        self.active_scans = Gauge(
            'devsecops_active_scans',
            'Number of currently running scans',
            registry=self.registry
        )

        # Policy metrics
        self.policy_evaluations_total = Counter(
            'devsecops_policy_evaluations_total',
            'Total number of policy evaluations',
            ['decision'],
            registry=self.registry
        )

        self.security_score = Gauge(
            'devsecops_security_score',
            'Latest security score (0-100)',
            ['scan_id'],
            registry=self.registry
        )

        # Scanner-specific metrics
        self.scanner_errors = Counter(
            'devsecops_scanner_errors_total',
            'Total scanner errors',
            ['scanner', 'error_type'],
            registry=self.registry
        )

        # Platform info
        self.platform_info = Info(
            'devsecops_platform',
            'Platform information',
            registry=self.registry
        )
        self.platform_info.info({
            'version': '1.0.0',
            'platform': 'DevSecOps Pipeline Guardian'
        })

    def record_scan_start(self, scan_type: str):
        """
        Record scan start

        Args:
            scan_type: Type of scan
        """
        self.active_scans.inc()

    def record_scan_complete(self, scan_type: str, duration: float, status: str,
                           vulnerabilities: Dict = None):
        """
        Record scan completion

        Args:
            scan_type: Type of scan
            duration: Scan duration in seconds
            status: Scan status (completed, failed)
            vulnerabilities: Vulnerability counts by severity
        """
        self.active_scans.dec()
        self.scans_total.labels(scan_type=scan_type, status=status).inc()
        self.scan_duration_seconds.labels(scan_type=scan_type).observe(duration)

        if vulnerabilities:
            for severity, count in vulnerabilities.items():
                if count > 0:
                    self.vulnerabilities_found.labels(
                        scan_type=scan_type,
                        severity=severity
                    ).inc(count)

    def record_policy_evaluation(self, decision: str, security_score: int, scan_id: str):
        """
        Record policy evaluation

        Args:
            decision: Policy decision (allow, deny)
            security_score: Security score (0-100)
            scan_id: Scan ID
        """
        self.policy_evaluations_total.labels(decision=decision).inc()
        self.security_score.labels(scan_id=scan_id).set(security_score)

    def record_scanner_error(self, scanner: str, error_type: str):
        """
        Record scanner error

        Args:
            scanner: Scanner name
            error_type: Type of error
        """
        self.scanner_errors.labels(scanner=scanner, error_type=error_type).inc()

    def get_metrics(self) -> bytes:
        """
        Get metrics in Prometheus format

        Returns:
            Metrics as bytes
        """
        return generate_latest(self.registry)

    def get_content_type(self) -> str:
        """
        Get content type for metrics

        Returns:
            Content type string
        """
        return CONTENT_TYPE_LATEST


# Global metrics instance
_metrics_collector = None


def get_metrics_collector() -> MetricsCollector:
    """
    Get global metrics collector instance

    Returns:
        MetricsCollector instance
    """
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector
