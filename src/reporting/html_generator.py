"""
HTML Generator - Generates HTML format reports
Creates comprehensive, styled HTML reports for security scans
"""

import logging
from typing import Dict, List
from datetime import datetime
from jinja2 import Template


class HTMLGenerator:
    """
    Generates HTML reports from scan results with styling and interactivity
    """

    def __init__(self):
        """Initialize HTML generator"""
        self.logger = logging.getLogger(__name__)

    def generate(self, scan_results: Dict) -> str:
        """
        Generate HTML report from scan results

        Args:
            scan_results: Scan results dictionary

        Returns:
            HTML string
        """
        self.logger.info("Generating HTML report...")

        template = self._get_template()
        context = self._prepare_context(scan_results)

        html = template.render(**context)
        return html

    def _prepare_context(self, scan_results: Dict) -> Dict:
        """
        Prepare template context from scan results

        Args:
            scan_results: Scan results

        Returns:
            Template context dictionary
        """
        results = scan_results.get('results', {})

        # Aggregate vulnerability counts
        total_vulns = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'total': 0
        }

        scan_details = []

        for scan_type in ['sast', 'dast', 'dependency', 'container']:
            if scan_type in results:
                scan_data = results[scan_type]
                summary = scan_data.get('summary', {})

                detail = {
                    'type': scan_type.upper(),
                    'type_lower': scan_type,
                    'vulnerabilities': scan_data.get('vulnerabilities', []),
                    'summary': summary,
                    'total': sum(summary.values()) if summary else 0
                }
                scan_details.append(detail)

                # Aggregate totals
                for severity in ['critical', 'high', 'medium', 'low']:
                    count = summary.get(severity, 0)
                    total_vulns[severity] += count
                    total_vulns['total'] += count

        context = {
            'scan_id': scan_results.get('scan_id', 'N/A'),
            'scan_type': scan_results.get('scan_type', 'N/A').upper(),
            'target': scan_results.get('target', 'N/A'),
            'status': scan_results.get('status', 'N/A'),
            'start_time': scan_results.get('start_time', 'N/A'),
            'end_time': scan_results.get('end_time', 'N/A'),
            'duration': scan_results.get('duration_seconds', 0),
            'generated_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'total_vulnerabilities': total_vulns,
            'scan_details': scan_details,
            'policy_evaluation': scan_results.get('policy_evaluation', {}),
            'has_policy': 'policy_evaluation' in scan_results
        }

        return context

    def _get_template(self) -> Template:
        """
        Get Jinja2 template for HTML report

        Returns:
            Jinja2 Template object
        """
        template_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {{ scan_id }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f6fa;
            color: #2c3e50;
            line-height: 1.6;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }

        .metadata {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background-color: #f8f9fa;
            border-bottom: 1px solid #e1e8ed;
        }

        .metadata-item {
            background: white;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #667eea;
        }

        .metadata-item label {
            display: block;
            font-size: 0.85em;
            color: #7f8c8d;
            text-transform: uppercase;
            margin-bottom: 5px;
            font-weight: 600;
        }

        .metadata-item .value {
            font-size: 1.1em;
            color: #2c3e50;
            font-weight: 500;
        }

        .summary {
            padding: 30px;
        }

        .summary h2 {
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #2c3e50;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }

        .severity-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .severity-card {
            padding: 20px;
            border-radius: 8px;
            color: white;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }

        .severity-card:hover {
            transform: translateY(-5px);
        }

        .severity-card.critical {
            background: linear-gradient(135deg, #e74c3c, #c0392b);
        }

        .severity-card.high {
            background: linear-gradient(135deg, #e67e22, #d35400);
        }

        .severity-card.medium {
            background: linear-gradient(135deg, #f39c12, #e67e22);
        }

        .severity-card.low {
            background: linear-gradient(135deg, #3498db, #2980b9);
        }

        .severity-card .count {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }

        .severity-card .label {
            font-size: 1.1em;
            text-transform: uppercase;
            opacity: 0.9;
        }

        .policy-evaluation {
            margin: 30px;
            padding: 25px;
            background-color: #f8f9fa;
            border-radius: 8px;
            border-left: 5px solid #27ae60;
        }

        .policy-evaluation.denied {
            border-left-color: #e74c3c;
            background-color: #fee;
        }

        .policy-evaluation h3 {
            font-size: 1.5em;
            margin-bottom: 15px;
            color: #2c3e50;
        }

        .policy-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }

        .policy-info-item {
            padding: 10px;
            background: white;
            border-radius: 4px;
        }

        .scan-section {
            margin: 30px;
        }

        .scan-section h2 {
            font-size: 1.6em;
            margin-bottom: 20px;
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }

        .scan-type-header {
            background: linear-gradient(135deg, #3498db, #2980b9);
            color: white;
            padding: 15px 20px;
            border-radius: 6px 6px 0 0;
            font-size: 1.3em;
            font-weight: 600;
        }

        .vulnerabilities-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        .vulnerabilities-table thead {
            background-color: #34495e;
            color: white;
        }

        .vulnerabilities-table th {
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }

        .vulnerabilities-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #ecf0f1;
        }

        .vulnerabilities-table tbody tr:hover {
            background-color: #f8f9fa;
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }

        .severity-badge.critical { background-color: #e74c3c; }
        .severity-badge.high { background-color: #e67e22; }
        .severity-badge.medium { background-color: #f39c12; }
        .severity-badge.low { background-color: #3498db; }
        .severity-badge.info { background-color: #95a5a6; }
        .severity-badge.informational { background-color: #95a5a6; }

        .footer {
            background-color: #34495e;
            color: white;
            text-align: center;
            padding: 20px;
            margin-top: 40px;
        }

        .no-vulnerabilities {
            text-align: center;
            padding: 40px;
            color: #27ae60;
            font-size: 1.2em;
        }

        .vuln-description {
            font-size: 0.9em;
            color: #7f8c8d;
            max-width: 500px;
        }

        @media print {
            body {
                background-color: white;
            }
            .severity-card:hover {
                transform: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Scan Report</h1>
            <div class="subtitle">DevSecOps Pipeline Guardian</div>
        </div>

        <div class="metadata">
            <div class="metadata-item">
                <label>Scan ID</label>
                <div class="value">{{ scan_id }}</div>
            </div>
            <div class="metadata-item">
                <label>Scan Type</label>
                <div class="value">{{ scan_type }}</div>
            </div>
            <div class="metadata-item">
                <label>Target</label>
                <div class="value">{{ target }}</div>
            </div>
            <div class="metadata-item">
                <label>Status</label>
                <div class="value">{{ status }}</div>
            </div>
            <div class="metadata-item">
                <label>Duration</label>
                <div class="value">{{ "%.2f"|format(duration) }} seconds</div>
            </div>
            <div class="metadata-item">
                <label>Generated</label>
                <div class="value">{{ generated_at }}</div>
            </div>
        </div>

        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="severity-grid">
                <div class="severity-card critical">
                    <div class="count">{{ total_vulnerabilities.critical }}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="severity-card high">
                    <div class="count">{{ total_vulnerabilities.high }}</div>
                    <div class="label">High</div>
                </div>
                <div class="severity-card medium">
                    <div class="count">{{ total_vulnerabilities.medium }}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="severity-card low">
                    <div class="count">{{ total_vulnerabilities.low }}</div>
                    <div class="label">Low</div>
                </div>
            </div>
        </div>

        {% if has_policy %}
        <div class="policy-evaluation {{ 'denied' if policy_evaluation.decision == 'deny' else '' }}">
            <h3>Policy Evaluation</h3>
            <div class="policy-info">
                <div class="policy-info-item">
                    <strong>Decision:</strong> {{ policy_evaluation.decision|upper }}
                </div>
                <div class="policy-info-item">
                    <strong>Security Score:</strong> {{ policy_evaluation.security_score }}/100
                </div>
                {% if policy_evaluation.violations %}
                <div class="policy-info-item">
                    <strong>Violations:</strong> {{ policy_evaluation.violations|length }}
                </div>
                {% endif %}
            </div>
        </div>
        {% endif %}

        {% for scan in scan_details %}
        <div class="scan-section">
            <div class="scan-type-header">
                {{ scan.type }} Scan Results ({{ scan.total }} findings)
            </div>

            {% if scan.vulnerabilities %}
            <table class="vulnerabilities-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {% for vuln in scan.vulnerabilities %}
                    <tr>
                        <td><code>{{ vuln.id }}</code></td>
                        <td>{{ vuln.title }}</td>
                        <td>
                            <span class="severity-badge {{ (vuln.severity or vuln.risk or 'low')|lower }}">
                                {{ vuln.severity or vuln.risk or 'N/A' }}
                            </span>
                        </td>
                        <td>
                            <div class="vuln-description">
                                {% if scan.type_lower == 'sast' %}
                                    File: {{ vuln.file or 'N/A' }} (Line {{ vuln.line or 'N/A' }})
                                {% elif scan.type_lower == 'dast' %}
                                    URL: {{ vuln.url or 'N/A' }}
                                {% elif scan.type_lower == 'dependency' %}
                                    Package: {{ vuln.package or 'N/A' }}
                                    {% if vuln.fixed_in %}
                                    <br>Fixed in: {{ vuln.fixed_in }}
                                    {% endif %}
                                {% elif scan.type_lower == 'container' %}
                                    Package: {{ vuln.package_name or 'N/A' }}
                                    <br>Installed: {{ vuln.installed_version or 'N/A' }}
                                    {% if vuln.fixed_version %}
                                    <br>Fixed: {{ vuln.fixed_version }}
                                    {% endif %}
                                {% endif %}
                            </div>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="no-vulnerabilities">
                ✓ No vulnerabilities found in {{ scan.type }} scan
            </div>
            {% endif %}
        </div>
        {% endfor %}

        <div class="footer">
            <p>Generated by DevSecOps Pipeline Guardian | {{ generated_at }}</p>
        </div>
    </div>
</body>
</html>
        """

        return Template(template_html)
