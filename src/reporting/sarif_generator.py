"""
SARIF Generator - Generates SARIF format reports
SARIF (Static Analysis Results Interchange Format) is a standard format for static analysis tools
"""

import json
import logging
from typing import Dict, List
from datetime import datetime


class SARIFGenerator:
    """
    Generates SARIF 2.1.0 compliant reports from scan results
    https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
    """

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def __init__(self):
        """Initialize SARIF generator"""
        self.logger = logging.getLogger(__name__)

    def generate(self, scan_results: Dict) -> str:
        """
        Generate SARIF report from scan results

        Args:
            scan_results: Scan results dictionary

        Returns:
            SARIF JSON string
        """
        self.logger.info("Generating SARIF report...")

        sarif_report = {
            "version": self.SARIF_VERSION,
            "$schema": self.SARIF_SCHEMA,
            "runs": []
        }

        results = scan_results.get('results', {})

        # Generate a run for each scan type
        for scan_type in ['sast', 'dast', 'dependency', 'container']:
            if scan_type in results:
                run = self._create_run(scan_type, results[scan_type], scan_results)
                sarif_report['runs'].append(run)

        return json.dumps(sarif_report, indent=2)

    def _create_run(self, scan_type: str, scan_data: Dict, full_results: Dict) -> Dict:
        """
        Create a SARIF run object for a specific scan type

        Args:
            scan_type: Type of scan (sast, dast, etc.)
            scan_data: Scan results for this type
            full_results: Full scan results for metadata

        Returns:
            SARIF run object
        """
        tool_name = self._get_tool_name(scan_type)

        run = {
            "tool": {
                "driver": {
                    "name": tool_name,
                    "informationUri": f"https://github.com/yourorg/devsecops-pipeline-guardian",
                    "version": "1.0.0",
                    "rules": []
                }
            },
            "results": [],
            "automationDetails": {
                "id": full_results.get('scan_id', 'unknown'),
                "description": {
                    "text": f"{scan_type.upper()} security scan"
                }
            },
            "invocations": [{
                "executionSuccessful": scan_data.get('error') is None,
                "startTimeUtc": full_results.get('start_time', datetime.utcnow().isoformat()),
                "endTimeUtc": full_results.get('end_time', datetime.utcnow().isoformat())
            }]
        }

        # Convert vulnerabilities to SARIF results
        vulnerabilities = scan_data.get('vulnerabilities', [])
        rules_seen = set()

        for vuln in vulnerabilities:
            # Add rule if not seen before
            rule_id = vuln.get('id', 'unknown')
            if rule_id not in rules_seen:
                rule = self._create_rule(vuln, scan_type)
                run['tool']['driver']['rules'].append(rule)
                rules_seen.add(rule_id)

            # Add result
            result = self._create_result(vuln, scan_type)
            run['results'].append(result)

        return run

    def _create_rule(self, vuln: Dict, scan_type: str) -> Dict:
        """
        Create a SARIF rule object from vulnerability

        Args:
            vuln: Vulnerability data
            scan_type: Type of scan

        Returns:
            SARIF rule object
        """
        rule_id = vuln.get('id', 'unknown')
        title = vuln.get('title', 'No title')
        description = vuln.get('description', 'No description available')

        rule = {
            "id": rule_id,
            "name": title,
            "shortDescription": {
                "text": title
            },
            "fullDescription": {
                "text": description
            },
            "defaultConfiguration": {
                "level": self._map_severity_to_level(vuln)
            },
            "properties": {
                "tags": [scan_type],
                "security-severity": str(self._get_security_severity(vuln))
            }
        }

        # Add CWE if available
        cwe = vuln.get('cwe', []) or vuln.get('cweid', '') or vuln.get('cwe_id', '')
        if cwe:
            if isinstance(cwe, list):
                cwe_ids = cwe
            else:
                cwe_ids = [str(cwe)]

            rule['properties']['cwe'] = cwe_ids

        return rule

    def _create_result(self, vuln: Dict, scan_type: str) -> Dict:
        """
        Create a SARIF result object from vulnerability

        Args:
            vuln: Vulnerability data
            scan_type: Type of scan

        Returns:
            SARIF result object
        """
        result = {
            "ruleId": vuln.get('id', 'unknown'),
            "level": self._map_severity_to_level(vuln),
            "message": {
                "text": vuln.get('title', 'No description')
            }
        }

        # Add location based on scan type
        if scan_type in ['sast']:
            # Code location
            file_path = vuln.get('file', '')
            line = vuln.get('line', 1)

            if file_path:
                result['locations'] = [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path
                        },
                        "region": {
                            "startLine": line
                        }
                    }
                }]
        elif scan_type == 'dast':
            # URL location
            url = vuln.get('url', '')
            if url:
                result['locations'] = [{
                    "logicalLocations": [{
                        "name": url,
                        "fullyQualifiedName": url
                    }]
                }]
        elif scan_type in ['dependency', 'container']:
            # Package location
            package = vuln.get('package', vuln.get('package_name', 'unknown'))
            result['locations'] = [{
                "logicalLocations": [{
                    "name": package,
                    "kind": "package"
                }]
            }]

        # Add additional properties
        result['properties'] = {}

        if 'cvss_score' in vuln:
            result['properties']['cvss_score'] = vuln['cvss_score']

        if 'fixed_version' in vuln:
            result['properties']['fixed_version'] = vuln['fixed_version']

        if 'tool' in vuln:
            result['properties']['scanner'] = vuln['tool']

        return result

    def _map_severity_to_level(self, vuln: Dict) -> str:
        """
        Map vulnerability severity to SARIF level

        Args:
            vuln: Vulnerability data

        Returns:
            SARIF level (error, warning, note, none)
        """
        severity = vuln.get('severity', vuln.get('risk', 'low')).lower()

        severity_map = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'note',
            'informational': 'note',
            'unknown': 'none'
        }

        return severity_map.get(severity, 'warning')

    def _get_security_severity(self, vuln: Dict) -> float:
        """
        Get security severity score (0.0-10.0)

        Args:
            vuln: Vulnerability data

        Returns:
            Security severity score
        """
        # If CVSS score available, use it
        if 'cvss_score' in vuln:
            return float(vuln['cvss_score'])

        # Otherwise map from severity
        severity = vuln.get('severity', vuln.get('risk', 'low')).lower()

        severity_scores = {
            'critical': 9.5,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 0.0,
            'informational': 0.0,
            'unknown': 0.0
        }

        return severity_scores.get(severity, 5.0)

    def _get_tool_name(self, scan_type: str) -> str:
        """
        Get tool name for scan type

        Args:
            scan_type: Type of scan

        Returns:
            Tool name
        """
        tool_names = {
            'sast': 'DevSecOps-SAST-Scanner',
            'dast': 'DevSecOps-DAST-Scanner',
            'dependency': 'DevSecOps-Dependency-Scanner',
            'container': 'DevSecOps-Container-Scanner'
        }

        return tool_names.get(scan_type, f'DevSecOps-{scan_type.upper()}-Scanner')
