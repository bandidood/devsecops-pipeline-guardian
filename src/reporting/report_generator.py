"""
Report Generator - Central reporting module
Generates security scan reports in multiple formats
"""

import json
import logging
from typing import Dict, Optional
from datetime import datetime
from pathlib import Path

from src.reporting.sarif_generator import SARIFGenerator
from src.reporting.html_generator import HTMLGenerator


class ReportGenerator:
    """
    Central report generator for security scan results
    Supports JSON, SARIF, HTML, and PDF formats
    """

    def __init__(self, output_dir: str = "./reports"):
        """
        Initialize report generator

        Args:
            output_dir: Directory to save generated reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

        # Initialize format-specific generators
        self.sarif_generator = SARIFGenerator()
        self.html_generator = HTMLGenerator()

    def generate(self, scan_results: Dict, format: str = 'json',
                save: bool = False, filename: Optional[str] = None) -> str:
        """
        Generate report in specified format

        Args:
            scan_results: Scan results dictionary
            format: Output format (json, sarif, html, pdf)
            save: Whether to save to file
            filename: Custom filename (optional)

        Returns:
            Generated report as string
        """
        self.logger.info(f"Generating {format.upper()} report...")

        # Generate report based on format
        if format == 'json':
            report = self._generate_json(scan_results)
        elif format == 'sarif':
            report = self.sarif_generator.generate(scan_results)
        elif format == 'html':
            report = self.html_generator.generate(scan_results)
        elif format == 'pdf':
            report = self._generate_pdf(scan_results)
        else:
            raise ValueError(f"Unsupported format: {format}")

        # Save to file if requested
        if save:
            filepath = self._save_report(report, scan_results, format, filename)
            self.logger.info(f"Report saved to: {filepath}")

        return report

    def _generate_json(self, scan_results: Dict) -> str:
        """
        Generate JSON report

        Args:
            scan_results: Scan results

        Returns:
            JSON string
        """
        return json.dumps(scan_results, indent=2, default=str)

    def _generate_pdf(self, scan_results: Dict) -> bytes:
        """
        Generate PDF report

        Args:
            scan_results: Scan results

        Returns:
            PDF content as bytes
        """
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from io import BytesIO

        # Create PDF buffer
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        story = []
        styles = getSampleStyleSheet()

        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=30
        )
        story.append(Paragraph("Security Scan Report", title_style))
        story.append(Spacer(1, 0.2*inch))

        # Scan metadata
        scan_id = scan_results.get('scan_id', 'N/A')
        scan_type = scan_results.get('scan_type', 'N/A')
        target = scan_results.get('target', 'N/A')
        status = scan_results.get('status', 'N/A')

        metadata = [
            ['Scan ID:', scan_id],
            ['Scan Type:', scan_type.upper()],
            ['Target:', target],
            ['Status:', status],
            ['Generated:', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')]
        ]

        metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        story.append(metadata_table)
        story.append(Spacer(1, 0.3*inch))

        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        story.append(Spacer(1, 0.1*inch))

        # Aggregate vulnerability counts
        results = scan_results.get('results', {})
        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0

        for scan_type in ['sast', 'dast', 'dependency', 'container']:
            if scan_type in results:
                summary = results[scan_type].get('summary', {})
                total_critical += summary.get('critical', 0)
                total_high += summary.get('high', 0)
                total_medium += summary.get('medium', 0)
                total_low += summary.get('low', 0)

        summary_data = [
            ['Severity', 'Count'],
            ['Critical', str(total_critical)],
            ['High', str(total_high)],
            ['Medium', str(total_medium)],
            ['Low', str(total_low)]
        ]

        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))

        # Policy Evaluation
        if 'policy_evaluation' in scan_results:
            policy = scan_results['policy_evaluation']
            story.append(Paragraph("Policy Evaluation", styles['Heading2']))
            story.append(Spacer(1, 0.1*inch))

            decision = policy.get('decision', 'N/A')
            security_score = policy.get('security_score', 0)

            policy_data = [
                ['Decision:', decision.upper()],
                ['Security Score:', f"{security_score}/100"]
            ]

            policy_table = Table(policy_data, colWidths=[2*inch, 3*inch])
            policy_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey)
            ]))
            story.append(policy_table)

        # Build PDF
        doc.build(story)
        pdf_content = buffer.getvalue()
        buffer.close()

        return pdf_content

    def _save_report(self, report: str, scan_results: Dict,
                    format: str, filename: Optional[str] = None) -> Path:
        """
        Save report to file

        Args:
            report: Generated report content
            scan_results: Scan results for metadata
            format: Report format
            filename: Custom filename

        Returns:
            Path to saved file
        """
        if filename is None:
            scan_id = scan_results.get('scan_id', 'unknown')
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"security_scan_{scan_id}_{timestamp}.{format}"

        filepath = self.output_dir / filename

        # Write based on format
        if format == 'pdf':
            with open(filepath, 'wb') as f:
                f.write(report)
        else:
            with open(filepath, 'w') as f:
                f.write(report)

        return filepath

    def generate_summary(self, scan_results: Dict) -> Dict:
        """
        Generate summary statistics from scan results

        Args:
            scan_results: Scan results

        Returns:
            Summary dictionary
        """
        results = scan_results.get('results', {})

        summary = {
            'scan_id': scan_results.get('scan_id'),
            'scan_type': scan_results.get('scan_type'),
            'target': scan_results.get('target'),
            'status': scan_results.get('status'),
            'duration_seconds': scan_results.get('duration_seconds', 0),
            'vulnerabilities': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'total': 0
            },
            'scans_performed': []
        }

        # Aggregate from all scan types
        for scan_type in ['sast', 'dast', 'dependency', 'container']:
            if scan_type in results:
                summary['scans_performed'].append(scan_type)
                scan_summary = results[scan_type].get('summary', {})

                for severity in ['critical', 'high', 'medium', 'low']:
                    count = scan_summary.get(severity, 0)
                    summary['vulnerabilities'][severity] += count
                    summary['vulnerabilities']['total'] += count

        return summary
