"""
Email Notifier - Send email notifications
"""

import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List
from src.notifications.notifier import NotificationLevel


class EmailNotifier:
    """
    Send email notifications about security scan results
    """

    def __init__(self, config: Dict):
        """
        Initialize email notifier

        Args:
            config: Email configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)

        self.smtp_host = config.get('smtp_host', 'localhost')
        self.smtp_port = config.get('smtp_port', 587)
        self.smtp_user = config.get('smtp_user', '')
        self.smtp_password = config.get('smtp_password', '')
        self.from_email = config.get('from_email', 'security@example.com')
        self.recipients = config.get('recipients', [])
        self.use_tls = config.get('use_tls', True)

    async def send(self, message: Dict, level: NotificationLevel):
        """
        Send email notification

        Args:
            message: Message dictionary
            level: Notification level
        """
        if not self.recipients:
            self.logger.warning("No email recipients configured")
            return

        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = message.get('title', 'Security Scan Notification')
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.recipients)

            # Create plain text and HTML versions
            text_content = self._create_text_content(message)
            html_content = self._create_html_content(message)

            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))

            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()

                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)

                server.send_message(msg)

            self.logger.info(f"Email notification sent to {len(self.recipients)} recipients")

        except Exception as e:
            self.logger.error(f"Failed to send email notification: {str(e)}")
            raise

    def _create_text_content(self, message: Dict) -> str:
        """
        Create plain text email content

        Args:
            message: Message dictionary

        Returns:
            Plain text content
        """
        lines = [
            message.get('title', 'Security Scan Notification'),
            '=' * 60,
            '',
            f"Scan ID: {message.get('scan_id', 'N/A')}",
            f"Target: {message.get('target', 'N/A')}",
            f"Status: {message.get('status', 'N/A').upper()}",
            '',
            'Vulnerabilities:',
            f"  Critical: {message.get('vulnerabilities', {}).get('critical', 0)}",
            f"  High: {message.get('vulnerabilities', {}).get('high', 0)}",
            f"  Medium: {message.get('vulnerabilities', {}).get('medium', 0)}",
            f"  Low: {message.get('vulnerabilities', {}).get('low', 0)}",
            '',
            f"Policy Decision: {message.get('policy_decision', 'N/A')}",
            f"Security Score: {message.get('security_score', 0)}/100",
            '',
            '=' * 60,
            message.get('summary', '')
        ]

        return '\n'.join(lines)

    def _create_html_content(self, message: Dict) -> str:
        """
        Create HTML email content

        Args:
            message: Message dictionary

        Returns:
            HTML content
        """
        vulns = message.get('vulnerabilities', {})

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                          color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f8f9fa; padding: 20px; }}
                .severity {{ display: inline-block; padding: 5px 10px; border-radius: 4px;
                            color: white; margin: 5px; font-weight: bold; }}
                .critical {{ background: #dc3545; }}
                .high {{ background: #fd7e14; }}
                .medium {{ background: #ffc107; color: #333; }}
                .low {{ background: #17a2b8; }}
                .footer {{ background: #34495e; color: white; padding: 15px;
                          text-align: center; border-radius: 0 0 8px 8px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
                td {{ padding: 10px; border-bottom: 1px solid #dee2e6; }}
                .label {{ font-weight: bold; width: 150px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>{message.get('title', 'Security Scan Notification')}</h2>
                </div>
                <div class="content">
                    <table>
                        <tr>
                            <td class="label">Scan ID:</td>
                            <td>{message.get('scan_id', 'N/A')}</td>
                        </tr>
                        <tr>
                            <td class="label">Target:</td>
                            <td>{message.get('target', 'N/A')}</td>
                        </tr>
                        <tr>
                            <td class="label">Status:</td>
                            <td><strong>{message.get('status', 'N/A').upper()}</strong></td>
                        </tr>
                    </table>

                    <h3>Vulnerabilities Found</h3>
                    <div>
                        <span class="severity critical">Critical: {vulns.get('critical', 0)}</span>
                        <span class="severity high">High: {vulns.get('high', 0)}</span>
                        <span class="severity medium">Medium: {vulns.get('medium', 0)}</span>
                        <span class="severity low">Low: {vulns.get('low', 0)}</span>
                    </div>

                    <h3>Policy Evaluation</h3>
                    <table>
                        <tr>
                            <td class="label">Decision:</td>
                            <td><strong>{message.get('policy_decision', 'N/A').upper()}</strong></td>
                        </tr>
                        <tr>
                            <td class="label">Security Score:</td>
                            <td><strong>{message.get('security_score', 0)}/100</strong></td>
                        </tr>
                    </table>
                </div>
                <div class="footer">
                    <p>DevSecOps Pipeline Guardian</p>
                </div>
            </div>
        </body>
        </html>
        """

        return html
