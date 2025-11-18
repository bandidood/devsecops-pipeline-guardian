"""
Slack Notifier - Send Slack notifications
"""

import logging
import aiohttp
from typing import Dict
from src.notifications.notifier import NotificationLevel


class SlackNotifier:
    """
    Send Slack notifications about security scan results
    """

    def __init__(self, config: Dict):
        """
        Initialize Slack notifier

        Args:
            config: Slack configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)

        self.webhook_url = config.get('webhook_url', '')
        self.channel = config.get('channel', '#security')
        self.username = config.get('username', 'DevSecOps Guardian')
        self.icon_emoji = config.get('icon_emoji', ':shield:')

    async def send(self, message: Dict, level: NotificationLevel):
        """
        Send Slack notification

        Args:
            message: Message dictionary
            level: Notification level
        """
        if not self.webhook_url:
            self.logger.warning("Slack webhook URL not configured")
            return

        try:
            payload = self._create_slack_message(message, level)

            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise Exception(f"Slack API error: {response.status} - {error_text}")

            self.logger.info("Slack notification sent successfully")

        except Exception as e:
            self.logger.error(f"Failed to send Slack notification: {str(e)}")
            raise

    def _create_slack_message(self, message: Dict, level: NotificationLevel) -> Dict:
        """
        Create Slack message payload

        Args:
            message: Message dictionary
            level: Notification level

        Returns:
            Slack message payload
        """
        # Determine color based on level
        color_map = {
            NotificationLevel.INFO: '#36a64f',      # Green
            NotificationLevel.WARNING: '#ff9800',   # Orange
            NotificationLevel.ERROR: '#f44336',     # Red
            NotificationLevel.CRITICAL: '#9c27b0'   # Purple
        }
        color = color_map.get(level, '#808080')

        vulns = message.get('vulnerabilities', {})

        # Create attachment
        attachment = {
            'color': color,
            'title': message.get('title', 'Security Scan Notification'),
            'fields': [
                {
                    'title': 'Scan ID',
                    'value': message.get('scan_id', 'N/A'),
                    'short': True
                },
                {
                    'title': 'Target',
                    'value': message.get('target', 'N/A'),
                    'short': True
                },
                {
                    'title': 'Status',
                    'value': message.get('status', 'N/A').upper(),
                    'short': True
                },
                {
                    'title': 'Security Score',
                    'value': f"{message.get('security_score', 0)}/100",
                    'short': True
                },
                {
                    'title': 'Critical Vulnerabilities',
                    'value': str(vulns.get('critical', 0)),
                    'short': True
                },
                {
                    'title': 'High Vulnerabilities',
                    'value': str(vulns.get('high', 0)),
                    'short': True
                },
                {
                    'title': 'Medium Vulnerabilities',
                    'value': str(vulns.get('medium', 0)),
                    'short': True
                },
                {
                    'title': 'Low Vulnerabilities',
                    'value': str(vulns.get('low', 0)),
                    'short': True
                },
                {
                    'title': 'Policy Decision',
                    'value': f"*{message.get('policy_decision', 'N/A').upper()}*",
                    'short': False
                }
            ],
            'footer': 'DevSecOps Pipeline Guardian',
            'footer_icon': 'https://platform.slack-edge.com/img/default_application_icon.png'
        }

        payload = {
            'channel': self.channel,
            'username': self.username,
            'icon_emoji': self.icon_emoji,
            'attachments': [attachment]
        }

        return payload
