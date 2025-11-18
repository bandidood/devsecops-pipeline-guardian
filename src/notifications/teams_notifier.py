"""
Microsoft Teams Notifier - Send Teams notifications
"""

import logging
import aiohttp
from typing import Dict
from src.notifications.notifier import NotificationLevel


class TeamsNotifier:
    """
    Send Microsoft Teams notifications about security scan results
    """

    def __init__(self, config: Dict):
        """
        Initialize Teams notifier

        Args:
            config: Teams configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)

        self.webhook_url = config.get('webhook_url', '')

    async def send(self, message: Dict, level: NotificationLevel):
        """
        Send Teams notification

        Args:
            message: Message dictionary
            level: Notification level
        """
        if not self.webhook_url:
            self.logger.warning("Teams webhook URL not configured")
            return

        try:
            payload = self._create_teams_message(message, level)

            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise Exception(f"Teams API error: {response.status} - {error_text}")

            self.logger.info("Teams notification sent successfully")

        except Exception as e:
            self.logger.error(f"Failed to send Teams notification: {str(e)}")
            raise

    def _create_teams_message(self, message: Dict, level: NotificationLevel) -> Dict:
        """
        Create Teams Adaptive Card message

        Args:
            message: Message dictionary
            level: Notification level

        Returns:
            Teams message payload
        """
        # Determine theme color based on level
        color_map = {
            NotificationLevel.INFO: '00FF00',      # Green
            NotificationLevel.WARNING: 'FFA500',   # Orange
            NotificationLevel.ERROR: 'FF0000',     # Red
            NotificationLevel.CRITICAL: '8B008B'   # Purple
        }
        theme_color = color_map.get(level, '808080')

        vulns = message.get('vulnerabilities', {})

        # Create Adaptive Card
        payload = {
            '@type': 'MessageCard',
            '@context': 'https://schema.org/extensions',
            'summary': message.get('title', 'Security Scan Notification'),
            'themeColor': theme_color,
            'title': message.get('title', 'Security Scan Notification'),
            'sections': [
                {
                    'activityTitle': 'Scan Details',
                    'facts': [
                        {
                            'name': 'Scan ID:',
                            'value': message.get('scan_id', 'N/A')
                        },
                        {
                            'name': 'Target:',
                            'value': message.get('target', 'N/A')
                        },
                        {
                            'name': 'Status:',
                            'value': message.get('status', 'N/A').upper()
                        },
                        {
                            'name': 'Security Score:',
                            'value': f"{message.get('security_score', 0)}/100"
                        }
                    ]
                },
                {
                    'activityTitle': 'Vulnerabilities',
                    'facts': [
                        {
                            'name': '🔴 Critical:',
                            'value': str(vulns.get('critical', 0))
                        },
                        {
                            'name': '🟠 High:',
                            'value': str(vulns.get('high', 0))
                        },
                        {
                            'name': '🟡 Medium:',
                            'value': str(vulns.get('medium', 0))
                        },
                        {
                            'name': '🟢 Low:',
                            'value': str(vulns.get('low', 0))
                        }
                    ]
                },
                {
                    'activityTitle': 'Policy Evaluation',
                    'facts': [
                        {
                            'name': 'Decision:',
                            'value': message.get('policy_decision', 'N/A').upper()
                        }
                    ]
                }
            ]
        }

        return payload
