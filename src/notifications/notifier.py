"""
Notification Manager - Central notification orchestration
"""

import logging
from typing import Dict, List, Optional
from enum import Enum

from src.notifications.email_notifier import EmailNotifier
from src.notifications.slack_notifier import SlackNotifier
from src.notifications.teams_notifier import TeamsNotifier


class NotificationLevel(Enum):
    """Notification severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class NotificationManager:
    """
    Manages notifications across multiple channels
    Supports Email, Slack, and Microsoft Teams
    """

    def __init__(self, config: Dict):
        """
        Initialize notification manager

        Args:
            config: Notification configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.enabled = config.get('enabled', True)

        # Initialize notifiers based on configuration
        self.notifiers = []

        if self.enabled:
            channels = config.get('channels', [])

            if 'email' in channels:
                email_config = config.get('email', {})
                if email_config:
                    self.notifiers.append(EmailNotifier(email_config))

            if 'slack' in channels:
                slack_config = config.get('slack', {})
                if slack_config:
                    self.notifiers.append(SlackNotifier(slack_config))

            if 'teams' in channels:
                teams_config = config.get('teams', {})
                if teams_config:
                    self.notifiers.append(TeamsNotifier(teams_config))

        self.logger.info(f"Notification Manager initialized with {len(self.notifiers)} notifiers")

    async def notify_scan_complete(self, scan_results: Dict) -> bool:
        """
        Send notification about completed scan

        Args:
            scan_results: Scan results dictionary

        Returns:
            True if all notifications sent successfully
        """
        if not self.enabled:
            self.logger.debug("Notifications disabled")
            return True

        # Determine notification level based on results
        level = self._determine_notification_level(scan_results)

        # Check if we should notify based on configuration
        if not self._should_notify(level, scan_results):
            self.logger.debug(f"Skipping notification for level {level.value}")
            return True

        # Prepare notification message
        message = self._prepare_message(scan_results, level)

        # Send notifications to all channels
        success = True
        for notifier in self.notifiers:
            try:
                await notifier.send(message, level)
                self.logger.info(f"Notification sent via {notifier.__class__.__name__}")
            except Exception as e:
                self.logger.error(f"Failed to send notification via {notifier.__class__.__name__}: {str(e)}")
                success = False

        return success

    async def notify_scan_failed(self, scan_id: str, error: str) -> bool:
        """
        Send notification about failed scan

        Args:
            scan_id: Scan ID
            error: Error message

        Returns:
            True if notifications sent successfully
        """
        if not self.enabled:
            return True

        message = {
            'title': '🔴 Security Scan Failed',
            'scan_id': scan_id,
            'status': 'failed',
            'error': error,
            'summary': f"Scan {scan_id} failed with error: {error}"
        }

        success = True
        for notifier in self.notifiers:
            try:
                await notifier.send(message, NotificationLevel.ERROR)
            except Exception as e:
                self.logger.error(f"Failed to send failure notification: {str(e)}")
                success = False

        return success

    def _determine_notification_level(self, scan_results: Dict) -> NotificationLevel:
        """
        Determine notification level based on scan results

        Args:
            scan_results: Scan results

        Returns:
            Notification level
        """
        # Check policy evaluation
        policy_eval = scan_results.get('policy_evaluation', {})
        if policy_eval.get('decision') == 'deny':
            return NotificationLevel.CRITICAL

        # Check vulnerability counts
        results = scan_results.get('results', {})
        total_critical = 0
        total_high = 0

        for scan_type in ['sast', 'dast', 'dependency', 'container']:
            if scan_type in results:
                summary = results[scan_type].get('summary', {})
                total_critical += summary.get('critical', 0)
                total_high += summary.get('high', 0)

        if total_critical > 0:
            return NotificationLevel.CRITICAL
        elif total_high > 5:
            return NotificationLevel.ERROR
        elif total_high > 0:
            return NotificationLevel.WARNING
        else:
            return NotificationLevel.INFO

    def _should_notify(self, level: NotificationLevel, scan_results: Dict) -> bool:
        """
        Check if notification should be sent based on configuration

        Args:
            level: Notification level
            scan_results: Scan results

        Returns:
            True if notification should be sent
        """
        # Check configuration settings
        on_failure = self.config.get('on_failure', True)
        on_success = self.config.get('on_success', False)

        status = scan_results.get('status', 'unknown')

        # Always notify on failures
        if level in [NotificationLevel.ERROR, NotificationLevel.CRITICAL]:
            return on_failure

        # Notify on success only if configured
        if status == 'completed' and level == NotificationLevel.INFO:
            return on_success

        # Notify on warnings based on configuration
        if level == NotificationLevel.WARNING:
            return on_failure  # Treat warnings as potential failures

        return True

    def _prepare_message(self, scan_results: Dict, level: NotificationLevel) -> Dict:
        """
        Prepare notification message

        Args:
            scan_results: Scan results
            level: Notification level

        Returns:
            Message dictionary
        """
        scan_id = scan_results.get('scan_id', 'unknown')
        scan_type = scan_results.get('scan_type', 'unknown')
        target = scan_results.get('target', 'unknown')
        status = scan_results.get('status', 'unknown')

        # Aggregate vulnerability counts
        results = scan_results.get('results', {})
        total_vulns = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

        for scan_type_key in ['sast', 'dast', 'dependency', 'container']:
            if scan_type_key in results:
                summary = results[scan_type_key].get('summary', {})
                for severity in total_vulns.keys():
                    total_vulns[severity] += summary.get(severity, 0)

        # Get policy evaluation
        policy_eval = scan_results.get('policy_evaluation', {})
        decision = policy_eval.get('decision', 'N/A')
        security_score = policy_eval.get('security_score', 0)

        # Prepare title with emoji
        title_emojis = {
            NotificationLevel.INFO: '✅',
            NotificationLevel.WARNING: '⚠️',
            NotificationLevel.ERROR: '🔴',
            NotificationLevel.CRITICAL: '🚨'
        }
        emoji = title_emojis.get(level, '📊')

        title = f"{emoji} Security Scan {status.capitalize()}"

        message = {
            'title': title,
            'level': level.value,
            'scan_id': scan_id,
            'scan_type': scan_type,
            'target': target,
            'status': status,
            'vulnerabilities': total_vulns,
            'policy_decision': decision,
            'security_score': security_score,
            'summary': self._generate_summary_text(scan_results, total_vulns)
        }

        return message

    def _generate_summary_text(self, scan_results: Dict, total_vulns: Dict) -> str:
        """
        Generate human-readable summary text

        Args:
            scan_results: Scan results
            total_vulns: Total vulnerability counts

        Returns:
            Summary text
        """
        scan_id = scan_results.get('scan_id', 'unknown')
        target = scan_results.get('target', 'unknown')

        summary_parts = [
            f"Scan {scan_id} completed for target: {target}",
            f"Vulnerabilities found: {total_vulns['critical']} Critical, {total_vulns['high']} High, "
            f"{total_vulns['medium']} Medium, {total_vulns['low']} Low"
        ]

        policy_eval = scan_results.get('policy_evaluation', {})
        if policy_eval:
            decision = policy_eval.get('decision', 'N/A')
            score = policy_eval.get('security_score', 0)
            summary_parts.append(f"Policy Decision: {decision.upper()} (Security Score: {score}/100)")

        return "\n".join(summary_parts)
