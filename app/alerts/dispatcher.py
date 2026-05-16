"""Alert Dispatcher - Multi-channel alerting system.

Sends alerts via Telegram, Discord webhooks, and Email
when critical attacks, campaigns, or anomalies are detected.
"""

import logging
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

from app import db, socketio
from app.models import AlertRule, AlertHistory, AttackLog

logger = logging.getLogger('honeypot.alerts')


class AlertDispatcher:
    """Dispatches alerts across multiple channels."""

    _instance = None

    def __init__(self, app=None):
        self.app = app
        self.enabled = False
        self.telegram_token = ''
        self.telegram_chat_id = ''
        self.discord_webhook = ''
        self.smtp_config = {}

        if app:
            self.configure(app)

        AlertDispatcher._instance = self

    @classmethod
    def get_instance(cls):
        return cls._instance

    def configure(self, app):
        """Configure alert dispatcher with app settings."""
        self.app = app
        self.enabled = app.config.get('ALERTING_ENABLED', True)
        self.telegram_token = app.config.get('TELEGRAM_BOT_TOKEN', '')
        self.telegram_chat_id = app.config.get('TELEGRAM_CHAT_ID', '')
        self.discord_webhook = app.config.get('DISCORD_WEBHOOK_URL', '')
        self.smtp_config = {
            'server': app.config.get('SMTP_SERVER', ''),
            'port': app.config.get('SMTP_PORT', 587),
            'username': app.config.get('SMTP_USERNAME', ''),
            'password': app.config.get('SMTP_PASSWORD', ''),
            'to': app.config.get('ALERT_EMAIL_TO', '')
        }

    def evaluate_attack(self, attack_dict, ai_result=None):
        """
        Evaluate an attack against alert rules and dispatch if triggered.

        Args:
            attack_dict: dict from AttackLog.to_dict()
            ai_result: dict from AI analyzer
        """
        if not self.enabled:
            return

        severity = attack_dict.get('severity', 'medium')
        threat_score = attack_dict.get('threat_score', 0) or (ai_result or {}).get('threat_score', 0)
        is_anomaly = attack_dict.get('is_anomaly', False) or (ai_result or {}).get('is_anomaly', False)
        campaign_id = attack_dict.get('campaign_id') or (ai_result or {}).get('campaign_id')

        # Check built-in alert conditions
        should_alert = False
        alert_reason = ''

        if severity == 'critical' and threat_score >= 7.0:
            should_alert = True
            alert_reason = f"Critical attack (score: {threat_score})"
        elif is_anomaly and threat_score >= 6.0:
            should_alert = True
            alert_reason = f"Anomaly detected (score: {threat_score})"
        elif campaign_id:
            should_alert = True
            alert_reason = f"Campaign detected: {campaign_id}"
        elif threat_score >= 8.5:
            should_alert = True
            alert_reason = f"High threat score: {threat_score}"

        if should_alert:
            self._dispatch_alert(attack_dict, alert_reason, ai_result)

    def _dispatch_alert(self, attack_dict, reason, ai_result=None):
        """Dispatch alert to all configured channels."""
        message = self._format_message(attack_dict, reason, ai_result)

        # Telegram
        if self.telegram_token and self.telegram_chat_id:
            self._send_telegram(message)

        # Discord
        if self.discord_webhook:
            self._send_discord(attack_dict, reason, ai_result)

        # Email
        if self.smtp_config.get('username') and self.smtp_config.get('to'):
            self._send_email(message, reason)

        # Always emit to dashboard
        socketio.emit('alert_triggered', {
            'reason': reason,
            'attack': attack_dict,
            'message': message,
            'timestamp': datetime.utcnow().isoformat()
        }, namespace='/')

        # Log alert history
        self._log_alert(attack_dict, reason, message)

    def _format_message(self, attack_dict, reason, ai_result=None):
        """Format alert message."""
        classification = attack_dict.get('ai_classification', 'unknown')
        if ai_result:
            classification = ai_result.get('classification', classification)

        msg = (
            f"🚨 HONEYPOT ALERT\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"⚠️ Reason: {reason}\n"
            f"🌐 Source IP: {attack_dict.get('source_ip')}\n"
            f"🎯 Service: {attack_dict.get('honeypot_type', '').upper()}\n"
            f"📋 Action: {attack_dict.get('action')}\n"
            f"🤖 AI Class: {classification}\n"
            f"📊 Threat Score: {attack_dict.get('threat_score', 0)}/10\n"
            f"🔴 Severity: {attack_dict.get('severity', 'medium').upper()}\n"
        )

        if attack_dict.get('geoip_country'):
            msg += f"🌍 Origin: {attack_dict.get('geoip_country')}\n"

        if attack_dict.get('ai_summary'):
            msg += f"📝 Summary: {attack_dict.get('ai_summary')[:200]}\n"

        msg += f"🕐 Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        return msg

    def _send_telegram(self, message):
        """Send alert via Telegram bot."""
        try:
            import requests

            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code != 200:
                logger.warning(f"Telegram alert failed: {response.status_code}")
        except ImportError:
            logger.debug("requests not available for Telegram alerts")
        except Exception as e:
            logger.error(f"Telegram alert error: {e}")

    def _send_discord(self, attack_dict, reason, ai_result=None):
        """Send alert via Discord webhook."""
        try:
            import requests

            color = {
                'critical': 0xFF0000, 'high': 0xFF8800,
                'medium': 0xFFCC00, 'low': 0x00FF00
            }.get(attack_dict.get('severity', 'medium'), 0xFFFFFF)

            embed = {
                'title': f'🚨 Honeypot Alert: {reason}',
                'color': color,
                'fields': [
                    {'name': '🌐 Source IP', 'value': attack_dict.get('source_ip', 'N/A'), 'inline': True},
                    {'name': '🎯 Service', 'value': attack_dict.get('honeypot_type', '').upper(), 'inline': True},
                    {'name': '📊 Threat Score', 'value': f"{attack_dict.get('threat_score', 0)}/10", 'inline': True},
                    {'name': '🤖 Classification', 'value': attack_dict.get('ai_classification', 'N/A'), 'inline': True},
                    {'name': '📋 Action', 'value': (attack_dict.get('action', 'N/A'))[:100], 'inline': False},
                ],
                'timestamp': datetime.utcnow().isoformat(),
                'footer': {'text': 'Honeypot-as-a-Service AI Platform'}
            }

            if attack_dict.get('ai_summary'):
                embed['fields'].append({
                    'name': '📝 AI Summary',
                    'value': attack_dict.get('ai_summary', '')[:250],
                    'inline': False
                })

            payload = {'embeds': [embed]}
            response = requests.post(self.discord_webhook, json=payload, timeout=10)
            if response.status_code not in (200, 204):
                logger.warning(f"Discord alert failed: {response.status_code}")
        except ImportError:
            logger.debug("requests not available for Discord alerts")
        except Exception as e:
            logger.error(f"Discord alert error: {e}")

    def _send_email(self, message, subject):
        """Send alert via email."""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.smtp_config['username']
            msg['To'] = self.smtp_config['to']
            msg['Subject'] = f"[HaaS Alert] {subject}"
            msg.attach(MIMEText(message, 'plain'))

            with smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port']) as server:
                server.starttls()
                server.login(self.smtp_config['username'], self.smtp_config['password'])
                server.send_message(msg)

            logger.info("Email alert sent successfully")
        except Exception as e:
            logger.error(f"Email alert error: {e}")

    def _log_alert(self, attack_dict, reason, message):
        """Log alert to database."""
        try:
            history = AlertHistory(
                triggered_at=datetime.utcnow(),
                channel='multi',
                message=message[:500],
                attack_id=attack_dict.get('id'),
                status='sent'
            )
            db.session.add(history)
            db.session.commit()
        except Exception as e:
            logger.debug(f"Failed to log alert: {e}")

    def process_alert(self, attack_id, alert_rule_id=None):
        """Process alert for a specific attack (called from Celery task)."""
        try:
            attack = AttackLog.query.get(attack_id)
            if attack:
                self.evaluate_attack(attack.to_dict())
        except Exception as e:
            logger.error(f"Alert processing failed: {e}")
