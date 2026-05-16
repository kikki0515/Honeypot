"""Alerting System Module.

Provides multi-channel alerting (Telegram, Discord, Email) triggered by
attack severity, threat scores, campaigns, and anomalies.
"""

from app.alerts.dispatcher import AlertDispatcher

__all__ = ['AlertDispatcher']
