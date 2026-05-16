"""Base honeypot class with common functionality."""

import logging
import threading
from datetime import datetime

from app import db, socketio
from app.models import AttackLog, HoneypotService


class BaseHoneypot:
    """Base class for all honeypot services."""

    def __init__(self, service_type, port, app=None):
        self.service_type = service_type
        self.port = port
        self.app = app
        self._running = False
        self._thread = None
        self.server_socket = None
        self.logger = logging.getLogger(f'honeypot.{service_type}')

    def log_attack(self, source_ip, action, details=None, source_port=None,
                   username_attempted=None, password_attempted=None, severity='medium'):
        """Log an attack event to the database and emit via WebSocket."""
        if not self.app:
            return

        with self.app.app_context():
            try:
                attack = AttackLog(
                    source_ip=source_ip,
                    source_port=source_port,
                    honeypot_type=self.service_type,
                    protocol=self.service_type.upper(),
                    action=action,
                    details=details,
                    username_attempted=username_attempted,
                    password_attempted=password_attempted,
                    severity=severity
                )
                db.session.add(attack)
                db.session.commit()

                # Emit real-time event via WebSocket
                socketio.emit('new_attack', attack.to_dict(), namespace='/')

                self.logger.info(
                    f"[{self.service_type.upper()}] {action} from {source_ip} "
                    f"(severity: {severity})"
                )
            except Exception as e:
                self.logger.error(f"Failed to log attack: {e}")
                db.session.rollback()

    def update_status(self, status):
        """Update the service status in the database."""
        if not self.app:
            return

        with self.app.app_context():
            try:
                service = HoneypotService.query.filter_by(
                    service_type=self.service_type
                ).first()

                if not service:
                    service = HoneypotService(
                        service_type=self.service_type,
                        port=self.port,
                        status=status
                    )
                    db.session.add(service)
                else:
                    service.status = status
                    if status == 'running':
                        service.started_at = datetime.utcnow()

                db.session.commit()

                # Emit status update via WebSocket
                socketio.emit('service_status', {
                    'service_type': self.service_type,
                    'status': status,
                    'port': self.port
                }, namespace='/')

            except Exception as e:
                self.logger.error(f"Failed to update status: {e}")
                db.session.rollback()

    def increment_connections(self):
        """Increment the total connection count."""
        if not self.app:
            return

        with self.app.app_context():
            try:
                service = HoneypotService.query.filter_by(
                    service_type=self.service_type
                ).first()
                if service:
                    service.total_connections += 1
                    service.last_activity = datetime.utcnow()
                    db.session.commit()
            except Exception as e:
                self.logger.error(f"Failed to increment connections: {e}")
                db.session.rollback()

    def start(self):
        """Start the honeypot service. Override in subclass."""
        raise NotImplementedError

    def stop(self):
        """Stop the honeypot service."""
        self._running = False
        self.update_status('stopped')
        self.logger.info(f"{self.service_type.upper()} Honeypot stopped")

    def start_threaded(self):
        """Start the honeypot in a separate thread."""
        self._thread = threading.Thread(target=self.start, daemon=True)
        self._thread.start()
        return self._thread

    @property
    def is_running(self):
        return self._running
