"""Database models for the Honeypot-as-a-Service platform."""

from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from app import db, login_manager


class User(UserMixin, db.Model):
    """User model for authentication."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class AttackLog(db.Model):
    """Model to store detected attack events."""
    __tablename__ = 'attack_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), nullable=False)
    source_port = db.Column(db.Integer)
    honeypot_type = db.Column(db.String(20), nullable=False)  # ssh, http, ftp
    protocol = db.Column(db.String(10))
    action = db.Column(db.String(100))  # e.g., "login_attempt", "file_access"
    details = db.Column(db.Text)  # JSON string with additional details
    username_attempted = db.Column(db.String(100))
    password_attempted = db.Column(db.String(100))
    severity = db.Column(db.String(10), default='medium')  # low, medium, high, critical

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'honeypot_type': self.honeypot_type,
            'protocol': self.protocol,
            'action': self.action,
            'details': self.details,
            'username_attempted': self.username_attempted,
            'password_attempted': self.password_attempted,
            'severity': self.severity
        }


class HoneypotService(db.Model):
    """Model to track honeypot service status."""
    __tablename__ = 'honeypot_services'

    id = db.Column(db.Integer, primary_key=True)
    service_type = db.Column(db.String(20), unique=True, nullable=False)
    port = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='stopped')  # running, stopped, error
    started_at = db.Column(db.DateTime)
    total_connections = db.Column(db.Integer, default=0)
    last_activity = db.Column(db.DateTime)

    def to_dict(self):
        return {
            'id': self.id,
            'service_type': self.service_type,
            'port': self.port,
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'total_connections': self.total_connections,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None
        }
