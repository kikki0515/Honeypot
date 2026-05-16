"""Database models for the Honeypot-as-a-Service platform.

Extended with AI analysis fields, GeoIP data, threat intelligence,
distributed agent support, and campaign tracking.
"""

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
    role = db.Column(db.String(20), default='analyst')  # admin, analyst, viewer
    api_key = db.Column(db.String(64), unique=True)
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class AttackLog(db.Model):
    """Model to store detected attack events with AI analysis."""
    __tablename__ = 'attack_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    source_port = db.Column(db.Integer)
    honeypot_type = db.Column(db.String(20), nullable=False)  # ssh, http, ftp
    protocol = db.Column(db.String(10))
    action = db.Column(db.String(100))  # e.g., "login_attempt", "file_access"
    details = db.Column(db.Text)  # JSON string with additional details
    username_attempted = db.Column(db.String(100))
    password_attempted = db.Column(db.String(100))
    severity = db.Column(db.String(10), default='medium')  # low, medium, high, critical

    # --- AI Analysis Fields ---
    ai_classification = db.Column(db.String(50))  # brute_force, sql_injection, etc.
    ai_confidence = db.Column(db.Float)  # 0.0 - 1.0
    ai_summary = db.Column(db.Text)  # Human-readable AI summary
    threat_score = db.Column(db.Float)  # 0.0 - 10.0
    threat_risk_level = db.Column(db.String(10))  # low, medium, high, critical

    # --- GeoIP Fields ---
    geoip_country = db.Column(db.String(100))
    geoip_country_code = db.Column(db.String(5))
    geoip_city = db.Column(db.String(100))
    geoip_latitude = db.Column(db.Float)
    geoip_longitude = db.Column(db.Float)
    geoip_asn = db.Column(db.String(20))
    geoip_isp = db.Column(db.String(200))

    # --- Threat Intelligence Fields ---
    reputation_score = db.Column(db.Float)  # 0-100 from external sources
    reputation_source = db.Column(db.String(50))  # abuseipdb, virustotal
    is_known_malicious = db.Column(db.Boolean, default=False)

    # --- Attacker Profiling ---
    attacker_fingerprint = db.Column(db.String(32))  # Behavioral fingerprint hash
    campaign_id = db.Column(db.String(20), index=True)  # Campaign grouping

    # --- Anomaly Detection ---
    is_anomaly = db.Column(db.Boolean, default=False)
    anomaly_score = db.Column(db.Float)

    # --- Distributed Agent ---
    agent_id = db.Column(db.String(64), index=True)  # Which agent reported this
    node_name = db.Column(db.String(100))

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'honeypot_type': self.honeypot_type,
            'protocol': self.protocol,
            'action': self.action,
            'details': self.details,
            'username_attempted': self.username_attempted,
            'password_attempted': self.password_attempted,
            'severity': self.severity,
            # AI fields
            'ai_classification': self.ai_classification,
            'ai_confidence': self.ai_confidence,
            'ai_summary': self.ai_summary,
            'threat_score': self.threat_score,
            'threat_risk_level': self.threat_risk_level,
            # GeoIP
            'geoip_country': self.geoip_country,
            'geoip_country_code': self.geoip_country_code,
            'geoip_city': self.geoip_city,
            'geoip_latitude': self.geoip_latitude,
            'geoip_longitude': self.geoip_longitude,
            'geoip_asn': self.geoip_asn,
            'geoip_isp': self.geoip_isp,
            # Threat Intel
            'reputation_score': self.reputation_score,
            'is_known_malicious': self.is_known_malicious,
            # Profiling
            'attacker_fingerprint': self.attacker_fingerprint,
            'campaign_id': self.campaign_id,
            'is_anomaly': self.is_anomaly,
            'anomaly_score': self.anomaly_score,
            # Agent
            'agent_id': self.agent_id,
            'node_name': self.node_name
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


class ThreatIntelFeed(db.Model):
    """Cached threat intelligence data for IP addresses."""
    __tablename__ = 'threat_intel_feeds'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    abuse_confidence = db.Column(db.Integer)  # AbuseIPDB confidence 0-100
    total_reports = db.Column(db.Integer, default=0)
    is_tor_exit = db.Column(db.Boolean, default=False)
    is_vpn = db.Column(db.Boolean, default=False)
    is_proxy = db.Column(db.Boolean, default=False)
    is_bot = db.Column(db.Boolean, default=False)
    threat_categories = db.Column(db.Text)  # JSON list of categories
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)
    data_source = db.Column(db.String(50))  # abuseipdb, virustotal, etc.
    raw_response = db.Column(db.Text)  # Full JSON response cached

    def to_dict(self):
        return {
            'ip_address': self.ip_address,
            'abuse_confidence': self.abuse_confidence,
            'total_reports': self.total_reports,
            'is_tor_exit': self.is_tor_exit,
            'is_vpn': self.is_vpn,
            'is_proxy': self.is_proxy,
            'is_bot': self.is_bot,
            'threat_categories': self.threat_categories,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_checked': self.last_checked.isoformat() if self.last_checked else None,
            'data_source': self.data_source
        }


class Campaign(db.Model):
    """Detected attack campaigns (coordinated attacks)."""
    __tablename__ = 'campaigns'

    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.String(20), unique=True, nullable=False, index=True)
    name = db.Column(db.String(200))
    description = db.Column(db.Text)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    source_ips = db.Column(db.Text)  # JSON list of IPs
    protocols_targeted = db.Column(db.String(100))
    total_attacks = db.Column(db.Integer, default=0)
    severity = db.Column(db.String(10), default='medium')
    status = db.Column(db.String(20), default='active')  # active, resolved, monitoring

    def to_dict(self):
        return {
            'id': self.id,
            'campaign_id': self.campaign_id,
            'name': self.name,
            'description': self.description,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'source_ips': self.source_ips,
            'protocols_targeted': self.protocols_targeted,
            'total_attacks': self.total_attacks,
            'severity': self.severity,
            'status': self.status
        }


class HoneypotAgent(db.Model):
    """Distributed honeypot agent registration."""
    __tablename__ = 'honeypot_agents'

    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    hostname = db.Column(db.String(200))
    ip_address = db.Column(db.String(45))
    location = db.Column(db.String(200))
    status = db.Column(db.String(20), default='offline')  # online, offline, error
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_heartbeat = db.Column(db.DateTime)
    services_running = db.Column(db.Text)  # JSON list of active services
    total_attacks_reported = db.Column(db.Integer, default=0)
    version = db.Column(db.String(20))
    api_key = db.Column(db.String(128))

    def to_dict(self):
        return {
            'id': self.id,
            'agent_id': self.agent_id,
            'name': self.name,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'location': self.location,
            'status': self.status,
            'registered_at': self.registered_at.isoformat() if self.registered_at else None,
            'last_heartbeat': self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            'services_running': self.services_running,
            'total_attacks_reported': self.total_attacks_reported,
            'version': self.version
        }


class AlertRule(db.Model):
    """Alert rules for triggering notifications."""
    __tablename__ = 'alert_rules'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    trigger_type = db.Column(db.String(50))  # severity, score, campaign, anomaly, frequency
    trigger_condition = db.Column(db.Text)  # JSON conditions
    channels = db.Column(db.Text)  # JSON: ["telegram", "discord", "email"]
    cooldown_minutes = db.Column(db.Integer, default=5)
    last_triggered = db.Column(db.DateTime)
    times_triggered = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'is_active': self.is_active,
            'trigger_type': self.trigger_type,
            'trigger_condition': self.trigger_condition,
            'channels': self.channels,
            'cooldown_minutes': self.cooldown_minutes,
            'last_triggered': self.last_triggered.isoformat() if self.last_triggered else None,
            'times_triggered': self.times_triggered,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class AlertHistory(db.Model):
    """History of triggered alerts."""
    __tablename__ = 'alert_history'

    id = db.Column(db.Integer, primary_key=True)
    alert_rule_id = db.Column(db.Integer, db.ForeignKey('alert_rules.id'))
    triggered_at = db.Column(db.DateTime, default=datetime.utcnow)
    channel = db.Column(db.String(50))
    message = db.Column(db.Text)
    attack_id = db.Column(db.Integer, db.ForeignKey('attack_logs.id'))
    status = db.Column(db.String(20), default='sent')  # sent, failed, acknowledged

    def to_dict(self):
        return {
            'id': self.id,
            'alert_rule_id': self.alert_rule_id,
            'triggered_at': self.triggered_at.isoformat() if self.triggered_at else None,
            'channel': self.channel,
            'message': self.message,
            'attack_id': self.attack_id,
            'status': self.status
        }
