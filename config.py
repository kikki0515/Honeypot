"""Configuration settings for Honeypot-as-a-Service platform.

All ports and settings are configurable via environment variables.
Uses python-dotenv for .env file support.
"""

import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def _validate_port(value, default, name='port'):
    """Validate port number from environment."""
    try:
        port = int(value) if value else default
        if not (1 <= port <= 65535):
            raise ValueError(f"Port {port} out of range")
        return port
    except (ValueError, TypeError):
        return default


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', '')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', f'sqlite:///{os.path.join(BASE_DIR, "honeypot.db")}')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Honeypot service ports (all configurable via .env)
    SSH_HONEYPOT_PORT = _validate_port(os.environ.get('SSH_HONEYPOT_PORT'), 2222, 'SSH')
    HTTP_HONEYPOT_PORT = _validate_port(os.environ.get('HTTP_HONEYPOT_PORT'), 8080, 'HTTP')
    FTP_HONEYPOT_PORT = _validate_port(os.environ.get('FTP_HONEYPOT_PORT'), 2121, 'FTP')
    WEB_PORT = _validate_port(os.environ.get('WEB_PORT'), 5000, 'WEB')

    # Logging
    LOG_DIR = os.path.join(BASE_DIR, 'logs')
    LOG_FILE = os.path.join(LOG_DIR, 'honeypot.log')

    # Redis
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

    # Celery
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/1')
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2')

    # AI Configuration
    AI_ENABLED = os.environ.get('AI_ENABLED', 'true').lower() == 'true'
    AI_ANOMALY_SENSITIVITY = float(os.environ.get('AI_ANOMALY_SENSITIVITY', '2.0'))
    AI_MIN_CONFIDENCE = float(os.environ.get('AI_MIN_CONFIDENCE', '0.3'))

    # GeoIP
    GEOIP_ENABLED = os.environ.get('GEOIP_ENABLED', 'true').lower() == 'true'
    GEOIP_DB_PATH = os.environ.get('GEOIP_DB_PATH', os.path.join(BASE_DIR, 'data', 'GeoLite2-City.mmdb'))

    # Threat Intelligence
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    THREAT_INTEL_ENABLED = os.environ.get('THREAT_INTEL_ENABLED', 'true').lower() == 'true'
    THREAT_INTEL_CACHE_HOURS = int(os.environ.get('THREAT_INTEL_CACHE_HOURS', '24'))

    # Alerting
    ALERTING_ENABLED = os.environ.get('ALERTING_ENABLED', 'true').lower() == 'true'
    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
    TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
    DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL', '')
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
    ALERT_EMAIL_TO = os.environ.get('ALERT_EMAIL_TO', '')

    # Distributed Agents
    AGENT_MODE = os.environ.get('AGENT_MODE', 'standalone')
    CENTRAL_SERVER_URL = os.environ.get('CENTRAL_SERVER_URL', '')
    AGENT_API_KEY = os.environ.get('AGENT_API_KEY', '')
    AGENT_HEARTBEAT_INTERVAL = int(os.environ.get('AGENT_HEARTBEAT_INTERVAL', '30'))

    # Security
    RATE_LIMIT_ENABLED = os.environ.get('RATE_LIMIT_ENABLED', 'true').lower() == 'true'
    RATE_LIMIT_DEFAULT = os.environ.get('RATE_LIMIT_DEFAULT', '200/hour')
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    WTF_CSRF_ENABLED = os.environ.get('WTF_CSRF_ENABLED', 'true').lower() == 'true'


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    RATE_LIMIT_ENABLED = False


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    WTF_CSRF_ENABLED = True


class DockerConfig(Config):
    """Docker deployment configuration."""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'postgresql://honeypot:honeypot@postgres:5432/honeypot'
    )
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://redis:6379/1')
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://redis:6379/2')


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'docker': DockerConfig,
    'default': DevelopmentConfig
}
