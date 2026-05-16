"""Configuration settings for Honeypot-as-a-Service platform."""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'honeypot-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', f'sqlite:///{os.path.join(BASE_DIR, "honeypot.db")}')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Honeypot service ports
    SSH_HONEYPOT_PORT = int(os.environ.get('SSH_HONEYPOT_PORT', 2222))
    HTTP_HONEYPOT_PORT = int(os.environ.get('HTTP_HONEYPOT_PORT', 8080))
    FTP_HONEYPOT_PORT = int(os.environ.get('FTP_HONEYPOT_PORT', 2121))

    # Web dashboard port
    WEB_PORT = int(os.environ.get('WEB_PORT', 5000))

    # Logging
    LOG_DIR = os.path.join(BASE_DIR, 'logs')
    LOG_FILE = os.path.join(LOG_DIR, 'honeypot.log')


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
