"""Main entry point for the AI-Powered Honeypot-as-a-Service platform.

Includes startup validation, dependency checks, and clear logging.
"""

import os
import sys
import logging
from datetime import datetime

# Create directories before anything else
os.makedirs('logs', exist_ok=True)
os.makedirs('data', exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/honeypot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def validate_startup():
    """Validate environment and dependencies before starting."""
    warnings = []
    errors = []

    # Check .env file
    if not os.path.exists('.env'):
        warnings.append(".env file not found. Using defaults. Copy .env.example to .env for custom config.")

    # Check SECRET_KEY
    secret = os.environ.get('SECRET_KEY', '')
    if not secret:
        warnings.append("SECRET_KEY not set. Sessions will use auto-generated key (not persistent across restarts).")

    # Check database
    db_url = os.environ.get('DATABASE_URL', '')
    if 'postgresql' in db_url:
        try:
            import psycopg2
        except ImportError:
            errors.append("PostgreSQL configured but psycopg2 not installed.")

    # Check Telegram config
    telegram_token = os.environ.get('TELEGRAM_BOT_TOKEN', '')
    telegram_chat = os.environ.get('TELEGRAM_CHAT_ID', '')
    if telegram_token and not telegram_chat:
        warnings.append("TELEGRAM_BOT_TOKEN set but TELEGRAM_CHAT_ID missing.")
    if telegram_chat and not telegram_token:
        warnings.append("TELEGRAM_CHAT_ID set but TELEGRAM_BOT_TOKEN missing.")

    return warnings, errors


def print_banner(app):
    """Print startup banner with configuration summary."""
    config = app.config

    print("\n")
    print("=" * 62)
    print("  ╔═╗╔═╗╔═╗  ╔═╗╦  ╔═╗╔╦╗╔═╗╔═╗╦═╗╔╦╗")
    print("  ╠═╣╠═╣╚═╗  ╠═╝║  ╠═╣ ║ ╠╣ ║ ║╠╦╝║║║")
    print("  ╩ ╩╩ ╩╚═╝  ╩  ╩═╝╩ ╩ ╩ ╚  ╚═╝╩╚═╩ ╩")
    print("  AI-Powered Honeypot-as-a-Service v2.1")
    print("=" * 62)
    print(f"  {'Feature':<25} {'Status':<15}")
    print("  " + "-" * 40)
    print(f"  {'AI Analysis':<25} {'ENABLED' if config.get('AI_ENABLED') else 'DISABLED':<15}")
    print(f"  {'GeoIP':<25} {'ENABLED' if config.get('GEOIP_ENABLED') else 'DISABLED':<15}")
    print(f"  {'Threat Intel':<25} {'ENABLED' if config.get('THREAT_INTEL_ENABLED') else 'DISABLED':<15}")
    print(f"  {'Alerting':<25} {'ENABLED' if config.get('ALERTING_ENABLED') else 'DISABLED':<15}")
    print(f"  {'Telegram':<25} {'CONFIGURED' if config.get('TELEGRAM_BOT_TOKEN') else 'NOT SET':<15}")
    print(f"  {'Rate Limiting':<25} {'ENABLED' if config.get('RATE_LIMIT_ENABLED') else 'DISABLED':<15}")
    print("  " + "-" * 40)
    print(f"  {'Service':<25} {'Port':<15}")
    print("  " + "-" * 40)
    print(f"  {'Web Dashboard':<25} http://0.0.0.0:{config['WEB_PORT']}")
    print(f"  {'SSH Honeypot':<25} :{config['SSH_HONEYPOT_PORT']}")
    print(f"  {'HTTP Honeypot':<25} :{config['HTTP_HONEYPOT_PORT']}")
    print(f"  {'FTP Honeypot':<25} :{config['FTP_HONEYPOT_PORT']}")
    print("=" * 62)
    print(f"  Database: {config.get('SQLALCHEMY_DATABASE_URI', '?')[:50]}")
    print("=" * 62)
    print("\n  Create admin: flask create-admin <username> <email> <password>")
    print("=" * 62)
    print()


# Run startup validation
warnings, errors = validate_startup()

if errors:
    for e in errors:
        logger.error(f"STARTUP ERROR: {e}")
    sys.exit(1)

for w in warnings:
    logger.warning(f"STARTUP: {w}")

# Import and create app
from app import create_app, socketio, db
from app.models import HoneypotService
from app.honeypots.manager import HoneypotManager

app = create_app(os.environ.get('FLASK_CONFIG', 'default'))
manager = HoneypotManager(app)


def init_services():
    """Initialize default honeypot services in the database."""
    with app.app_context():
        services = [
            ('ssh', app.config['SSH_HONEYPOT_PORT']),
            ('http', app.config['HTTP_HONEYPOT_PORT']),
            ('ftp', app.config['FTP_HONEYPOT_PORT']),
        ]
        for service_type, port in services:
            existing = HoneypotService.query.filter_by(service_type=service_type).first()
            if not existing:
                service = HoneypotService(service_type=service_type, port=port, status='stopped')
                db.session.add(service)
            else:
                # Update port if changed in config
                if existing.port != port:
                    existing.port = port
        db.session.commit()


if __name__ == '__main__':
    init_services()
    print_banner(app)

    # Start honeypot services
    manager.start_all()

    # Run web server
    socketio.run(
        app,
        host='0.0.0.0',
        port=app.config['WEB_PORT'],
        debug=app.config.get('DEBUG', False),
        allow_unsafe_werkzeug=True
    )
