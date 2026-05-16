"""Main entry point for the AI-Powered Honeypot-as-a-Service platform."""

import os
import logging
from datetime import datetime

from app import create_app, socketio, db
from app.models import HoneypotService
from app.honeypots.manager import HoneypotManager

# Create logs directory
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

# Create Flask application
app = create_app(os.environ.get('FLASK_CONFIG', 'default'))

# Initialize honeypot manager
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
                service = HoneypotService(
                    service_type=service_type,
                    port=port,
                    status='stopped'
                )
                db.session.add(service)
        db.session.commit()


if __name__ == '__main__':
    init_services()

    # Start all honeypot services
    logger.info("=" * 60)
    logger.info("  AI-Powered Honeypot-as-a-Service Platform v2.0")
    logger.info("  Distributed Threat Intelligence System")
    logger.info("=" * 60)
    logger.info(f"  AI Analysis: {'ENABLED' if app.config.get('AI_ENABLED') else 'DISABLED'}")
    logger.info(f"  GeoIP: {'ENABLED' if app.config.get('GEOIP_ENABLED') else 'DISABLED'}")
    logger.info(f"  Threat Intel: {'ENABLED' if app.config.get('THREAT_INTEL_ENABLED') else 'DISABLED'}")
    logger.info(f"  Alerting: {'ENABLED' if app.config.get('ALERTING_ENABLED') else 'DISABLED'}")
    logger.info("=" * 60)

    manager.start_all()

    logger.info(f"  Web Dashboard: http://0.0.0.0:{app.config['WEB_PORT']}")
    logger.info(f"  SSH Honeypot:  port {app.config['SSH_HONEYPOT_PORT']}")
    logger.info(f"  HTTP Honeypot: port {app.config['HTTP_HONEYPOT_PORT']}")
    logger.info(f"  FTP Honeypot:  port {app.config['FTP_HONEYPOT_PORT']}")
    logger.info("=" * 60)

    socketio.run(
        app,
        host='0.0.0.0',
        port=app.config['WEB_PORT'],
        debug=app.config['DEBUG'],
        allow_unsafe_werkzeug=True
    )
