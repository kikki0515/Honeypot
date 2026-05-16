"""Main entry point for the Honeypot-as-a-Service platform."""

import os
import logging
from datetime import datetime

from app import create_app, socketio, db
from app.models import HoneypotService
from app.honeypots.manager import HoneypotManager

# Create logs directory
os.makedirs('logs', exist_ok=True)

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
    logger.info("Starting Honeypot-as-a-Service Platform...")
    manager.start_all()

    # Run Flask web server with SocketIO
    logger.info(f"Web Dashboard running on http://0.0.0.0:{app.config['WEB_PORT']}")
    socketio.run(
        app,
        host='0.0.0.0',
        port=app.config['WEB_PORT'],
        debug=app.config['DEBUG'],
        allow_unsafe_werkzeug=True
    )
