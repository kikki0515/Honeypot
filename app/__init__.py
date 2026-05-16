"""Honeypot-as-a-Service Platform - Application Factory.

AI-Powered Distributed Threat Intelligence Platform with real-time monitoring,
attack classification, GeoIP enrichment, and multi-channel alerting.
"""

import os
import logging

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_login import LoginManager
from flask_migrate import Migrate

from config import config

logger = logging.getLogger('honeypot.app')

db = SQLAlchemy()
socketio = SocketIO()
login_manager = LoginManager()
migrate = Migrate()


def create_app(config_name=None):
    """Create and configure the Flask application."""
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'default')

    app = Flask(__name__,
                template_folder='../templates',
                static_folder='../static')
    app.config.from_object(config[config_name])

    # Ensure SECRET_KEY is set (critical for sessions)
    if not app.config.get('SECRET_KEY') or app.config['SECRET_KEY'] == 'honeypot-secret-key-change-in-production':
        import secrets
        app.config['SECRET_KEY'] = secrets.token_hex(32)
        logger.warning("Using auto-generated SECRET_KEY. Set SECRET_KEY in .env for persistent sessions.")

    # Session configuration for reliable auth
    app.config.setdefault('SESSION_TYPE', 'filesystem')
    app.config.setdefault('PERMANENT_SESSION_LIFETIME', 86400)  # 24 hours
    app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
    app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
    app.config.setdefault('REMEMBER_COOKIE_DURATION', 86400 * 7)  # 7 days

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    socketio.init_app(app, cors_allowed_origins="*", async_mode='threading')
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'error'

    # Security extensions (optional, graceful if not installed)
    _init_security(app)

    # Register blueprints
    from app.routes.dashboard import dashboard_bp
    from app.routes.api import api_bp
    from app.routes.auth import auth_bp
    from app.routes.agents import agents_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(agents_bp, url_prefix='/api/agents')

    # Register CLI commands
    from app.cli import register_cli
    register_cli(app)

    # Initialize database and services
    with app.app_context():
        from app import models
        db.create_all()
        _init_services(app)

    return app


def _init_security(app):
    """Initialize security extensions (graceful failures)."""
    # Rate limiting
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address

        if app.config.get('RATE_LIMIT_ENABLED', False):
            limiter = Limiter(
                app=app,
                key_func=get_remote_address,
                default_limits=[app.config.get('RATE_LIMIT_DEFAULT', '200/hour')],
                storage_uri=app.config.get('REDIS_URL', 'memory://')
            )
            app.extensions['limiter'] = limiter
            logger.info("Rate limiting enabled")
    except ImportError:
        logger.debug("flask-limiter not available, skipping rate limiting")
    except Exception as e:
        logger.warning(f"Rate limiter init failed: {e}")

    # Security headers
    try:
        from flask_talisman import Talisman

        if not app.config.get('DEBUG', False):
            Talisman(
                app,
                force_https=app.config.get('SESSION_COOKIE_SECURE', False),
                session_cookie_secure=app.config.get('SESSION_COOKIE_SECURE', False),
                content_security_policy=None  # Disabled for TailwindCSS CDN
            )
            logger.info("Security headers enabled (Talisman)")
    except ImportError:
        logger.debug("flask-talisman not available, skipping security headers")
    except Exception as e:
        logger.debug(f"Talisman init skipped: {e}")


def _init_services(app):
    """Initialize AI, GeoIP, Reputation, and Alerting services."""
    try:
        from app.ai.analyzer import AttackAnalyzer
        AttackAnalyzer()
        logger.info("AI Analyzer initialized")
    except Exception as e:
        logger.warning(f"AI Analyzer init failed: {e}")

    try:
        from app.intel.geoip import GeoIPLookup
        geoip = GeoIPLookup(db_path=app.config.get('GEOIP_DB_PATH'))
        # Attempt auto-download if not found
        if not geoip.reader:
            _try_download_geoip(app, geoip)
    except Exception as e:
        logger.warning(f"GeoIP init failed: {e}")

    try:
        from app.intel.reputation import ReputationChecker
        ReputationChecker(app=app)
    except Exception as e:
        logger.warning(f"Reputation checker init failed: {e}")

    try:
        from app.alerts.dispatcher import AlertDispatcher
        AlertDispatcher(app=app)
    except Exception as e:
        logger.warning(f"Alert dispatcher init failed: {e}")

    try:
        from app.agents.manager import AgentManager
        AgentManager(app=app)
    except Exception as e:
        logger.warning(f"Agent manager init failed: {e}")


def _try_download_geoip(app, geoip_instance):
    """Attempt to download GeoIP database if missing."""
    try:
        db_path = app.config.get('GEOIP_DB_PATH', '')
        if not db_path:
            return

        data_dir = os.path.dirname(db_path)
        os.makedirs(data_dir, exist_ok=True)

        if os.path.exists(db_path):
            return

        logger.info("GeoIP database not found. Attempting download...")

        # Try downloading from a public mirror
        import requests
        import gzip
        import shutil

        # Use ip-api.com as fallback - no database needed
        # The GeoIPLookup class already has a fallback mechanism
        logger.info("GeoIP database not available. Using built-in fallback geolocation.")

    except ImportError:
        logger.debug("Cannot auto-download GeoIP (requests not available)")
    except Exception as e:
        logger.debug(f"GeoIP auto-download skipped: {e}")
