"""Honeypot-as-a-Service Platform - Application Factory.

AI-Powered Distributed Threat Intelligence Platform with real-time monitoring,
attack classification, GeoIP enrichment, and multi-channel alerting.
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_login import LoginManager

from config import config

db = SQLAlchemy()
socketio = SocketIO()
login_manager = LoginManager()


def create_app(config_name='default'):
    """Create and configure the Flask application."""
    app = Flask(__name__,
                template_folder='../templates',
                static_folder='../static')
    app.config.from_object(config[config_name])

    # Initialize extensions
    db.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*", async_mode='threading')
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    # Register blueprints
    from app.routes.dashboard import dashboard_bp
    from app.routes.api import api_bp
    from app.routes.auth import auth_bp
    from app.routes.agents import agents_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(agents_bp, url_prefix='/api/agents')

    # Initialize AI analyzer
    with app.app_context():
        from app import models
        db.create_all()

        # Initialize singletons
        _init_services(app)

    return app


def _init_services(app):
    """Initialize AI, GeoIP, Reputation, and Alerting services."""
    try:
        from app.ai.analyzer import AttackAnalyzer
        AttackAnalyzer()

        from app.intel.geoip import GeoIPLookup
        GeoIPLookup(db_path=app.config.get('GEOIP_DB_PATH'))

        from app.intel.reputation import ReputationChecker
        ReputationChecker(app=app)

        from app.alerts.dispatcher import AlertDispatcher
        AlertDispatcher(app=app)

        from app.agents.manager import AgentManager
        AgentManager(app=app)

    except Exception as e:
        import logging
        logging.getLogger('honeypot').warning(f"Service init warning: {e}")
