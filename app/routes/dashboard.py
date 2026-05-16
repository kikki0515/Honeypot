"""Dashboard routes for the web interface."""

from flask import Blueprint, render_template
from flask_login import login_required

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@login_required
def index():
    """Main dashboard page."""
    return render_template('dashboard/index.html')


@dashboard_bp.route('/attacks')
@login_required
def attacks():
    """Attack logs page."""
    return render_template('dashboard/attacks.html')


@dashboard_bp.route('/services')
@login_required
def services():
    """Honeypot services management page."""
    return render_template('dashboard/services.html')


@dashboard_bp.route('/analytics')
@login_required
def analytics():
    """Analytics and reports page."""
    return render_template('dashboard/analytics.html')
