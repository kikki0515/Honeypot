"""Dashboard routes for the web interface.

Includes main dashboard, attacks, services, analytics, settings, and attack map.
"""

from flask import Blueprint, render_template, jsonify, request
from flask_login import login_required, current_user

from app import db
from app.models import SystemSetting

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


@dashboard_bp.route('/map')
@login_required
def attack_map():
    """Real-time attack world map."""
    return render_template('dashboard/map.html')


@dashboard_bp.route('/settings', methods=['GET'])
@login_required
def settings():
    """Settings page."""
    if not current_user.is_admin:
        from flask import flash, redirect, url_for
        flash('Admin access required.', 'error')
        return redirect(url_for('dashboard.index'))
    return render_template('dashboard/settings.html')


@dashboard_bp.route('/settings/save', methods=['POST'])
@login_required
def save_settings():
    """Save settings from dashboard."""
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    try:
        for key, value in data.items():
            SystemSetting.set(key, value)

        return jsonify({'status': 'success', 'message': 'Settings saved successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/settings/get', methods=['GET'])
@login_required
def get_settings():
    """Get all settings."""
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        settings = SystemSetting.query.all()
        return jsonify({
            'settings': {s.key: s.value for s in settings}
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@dashboard_bp.route('/settings/test-telegram', methods=['POST'])
@login_required
def test_telegram():
    """Send a test Telegram notification."""
    if not current_user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    try:
        from app.alerts.dispatcher import AlertDispatcher
        dispatcher = AlertDispatcher.get_instance()
        if not dispatcher:
            return jsonify({'error': 'Alert dispatcher not initialized'}), 500

        if not dispatcher.telegram_token or not dispatcher.telegram_chat_id:
            return jsonify({'error': 'Telegram not configured. Set BOT_TOKEN and CHAT_ID.'}), 400

        test_message = (
            "🧪 HaaS TEST NOTIFICATION\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "✅ Telegram integration working!\n"
            "🤖 Honeypot-as-a-Service AI Platform\n"
            "🕐 Test sent successfully."
        )
        dispatcher._send_telegram(test_message)
        return jsonify({'status': 'success', 'message': 'Test notification sent!'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500
