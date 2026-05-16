"""Authentication routes - Fixed and hardened.

Registration is disabled. Admin users are created via CLI command only.
Login uses Flask-Login with proper session handling.
"""

import logging
from datetime import datetime

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user

from app import db
from app.models import User

logger = logging.getLogger('honeypot.auth')

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login with proper session management."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('auth/login.html')

        # Query user by username
        user = User.query.filter_by(username=username).first()

        if user and user.is_active and user.check_password(password):
            # Successful login
            login_user(user, remember=True)
            user.last_login = datetime.utcnow()
            db.session.commit()

            logger.info(f"User '{username}' logged in successfully from {request.remote_addr}")

            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard.index'))

        # Failed login
        logger.warning(f"Failed login attempt for '{username}' from {request.remote_addr}")
        flash('Invalid username or password.', 'error')

    return render_template('auth/login.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Registration is disabled. Redirect to login with message."""
    flash('Registration is disabled. Contact your administrator for access.', 'error')
    return redirect(url_for('auth.login'))


@auth_bp.route('/logout')
@login_required
def logout():
    """Handle user logout - clear session properly."""
    username = current_user.username
    logout_user()
    logger.info(f"User '{username}' logged out")
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth.login'))
