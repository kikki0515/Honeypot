"""CLI commands for the Honeypot platform.

Provides management commands like create-admin for user management.
Usage: flask create-admin <username> <email> <password>
"""

import click
from flask import current_app
from flask.cli import with_appcontext

from app import db
from app.models import User


@click.command('create-admin')
@click.argument('username')
@click.argument('email')
@click.argument('password')
@with_appcontext
def create_admin_command(username, email, password):
    """Create an admin user.

    Usage: flask create-admin admin admin@example.com admin123
    """
    try:
        # Ensure tables exist
        db.create_all()

        # Check for existing user
        existing = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing:
            if existing.username == username:
                click.echo(f"Error: Username '{username}' already exists.")
            else:
                click.echo(f"Error: Email '{email}' already registered.")
            return

        # Validate inputs
        if len(password) < 4:
            click.echo("Error: Password must be at least 4 characters.")
            return

        if not email or '@' not in email:
            click.echo("Error: Invalid email address.")
            return

        # Create admin user
        user = User(
            username=username,
            email=email,
            role='admin',
            is_active=True
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        click.echo(f"Admin user created successfully!")
        click.echo(f"  Username: {username}")
        click.echo(f"  Email:    {email}")
        click.echo(f"  Role:     admin")
        click.echo(f"\nYou can now login at http://localhost:{current_app.config.get('WEB_PORT', 5000)}/auth/login")

    except Exception as e:
        db.session.rollback()
        click.echo(f"Error creating admin: {e}")


@click.command('init-db')
@with_appcontext
def init_db_command():
    """Initialize/recreate database tables.

    Usage: flask init-db
    """
    try:
        db.create_all()
        click.echo("Database tables created successfully.")
    except Exception as e:
        click.echo(f"Error initializing database: {e}")


@click.command('list-users')
@with_appcontext
def list_users_command():
    """List all registered users.

    Usage: flask list-users
    """
    try:
        users = User.query.all()
        if not users:
            click.echo("No users found. Use 'flask create-admin' to create one.")
            return

        click.echo(f"\n{'ID':<5} {'Username':<20} {'Email':<30} {'Role':<10} {'Active':<8}")
        click.echo("-" * 75)
        for u in users:
            click.echo(f"{u.id:<5} {u.username:<20} {u.email:<30} {u.role:<10} {'Yes' if u.is_active else 'No':<8}")
        click.echo(f"\nTotal: {len(users)} user(s)")

    except Exception as e:
        click.echo(f"Error listing users: {e}")


def register_cli(app):
    """Register all CLI commands with the Flask app."""
    app.cli.add_command(create_admin_command)
    app.cli.add_command(init_db_command)
    app.cli.add_command(list_users_command)
