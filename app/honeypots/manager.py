"""Honeypot Manager - Manages all honeypot services."""

import logging

from app.honeypots.ssh_honeypot import SSHHoneypot
from app.honeypots.http_honeypot import HTTPHoneypot
from app.honeypots.ftp_honeypot import FTPHoneypot


class HoneypotManager:
    """Central manager for all honeypot services."""

    _instance = None

    def __init__(self, app):
        self.app = app
        self.honeypots = {}
        self.logger = logging.getLogger('honeypot.manager')

        # Initialize honeypot services
        self.honeypots['ssh'] = SSHHoneypot(
            app=app,
            port=app.config['SSH_HONEYPOT_PORT']
        )
        self.honeypots['http'] = HTTPHoneypot(
            app=app,
            port=app.config['HTTP_HONEYPOT_PORT']
        )
        self.honeypots['ftp'] = FTPHoneypot(
            app=app,
            port=app.config['FTP_HONEYPOT_PORT']
        )

        HoneypotManager._instance = self

    @classmethod
    def get_instance(cls):
        return cls._instance

    def start_all(self):
        """Start all honeypot services."""
        for name, honeypot in self.honeypots.items():
            self.start_honeypot(name)

    def stop_all(self):
        """Stop all honeypot services."""
        for name, honeypot in self.honeypots.items():
            self.stop_honeypot(name)

    def start_honeypot(self, service_type):
        """Start a specific honeypot service."""
        if service_type in self.honeypots:
            honeypot = self.honeypots[service_type]
            if not honeypot.is_running:
                honeypot.start_threaded()
                self.logger.info(f"Started {service_type} honeypot")
            else:
                self.logger.warning(f"{service_type} honeypot is already running")

    def stop_honeypot(self, service_type):
        """Stop a specific honeypot service."""
        if service_type in self.honeypots:
            honeypot = self.honeypots[service_type]
            if honeypot.is_running:
                honeypot.stop()
                self.logger.info(f"Stopped {service_type} honeypot")

    def get_status(self):
        """Get status of all honeypot services."""
        return {
            name: {
                'running': hp.is_running,
                'port': hp.port,
                'type': hp.service_type
            }
            for name, hp in self.honeypots.items()
        }
