"""SSH Honeypot - Simulates an SSH server to capture brute-force login attempts."""

import socket
import threading
import paramiko
import json
from datetime import datetime

from app.honeypots.base import BaseHoneypot


# Generate RSA host key for the SSH server
HOST_KEY = paramiko.RSAKey.generate(2048)


class SSHServerInterface(paramiko.ServerInterface):
    """Paramiko server interface to handle SSH authentication attempts."""

    def __init__(self, client_ip, honeypot):
        self.client_ip = client_ip
        self.honeypot = honeypot
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        """Log authentication attempts - always deny access."""
        self.honeypot.log_attack(
            source_ip=self.client_ip,
            action='login_attempt',
            details=json.dumps({
                'method': 'password',
                'username': username,
                'password': password
            }),
            username_attempted=username,
            password_attempted=password,
            severity='high'
        )
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        """Log public key authentication attempts."""
        self.honeypot.log_attack(
            source_ip=self.client_ip,
            action='pubkey_attempt',
            details=json.dumps({
                'method': 'publickey',
                'username': username,
                'key_type': key.get_name()
            }),
            username_attempted=username,
            severity='medium'
        )
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password,publickey'

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class SSHHoneypot(BaseHoneypot):
    """SSH Honeypot that simulates an SSH server."""

    def __init__(self, app=None, port=2222):
        super().__init__(service_type='ssh', port=port, app=app)
        self.banner = 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4'

    def handle_client(self, client_socket, client_address):
        """Handle incoming SSH connection."""
        client_ip = client_address[0]
        client_port = client_address[1]

        self.log_attack(
            source_ip=client_ip,
            source_port=client_port,
            action='connection',
            details=json.dumps({'event': 'new_ssh_connection'}),
            severity='low'
        )

        try:
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(HOST_KEY)
            transport.local_version = self.banner

            server = SSHServerInterface(client_ip, self)

            try:
                transport.start_server(server=server)
            except paramiko.SSHException:
                self.logger.warning(f"SSH negotiation failed from {client_ip}")
                return

            # Wait for authentication attempts (timeout after 30 seconds)
            channel = transport.accept(timeout=30)
            if channel is not None:
                channel.close()

        except Exception as e:
            self.logger.error(f"SSH honeypot error handling {client_ip}: {e}")
        finally:
            try:
                transport.close()
            except Exception:
                pass
            client_socket.close()

    def start(self):
        """Start the SSH honeypot server."""
        self._running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1.0)

        try:
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(100)
            self.update_status('running')
            self.logger.info(f"SSH Honeypot started on port {self.port}")

            while self._running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    self.increment_connections()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        self.logger.error(f"SSH Honeypot accept error: {e}")

        except Exception as e:
            self.logger.error(f"SSH Honeypot failed to start: {e}")
            self.update_status('error')
        finally:
            self.server_socket.close()
            if self._running:
                self.update_status('stopped')
