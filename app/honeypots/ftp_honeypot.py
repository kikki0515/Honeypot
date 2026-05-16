"""FTP Honeypot - Simulates an FTP server to capture file access attempts."""

import socket
import threading
import json
from datetime import datetime

from app.honeypots.base import BaseHoneypot


# Fake directory listing
FAKE_DIR_LISTING = """drwxr-xr-x   2 root root  4096 Jan 15 10:30 .
drwxr-xr-x   3 root root  4096 Jan 15 10:30 ..
-rw-r--r--   1 root root  1024 Jan 10 08:15 config.bak
-rw-r--r--   1 root root   256 Dec 20 14:22 credentials.txt
-rw-r--r--   1 root root  2048 Jan 12 09:00 database_backup.sql
drwxr-xr-x   2 root root  4096 Jan 05 16:45 private
-rw-r--r--   1 root root   512 Nov 30 11:30 readme.txt
"""


class FTPHoneypot(BaseHoneypot):
    """FTP Honeypot that simulates a vulnerable FTP server."""

    def __init__(self, app=None, port=2121):
        super().__init__(service_type='ftp', port=port, app=app)
        self.banner = '220 ProFTPD 1.3.5 Server (Ubuntu) [::ffff:192.168.1.100]'

    def handle_client(self, client_socket, client_address):
        """Handle incoming FTP connection."""
        client_ip = client_address[0]
        client_port = client_address[1]
        authenticated = False
        current_user = None

        self.log_attack(
            source_ip=client_ip,
            source_port=client_port,
            action='connection',
            details=json.dumps({'event': 'new_ftp_connection'}),
            severity='low'
        )

        try:
            # Send banner
            client_socket.sendall(f"{self.banner}\r\n".encode())

            while self._running:
                client_socket.settimeout(30)
                try:
                    data = client_socket.recv(1024)
                except socket.timeout:
                    break

                if not data:
                    break

                command = data.decode('utf-8', errors='replace').strip()
                if not command:
                    continue

                parts = command.split(' ', 1)
                cmd = parts[0].upper()
                args = parts[1] if len(parts) > 1 else ''

                # Handle FTP commands
                if cmd == 'USER':
                    current_user = args
                    client_socket.sendall(b'331 Password required for ' + args.encode() + b'\r\n')

                elif cmd == 'PASS':
                    # Log login attempt
                    self.log_attack(
                        source_ip=client_ip,
                        source_port=client_port,
                        action='login_attempt',
                        details=json.dumps({
                            'username': current_user,
                            'password': args
                        }),
                        username_attempted=current_user,
                        password_attempted=args,
                        severity='high'
                    )
                    # Always "authenticate" to see what they do next
                    authenticated = True
                    client_socket.sendall(b'230 User logged in.\r\n')

                elif cmd == 'SYST':
                    client_socket.sendall(b'215 UNIX Type: L8\r\n')

                elif cmd == 'PWD':
                    client_socket.sendall(b'257 "/" is current directory.\r\n')

                elif cmd == 'CWD':
                    self.log_attack(
                        source_ip=client_ip,
                        action='directory_change',
                        details=json.dumps({'directory': args}),
                        severity='medium'
                    )
                    client_socket.sendall(b'250 Directory successfully changed.\r\n')

                elif cmd == 'LIST' or cmd == 'NLST':
                    self.log_attack(
                        source_ip=client_ip,
                        action='directory_listing',
                        details=json.dumps({'command': cmd, 'path': args}),
                        severity='medium'
                    )
                    client_socket.sendall(b'150 Opening data connection.\r\n')
                    # Simulate directory listing
                    client_socket.sendall(b'226 Transfer complete.\r\n')

                elif cmd == 'RETR':
                    self.log_attack(
                        source_ip=client_ip,
                        action='file_download',
                        details=json.dumps({'filename': args}),
                        severity='high'
                    )
                    client_socket.sendall(b'550 Permission denied.\r\n')

                elif cmd == 'STOR':
                    self.log_attack(
                        source_ip=client_ip,
                        action='file_upload',
                        details=json.dumps({'filename': args}),
                        severity='critical'
                    )
                    client_socket.sendall(b'550 Permission denied.\r\n')

                elif cmd == 'DELE':
                    self.log_attack(
                        source_ip=client_ip,
                        action='file_delete',
                        details=json.dumps({'filename': args}),
                        severity='critical'
                    )
                    client_socket.sendall(b'550 Permission denied.\r\n')

                elif cmd == 'TYPE':
                    client_socket.sendall(b'200 Type set to I.\r\n')

                elif cmd == 'PASV':
                    client_socket.sendall(b'227 Entering Passive Mode (192,168,1,100,40,1).\r\n')

                elif cmd == 'QUIT':
                    client_socket.sendall(b'221 Goodbye.\r\n')
                    break

                else:
                    client_socket.sendall(f'502 Command not implemented: {cmd}\r\n'.encode())

        except Exception as e:
            self.logger.error(f"FTP honeypot error handling {client_ip}: {e}")
        finally:
            client_socket.close()

    def start(self):
        """Start the FTP honeypot server."""
        self._running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1.0)

        try:
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(100)
            self.update_status('running')
            self.logger.info(f"FTP Honeypot started on port {self.port}")

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
                        self.logger.error(f"FTP Honeypot accept error: {e}")

        except Exception as e:
            self.logger.error(f"FTP Honeypot failed to start: {e}")
            self.update_status('error')
        finally:
            self.server_socket.close()
            if self._running:
                self.update_status('stopped')
