"""HTTP Honeypot - Simulates a vulnerable web server to capture web attacks."""

import socket
import threading
import json
from datetime import datetime
from urllib.parse import unquote

from app.honeypots.base import BaseHoneypot


# Fake response pages
FAKE_LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head><title>Admin Panel - Login</title></head>
<body>
<h1>Administration Panel</h1>
<form method="POST" action="/admin/login">
    <input type="text" name="username" placeholder="Username"><br>
    <input type="password" name="password" placeholder="Password"><br>
    <button type="submit">Login</button>
</form>
</body>
</html>"""

FAKE_404_PAGE = """<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server</address>
</body>
</html>"""

FAKE_INDEX_PAGE = """<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body>
<h1>Welcome to our server</h1>
<p>This server is under maintenance.</p>
</body>
</html>"""


# Suspicious paths that indicate scanning/attack behavior
SUSPICIOUS_PATHS = [
    '/admin', '/wp-admin', '/phpmyadmin', '/wp-login.php',
    '/.env', '/config', '/backup', '/shell', '/cmd',
    '/etc/passwd', '/api/v1', '/.git', '/xmlrpc.php',
    '/administrator', '/login', '/wp-content', '/uploads'
]


class HTTPHoneypot(BaseHoneypot):
    """HTTP Honeypot that simulates a vulnerable web server."""

    def __init__(self, app=None, port=8080):
        super().__init__(service_type='http', port=port, app=app)
        self.server_banner = 'Apache/2.4.52 (Ubuntu)'

    def parse_http_request(self, data):
        """Parse raw HTTP request data."""
        try:
            decoded = data.decode('utf-8', errors='replace')
            lines = decoded.split('\r\n')
            if not lines:
                return None

            # Parse request line
            request_line = lines[0].split(' ')
            if len(request_line) < 2:
                return None

            method = request_line[0]
            path = unquote(request_line[1])
            version = request_line[2] if len(request_line) > 2 else 'HTTP/1.0'

            # Parse headers
            headers = {}
            body = ''
            header_end = False
            for line in lines[1:]:
                if line == '':
                    header_end = True
                    continue
                if header_end:
                    body += line
                else:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()

            return {
                'method': method,
                'path': path,
                'version': version,
                'headers': headers,
                'body': body
            }
        except Exception:
            return None

    def determine_severity(self, request):
        """Determine attack severity based on request characteristics."""
        path = request['path'].lower()

        # SQL injection indicators
        sql_indicators = ["'", "union", "select", "drop", "insert", "--", "or 1=1"]
        if any(indicator in path for indicator in sql_indicators):
            return 'critical'

        # Command injection indicators
        cmd_indicators = [';', '|', '`', '$(', '/bin/', 'cmd.exe']
        if any(indicator in path for indicator in cmd_indicators):
            return 'critical'

        # Path traversal
        if '../' in path or '..\\' in path:
            return 'high'

        # Suspicious paths
        if any(path.startswith(sp) for sp in SUSPICIOUS_PATHS):
            return 'high'

        # POST to login pages
        if request['method'] == 'POST':
            return 'medium'

        return 'low'

    def generate_response(self, request):
        """Generate appropriate fake HTTP response."""
        path = request['path'].lower()

        if path in ['/', '/index.html']:
            body = FAKE_INDEX_PAGE
            status = '200 OK'
        elif 'login' in path or 'admin' in path:
            body = FAKE_LOGIN_PAGE
            status = '200 OK'
        else:
            body = FAKE_404_PAGE
            status = '404 Not Found'

        response = (
            f"HTTP/1.1 {status}\r\n"
            f"Server: {self.server_banner}\r\n"
            f"Content-Type: text/html; charset=UTF-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )
        return response.encode()

    def handle_client(self, client_socket, client_address):
        """Handle incoming HTTP connection."""
        client_ip = client_address[0]
        client_port = client_address[1]

        try:
            client_socket.settimeout(10)
            data = client_socket.recv(4096)

            if not data:
                return

            request = self.parse_http_request(data)
            if not request:
                return

            severity = self.determine_severity(request)

            self.log_attack(
                source_ip=client_ip,
                source_port=client_port,
                action=f"{request['method']} {request['path']}",
                details=json.dumps({
                    'method': request['method'],
                    'path': request['path'],
                    'headers': request['headers'],
                    'body': request['body'][:500],
                    'user_agent': request['headers'].get('User-Agent', 'Unknown')
                }),
                severity=severity
            )

            # Send fake response
            response = self.generate_response(request)
            client_socket.sendall(response)

        except socket.timeout:
            pass
        except Exception as e:
            self.logger.error(f"HTTP honeypot error handling {client_ip}: {e}")
        finally:
            client_socket.close()

    def start(self):
        """Start the HTTP honeypot server."""
        self._running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1.0)

        try:
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(100)
            self.update_status('running')
            self.logger.info(f"HTTP Honeypot started on port {self.port}")

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
                        self.logger.error(f"HTTP Honeypot accept error: {e}")

        except Exception as e:
            self.logger.error(f"HTTP Honeypot failed to start: {e}")
            self.update_status('error')
        finally:
            self.server_socket.close()
            if self._running:
                self.update_status('stopped')
