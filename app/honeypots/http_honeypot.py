"""HTTP Honeypot - Simulates a vulnerable web server with fake admin panels.

Enhanced with:
- Multiple fake admin panels (WordPress, phpMyAdmin, cPanel)
- Fake REST API endpoints
- Hidden trap routes
- SQLMap/Nikto/scanner detection
- Realistic response generation
"""

import socket
import threading
import json
import re
from datetime import datetime
from urllib.parse import unquote, parse_qs

from app.honeypots.base import BaseHoneypot


# ============================================================
# FAKE PAGES - Realistic admin panels and trap pages
# ============================================================

FAKE_WORDPRESS_LOGIN = """<!DOCTYPE html>
<html lang="en-US">
<head><meta charset="UTF-8"><title>Log In &lsaquo; Corporate Blog &#8212; WordPress</title>
<style>body{background:#f1f1f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif}
.login{width:320px;margin:50px auto;padding:20px;background:#fff;border:1px solid #c3c4c7;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
h1{text-align:center;margin-bottom:20px}h1 a{font-size:20px;color:#2271b1;text-decoration:none}
label{display:block;margin-bottom:4px;font-size:14px}input[type=text],input[type=password]{width:100%;padding:8px;margin-bottom:12px;border:1px solid #8c8f94;border-radius:4px;box-sizing:border-box}
.button-primary{width:100%;padding:10px;background:#2271b1;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px}
.button-primary:hover{background:#135e96}</style></head>
<body><div class="login"><h1><a href="#">Corporate Blog</a></h1>
<form method="post" action="/wp-login.php">
<label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login">
<label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass">
<p><label><input type="checkbox" name="rememberme"> Remember Me</label></p>
<input type="submit" class="button-primary" value="Log In">
</form><p style="text-align:center;font-size:13px"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p></div></body></html>"""

FAKE_PHPMYADMIN = """<!DOCTYPE html>
<html><head><title>phpMyAdmin</title>
<style>body{font-family:sans-serif;background:#e7e9ed;margin:0}.header{background:#2962ff;color:#fff;padding:10px 20px;font-size:18px}
.login-box{width:400px;margin:50px auto;background:#fff;padding:30px;border-radius:4px;box-shadow:0 2px 8px rgba(0,0,0,0.1)}
h2{margin-top:0;color:#333}input{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:4px;box-sizing:border-box}
select{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:4px}
.btn{width:100%;padding:12px;background:#2962ff;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px;margin-top:10px}
</style></head>
<body><div class="header">phpMyAdmin 5.2.1</div>
<div class="login-box"><h2>Welcome to phpMyAdmin</h2>
<form method="post" action="/phpmyadmin/index.php">
<label>Username:</label><input type="text" name="pma_username" placeholder="root">
<label>Password:</label><input type="password" name="pma_password">
<label>Server Choice:</label><select name="server"><option>localhost</option><option>db-server-01</option></select>
<input type="submit" class="btn" value="Log in">
</form></div></body></html>"""

FAKE_CPANEL = """<!DOCTYPE html>
<html><head><title>cPanel Login</title>
<style>body{font-family:sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.panel{width:380px;background:#fff;padding:40px;border-radius:8px;box-shadow:0 10px 40px rgba(0,0,0,0.3)}
h1{margin:0 0 30px;font-size:24px;color:#333;text-align:center}
input{width:100%;padding:12px;margin:8px 0;border:1px solid #e0e0e0;border-radius:4px;box-sizing:border-box;font-size:14px}
.btn{width:100%;padding:14px;background:#ff6600;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:16px;margin-top:15px}
.footer{text-align:center;margin-top:20px;font-size:12px;color:#888}</style></head>
<body><div class="panel"><h1>cPanel Login</h1>
<form method="post" action="/login/"><input type="text" name="user" placeholder="Username"><input type="password" name="pass" placeholder="Password">
<input type="submit" class="btn" value="Log in"></form>
<div class="footer">cPanel, Inc. &copy; 2024. All rights reserved.</div></div></body></html>"""

FAKE_API_RESPONSE = json.dumps({
    "status": "error",
    "code": 401,
    "message": "Authentication required",
    "api_version": "2.1.0",
    "endpoints": ["/api/v1/users", "/api/v1/data", "/api/v1/config", "/api/v1/admin"]
}, indent=2)

FAKE_ENV_FILE = """APP_NAME=CorporatePortal
APP_ENV=production
APP_KEY=base64:Rk9PQkFSQkFaUVVYQ09SUEdSQVVMVA==
APP_DEBUG=false
APP_URL=https://portal.example.com

DB_CONNECTION=mysql
DB_HOST=192.168.1.10
DB_PORT=3306
DB_DATABASE=portal_prod
DB_USERNAME=portal_admin
DB_PASSWORD=Pr0d_DB_P@ss!2024

REDIS_HOST=192.168.1.20
REDIS_PASSWORD=r3d1s_s3cr3t

MAIL_MAILER=smtp
MAIL_HOST=smtp.example.com
MAIL_USERNAME=noreply@example.com
MAIL_PASSWORD=M@ilP@ss123

AWS_ACCESS_KEY_ID=FAKEKEYID0000EXAMPLE
AWS_SECRET_ACCESS_KEY=FakeSecretAccessKey/XXXXXXXXXXXXXXXXX
"""

FAKE_404_PAGE = """<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.52 (Ubuntu) Server at portal.example.com Port 80</address></body></html>"""

FAKE_INDEX_PAGE = """<!DOCTYPE html>
<html><head><title>Corporate Portal - Under Maintenance</title>
<style>body{font-family:sans-serif;background:#f5f5f5;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.container{text-align:center;padding:40px;background:#fff;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}
h1{color:#333}p{color:#666}a{color:#2271b1}</style></head>
<body><div class="container"><h1>Corporate Portal</h1><p>System is currently under scheduled maintenance.</p>
<p>Please check back later. For urgent matters contact <a href="mailto:admin@example.com">admin@example.com</a></p></div></body></html>"""

FAKE_ROBOTS_TXT = """User-agent: *
Disallow: /admin/
Disallow: /wp-admin/
Disallow: /backup/
Disallow: /config/
Disallow: /api/internal/
Disallow: /debug/
Disallow: /.git/
Sitemap: https://portal.example.com/sitemap.xml
"""

# ============================================================
# SCANNER DETECTION PATTERNS
# ============================================================

SCANNER_SIGNATURES = {
    'sqlmap': {
        'ua_patterns': [r'sqlmap', r'python-requests.*sqlmap'],
        'path_patterns': [r'\*\)', r'UNION.*SELECT', r'AND\s+\d+=\d+'],
        'severity': 'critical'
    },
    'nikto': {
        'ua_patterns': [r'nikto', r'Mozilla/4\.75'],
        'path_patterns': [r'/icons/', r'/manual/', r'\.bak$', r'~$'],
        'severity': 'high'
    },
    'nmap': {
        'ua_patterns': [r'nmap', r'Mozilla/5\.0 \(compatible; Nmap'],
        'path_patterns': [r'/nmaplowercheck', r'/nice%20ports'],
        'severity': 'medium'
    },
    'dirbuster': {
        'ua_patterns': [r'DirBuster', r'gobuster', r'dirsearch', r'feroxbuster'],
        'path_patterns': [],
        'severity': 'high'
    },
    'wpscan': {
        'ua_patterns': [r'WPScan', r'wpscan'],
        'path_patterns': [r'/wp-json/', r'/xmlrpc\.php', r'/wp-content/plugins/'],
        'severity': 'high'
    },
    'acunetix': {
        'ua_patterns': [r'Acunetix'],
        'path_patterns': [r'acunetix-wvs-test', r'/acx_test'],
        'severity': 'critical'
    },
    'burpsuite': {
        'ua_patterns': [r'Burp'],
        'path_patterns': [r'burpcollaborator'],
        'severity': 'high'
    }
}

# Suspicious paths
SUSPICIOUS_PATHS = [
    '/admin', '/wp-admin', '/phpmyadmin', '/wp-login.php',
    '/.env', '/config', '/backup', '/shell', '/cmd',
    '/etc/passwd', '/api/v1', '/.git', '/xmlrpc.php',
    '/administrator', '/login', '/wp-content', '/uploads',
    '/console', '/debug', '/actuator', '/swagger',
    '/.htaccess', '/server-status', '/phpinfo.php',
    '/wp-config.php', '/web.config', '/database',
    '/cgi-bin', '/.svn', '/.hg', '/composer.json'
]

# Hidden trap routes (not linked anywhere - only found by scanners)
TRAP_ROUTES = [
    '/admin/secret-panel',
    '/api/internal/debug',
    '/backup/db-export',
    '/.git/config',
    '/config/database.yml',
    '/debug/vars',
]


class HTTPHoneypot(BaseHoneypot):
    """HTTP Honeypot with fake admin panels and scanner detection."""

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

            request_line = lines[0].split(' ')
            if len(request_line) < 2:
                return None

            method = request_line[0]
            path = unquote(request_line[1])
            version = request_line[2] if len(request_line) > 2 else 'HTTP/1.0'

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

    def detect_scanner(self, request):
        """Detect known vulnerability scanners."""
        user_agent = request['headers'].get('User-Agent', '')
        path = request['path']

        for scanner_name, sig in SCANNER_SIGNATURES.items():
            # Check user agent patterns
            for ua_pattern in sig['ua_patterns']:
                if re.search(ua_pattern, user_agent, re.IGNORECASE):
                    return scanner_name, sig['severity']

            # Check path patterns
            for path_pattern in sig['path_patterns']:
                if re.search(path_pattern, path, re.IGNORECASE):
                    return scanner_name, sig['severity']

        return None, None

    def determine_severity(self, request):
        """Determine attack severity based on request characteristics."""
        path = request['path'].lower()
        body = request.get('body', '').lower()
        combined = f"{path} {body}"

        # SQL injection
        sqli_patterns = [
            r"(?:'|\")?\s*(?:or|and)\s+[\d\w]+=[\d\w]+",
            r"union\s+(?:all\s+)?select",
            r";\s*(?:drop|alter|create|exec|insert|update|delete)",
            r"(?:information_schema|sys\.)",
            r"sleep\s*\(",
            r"benchmark\s*\(",
            r"load_file\s*\(",
        ]
        for pattern in sqli_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                return 'critical'

        # Command injection
        cmd_patterns = [r';.*(?:cat|ls|id|whoami|pwd|wget|curl)', r'\|.*(?:bash|sh|nc)',
                       r'`.*`', r'\$\(', r'/bin/', r'cmd\.exe', r'powershell']
        for pattern in cmd_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                return 'critical'

        # XSS
        xss_patterns = [r'<script', r'javascript:', r'on(?:error|load|click)\s*=', r'alert\s*\(']
        for pattern in xss_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                return 'high'

        # Path traversal
        if '../' in path or '..\\' in path:
            return 'high'

        # Trap routes (only scanners find these)
        if any(path.startswith(trap) for trap in TRAP_ROUTES):
            return 'high'

        # Suspicious paths
        if any(path.startswith(sp) for sp in SUSPICIOUS_PATHS):
            return 'high'

        # POST to login pages
        if request['method'] == 'POST':
            return 'medium'

        return 'low'

    def generate_response(self, request):
        """Generate appropriate fake HTTP response based on path."""
        path = request['path'].lower()
        method = request['method']
        body = request.get('body', '')

        # WordPress login
        if '/wp-login' in path or '/wp-admin' in path:
            if method == 'POST':
                return self._response(200, FAKE_WORDPRESS_LOGIN, 'text/html')
            return self._response(200, FAKE_WORDPRESS_LOGIN, 'text/html')

        # phpMyAdmin
        if '/phpmyadmin' in path or '/pma' in path:
            return self._response(200, FAKE_PHPMYADMIN, 'text/html')

        # cPanel
        if '/cpanel' in path or path == '/login/' or '/cplogin' in path:
            return self._response(200, FAKE_CPANEL, 'text/html')

        # .env file (trap)
        if '/.env' in path or '/env' == path:
            return self._response(200, FAKE_ENV_FILE, 'text/plain')

        # robots.txt (reveals hidden paths)
        if '/robots.txt' in path:
            return self._response(200, FAKE_ROBOTS_TXT, 'text/plain')

        # Fake API
        if path.startswith('/api/'):
            return self._response(401, FAKE_API_RESPONSE, 'application/json')

        # Git config
        if '/.git' in path:
            return self._response(200, '[core]\n\trepositoryformatversion = 0\n\tbare = false\n', 'text/plain')

        # Admin panels
        if '/admin' in path or '/administrator' in path:
            return self._response(200, FAKE_CPANEL, 'text/html')

        # Index
        if path in ['/', '/index.html', '/index.php']:
            return self._response(200, FAKE_INDEX_PAGE, 'text/html')

        # Everything else
        return self._response(404, FAKE_404_PAGE, 'text/html')

    def _response(self, status_code, body, content_type):
        """Build HTTP response bytes."""
        status_map = {200: 'OK', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 500: 'Internal Server Error'}
        status_text = status_map.get(status_code, 'OK')

        response = (
            f"HTTP/1.1 {status_code} {status_text}\r\n"
            f"Server: {self.server_banner}\r\n"
            f"Content-Type: {content_type}; charset=UTF-8\r\n"
            f"Content-Length: {len(body.encode())}\r\n"
            f"X-Powered-By: PHP/8.2.12\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        )
        return response.encode()

    def _extract_credentials(self, request):
        """Extract credentials from POST bodies."""
        body = request.get('body', '')
        username = None
        password = None

        # URL-encoded form data
        if body:
            try:
                params = parse_qs(body)
                # WordPress
                username = params.get('log', params.get('pma_username', params.get('user', [None])))[0]
                password = params.get('pwd', params.get('pma_password', params.get('pass', [None])))[0]
            except (IndexError, TypeError, KeyError):
                pass

            # Try JSON
            if not username:
                try:
                    data = json.loads(body)
                    username = data.get('username', data.get('user', data.get('email')))
                    password = data.get('password', data.get('pass', data.get('pwd')))
                except (json.JSONDecodeError, AttributeError):
                    pass

        return username, password

    def handle_client(self, client_socket, client_address):
        """Handle incoming HTTP connection."""
        client_ip = client_address[0]
        client_port = client_address[1]

        try:
            client_socket.settimeout(10)
            data = client_socket.recv(8192)

            if not data:
                return

            request = self.parse_http_request(data)
            if not request:
                return

            # Detect scanners
            scanner_name, scanner_severity = self.detect_scanner(request)
            severity = self.determine_severity(request)

            if scanner_name:
                severity = scanner_severity or severity
                self.log_attack(
                    source_ip=client_ip,
                    source_port=client_port,
                    action=f'scanner_detected:{scanner_name}',
                    details=json.dumps({
                        'scanner': scanner_name,
                        'method': request['method'],
                        'path': request['path'],
                        'user_agent': request['headers'].get('User-Agent', ''),
                    }),
                    severity=severity
                )

            # Extract credentials from POST requests
            username, password = None, None
            if request['method'] == 'POST':
                username, password = self._extract_credentials(request)

            # Log the attack
            self.log_attack(
                source_ip=client_ip,
                source_port=client_port,
                action=f"{request['method']} {request['path']}",
                details=json.dumps({
                    'method': request['method'],
                    'path': request['path'],
                    'headers': request['headers'],
                    'body': request.get('body', '')[:1000],
                    'user_agent': request['headers'].get('User-Agent', 'Unknown'),
                    'scanner_detected': scanner_name,
                    'is_trap_route': any(request['path'].lower().startswith(t) for t in TRAP_ROUTES)
                }),
                username_attempted=username,
                password_attempted=password,
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
