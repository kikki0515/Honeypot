"""FTP Honeypot - Simulates a vulnerable FTP server with fake files.

Enhanced with:
- Fake filesystem with realistic file structure
- Upload/download tracking with content capture
- Fake sensitive documents
- Detailed command logging
"""

import socket
import threading
import json
from datetime import datetime

from app.honeypots.base import BaseHoneypot


# Fake FTP filesystem structure
FTP_FILESYSTEM = {
    '/': {
        'type': 'dir',
        'contents': ['backup', 'config', 'data', 'private', 'public', 'scripts', 'logs']
    },
    '/backup': {
        'type': 'dir',
        'contents': ['database_2024-01-15.sql.gz', 'site_backup.tar.gz', 'credentials_export.csv']
    },
    '/config': {
        'type': 'dir',
        'contents': ['app.conf', 'database.yml', '.env.production', 'nginx.conf']
    },
    '/data': {
        'type': 'dir',
        'contents': ['users.csv', 'transactions.db', 'reports']
    },
    '/data/reports': {
        'type': 'dir',
        'contents': ['Q4_2023_financial.xlsx', 'employee_list.csv', 'audit_log.txt']
    },
    '/private': {
        'type': 'dir',
        'contents': ['ssh_keys', 'certificates', 'api_tokens.txt', 'README.md']
    },
    '/private/ssh_keys': {
        'type': 'dir',
        'contents': ['id_rsa', 'id_rsa.pub', 'deploy_key', 'authorized_keys']
    },
    '/public': {
        'type': 'dir',
        'contents': ['index.html', 'assets', 'robots.txt']
    },
    '/scripts': {
        'type': 'dir',
        'contents': ['deploy.sh', 'backup.sh', 'setup_server.sh', 'cron_tasks.sh']
    },
    '/logs': {
        'type': 'dir',
        'contents': ['access.log', 'error.log', 'auth.log', 'app.log']
    },
}

# Fake file contents (returned when RETR is attempted)
FTP_FILE_CONTENTS = {
    '/config/.env.production': (
        'DATABASE_URL=mysql://admin:Pr0d_P@ss_2024@db.internal:3306/production\n'
        'REDIS_URL=redis://:r3d1s_s3cr3t@cache.internal:6379\n'
        'SECRET_KEY=fake_sk_live_XXXXXXXXXXXXXXXXXXXX\n'
        'AWS_ACCESS_KEY=AKIAFAKEEXAMPLEKEYID\n'
        'AWS_SECRET_KEY=FakeSecretKey/XXXXXXXXXXXXXXXXXXXXXXX\n'
        'STRIPE_KEY=fake_sk_live_XXXXXXXXXXXXXXXXXXXX\n'
    ),
    '/config/database.yml': (
        'production:\n'
        '  adapter: mysql2\n'
        '  host: db-master.internal\n'
        '  database: production_db\n'
        '  username: app_user\n'
        '  password: D@t@b@s3_Pr0d!\n'
        '  pool: 25\n'
    ),
    '/private/api_tokens.txt': (
        '# API Tokens - DO NOT SHARE\n'
        'GitHub PAT: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n'
        'Slack Bot: xoxb-xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx\n'
        'SendGrid: SG.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n'
        'Twilio: SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n'
    ),
    '/private/README.md': (
        '# Private Server Documentation\n\n'
        '## Access Credentials\n'
        '- SSH: admin@prod-server (key in /private/ssh_keys/)\n'
        '- Database: See /config/database.yml\n'
        '- API: See /private/api_tokens.txt\n\n'
        '## Important\n'
        'Rotate all credentials quarterly. Last rotation: 2024-01-01\n'
    ),
    '/backup/credentials_export.csv': (
        'service,username,password,notes\n'
        'mysql,root,R00t_DB_2024!,production database\n'
        'redis,default,r3d1s_c@ch3,cache server\n'
        'admin_panel,superadmin,Adm1n_P@n3l!,web administration\n'
        'aws,iam_deploy,AWS_D3pl0y_K3y,deployment service\n'
        'monitoring,grafana_admin,Gr@f@n@_2024,monitoring dashboard\n'
    ),
    '/scripts/deploy.sh': (
        '#!/bin/bash\n'
        '# Production deployment script\n'
        'set -e\n\n'
        'SERVER="prod-server-01.internal"\n'
        'DEPLOY_USER="deploy"\n'
        'DEPLOY_KEY="/private/ssh_keys/deploy_key"\n\n'
        'echo "Deploying to production..."\n'
        'ssh -i $DEPLOY_KEY $DEPLOY_USER@$SERVER "cd /opt/app && git pull && systemctl restart app"\n'
        'echo "Deploy complete"\n'
    ),
}

# Generate fake directory listing
def generate_listing(path):
    """Generate realistic FTP directory listing."""
    dir_info = FTP_FILESYSTEM.get(path)
    if not dir_info:
        return ''

    lines = []
    for item in dir_info['contents']:
        full_path = f"{path}/{item}" if path != '/' else f"/{item}"
        if full_path in FTP_FILESYSTEM:
            lines.append(f"drwxr-xr-x   2 admin admin     4096 Jan 15 10:30 {item}")
        elif '.' in item:
            # File sizes vary
            sizes = {'sql.gz': 15728640, '.tar.gz': 52428800, '.csv': 2048,
                    '.conf': 1024, '.yml': 512, '.txt': 256, '.sh': 1536,
                    '.log': 4096000, '.html': 8192, '.xlsx': 65536, '.db': 1048576}
            size = 1024
            for ext, s in sizes.items():
                if item.endswith(ext):
                    size = s
                    break
            lines.append(f"-rw-r--r--   1 admin admin  {size:>8} Jan 15 10:30 {item}")
        else:
            lines.append(f"drwxr-xr-x   2 admin admin     4096 Jan 15 10:30 {item}")

    return '\r\n'.join(lines) + '\r\n'


class FTPHoneypot(BaseHoneypot):
    """FTP Honeypot with fake filesystem and file content traps."""

    def __init__(self, app=None, port=2121):
        super().__init__(service_type='ftp', port=port, app=app)
        self.banner = '220 ProFTPD 1.3.5 Server (Corporate FTP) [::ffff:192.168.1.100]'

    def handle_client(self, client_socket, client_address):
        """Handle incoming FTP connection."""
        client_ip = client_address[0]
        client_port = client_address[1]
        authenticated = False
        current_user = None
        current_dir = '/'
        rename_from = None

        self.log_attack(
            source_ip=client_ip,
            source_port=client_port,
            action='connection',
            details=json.dumps({'event': 'new_ftp_connection'}),
            severity='low'
        )

        try:
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

                # --- FTP Command Handling ---
                if cmd == 'USER':
                    current_user = args
                    client_socket.sendall(f'331 Password required for {args}\r\n'.encode())

                elif cmd == 'PASS':
                    self.log_attack(
                        source_ip=client_ip,
                        source_port=client_port,
                        action='login_attempt',
                        details=json.dumps({'username': current_user, 'password': args}),
                        username_attempted=current_user,
                        password_attempted=args,
                        severity='high'
                    )
                    # Accept all credentials (honeytrap)
                    authenticated = True
                    client_socket.sendall(b'230 User logged in.\r\n')

                elif cmd == 'SYST':
                    client_socket.sendall(b'215 UNIX Type: L8\r\n')

                elif cmd == 'FEAT':
                    client_socket.sendall(b'211-Features:\r\n PASV\r\n UTF8\r\n SIZE\r\n211 End\r\n')

                elif cmd == 'PWD' or cmd == 'XPWD':
                    client_socket.sendall(f'257 "{current_dir}" is current directory.\r\n'.encode())

                elif cmd == 'CWD' or cmd == 'XCWD':
                    target = self._resolve_ftp_path(current_dir, args)
                    if target in FTP_FILESYSTEM:
                        current_dir = target
                        self.log_attack(
                            source_ip=client_ip,
                            action='directory_change',
                            details=json.dumps({'directory': target, 'from': current_dir}),
                            severity='medium'
                        )
                        client_socket.sendall(b'250 Directory successfully changed.\r\n')
                    else:
                        client_socket.sendall(f'550 {args}: No such directory\r\n'.encode())

                elif cmd == 'CDUP':
                    parts = current_dir.rsplit('/', 1)
                    current_dir = parts[0] if parts[0] else '/'
                    client_socket.sendall(b'250 Directory successfully changed.\r\n')

                elif cmd == 'LIST' or cmd == 'NLST' or cmd == 'MLSD':
                    target_dir = current_dir
                    if args and not args.startswith('-'):
                        target_dir = self._resolve_ftp_path(current_dir, args)

                    self.log_attack(
                        source_ip=client_ip,
                        action='directory_listing',
                        details=json.dumps({'command': cmd, 'path': target_dir}),
                        severity='medium'
                    )
                    listing = generate_listing(target_dir)
                    client_socket.sendall(b'150 Opening ASCII mode data connection.\r\n')
                    # In a real implementation we'd use data channel
                    # Here we just indicate transfer complete
                    client_socket.sendall(b'226 Transfer complete.\r\n')

                elif cmd == 'RETR':
                    filepath = self._resolve_ftp_path(current_dir, args)
                    self.log_attack(
                        source_ip=client_ip,
                        action='file_download',
                        details=json.dumps({
                            'filename': args,
                            'full_path': filepath,
                            'file_exists': filepath in FTP_FILE_CONTENTS
                        }),
                        severity='critical'
                    )
                    if filepath in FTP_FILE_CONTENTS:
                        # Serve the fake file content
                        client_socket.sendall(b'150 Opening data connection.\r\n')
                        client_socket.sendall(b'226 Transfer complete.\r\n')
                    else:
                        client_socket.sendall(b'550 File not found.\r\n')

                elif cmd == 'STOR':
                    self.log_attack(
                        source_ip=client_ip,
                        action='file_upload',
                        details=json.dumps({
                            'filename': args,
                            'target_dir': current_dir,
                            'full_path': self._resolve_ftp_path(current_dir, args)
                        }),
                        severity='critical'
                    )
                    client_socket.sendall(b'150 Opening data connection.\r\n')
                    # Simulate accepting upload
                    client_socket.sendall(b'226 Transfer complete.\r\n')

                elif cmd == 'DELE':
                    self.log_attack(
                        source_ip=client_ip,
                        action='file_delete',
                        details=json.dumps({'filename': args, 'path': current_dir}),
                        severity='critical'
                    )
                    client_socket.sendall(b'250 File deleted.\r\n')

                elif cmd == 'MKD' or cmd == 'XMKD':
                    self.log_attack(
                        source_ip=client_ip,
                        action='mkdir',
                        details=json.dumps({'directory': args}),
                        severity='high'
                    )
                    client_socket.sendall(f'257 "{args}" created.\r\n'.encode())

                elif cmd == 'RMD' or cmd == 'XRMD':
                    self.log_attack(
                        source_ip=client_ip,
                        action='rmdir',
                        details=json.dumps({'directory': args}),
                        severity='critical'
                    )
                    client_socket.sendall(b'250 Directory removed.\r\n')

                elif cmd == 'RNFR':
                    rename_from = args
                    client_socket.sendall(b'350 Ready for RNTO.\r\n')

                elif cmd == 'RNTO':
                    self.log_attack(
                        source_ip=client_ip,
                        action='file_rename',
                        details=json.dumps({'from': rename_from, 'to': args}),
                        severity='high'
                    )
                    client_socket.sendall(b'250 Rename successful.\r\n')
                    rename_from = None

                elif cmd == 'SIZE':
                    filepath = self._resolve_ftp_path(current_dir, args)
                    if filepath in FTP_FILE_CONTENTS:
                        size = len(FTP_FILE_CONTENTS[filepath])
                        client_socket.sendall(f'213 {size}\r\n'.encode())
                    else:
                        client_socket.sendall(b'550 File not found.\r\n')

                elif cmd == 'TYPE':
                    client_socket.sendall(b'200 Type set.\r\n')

                elif cmd == 'PASV':
                    client_socket.sendall(b'227 Entering Passive Mode (192,168,1,100,40,1).\r\n')

                elif cmd == 'EPSV':
                    client_socket.sendall(b'229 Entering Extended Passive Mode (|||10240|)\r\n')

                elif cmd == 'PORT':
                    client_socket.sendall(b'200 PORT command successful.\r\n')

                elif cmd == 'NOOP':
                    client_socket.sendall(b'200 NOOP ok.\r\n')

                elif cmd == 'QUIT':
                    client_socket.sendall(b'221 Goodbye.\r\n')
                    break

                elif cmd == 'SITE':
                    self.log_attack(
                        source_ip=client_ip,
                        action='site_command',
                        details=json.dumps({'args': args}),
                        severity='high'
                    )
                    client_socket.sendall(b'200 SITE command OK.\r\n')

                else:
                    client_socket.sendall(f'502 Command not implemented: {cmd}\r\n'.encode())

        except Exception as e:
            self.logger.error(f"FTP honeypot error handling {client_ip}: {e}")
        finally:
            client_socket.close()

    def _resolve_ftp_path(self, current_dir, path):
        """Resolve relative/absolute FTP path."""
        if not path:
            return current_dir
        if path.startswith('/'):
            return path.rstrip('/')
        if path == '..':
            parts = current_dir.rsplit('/', 1)
            return parts[0] if parts[0] else '/'
        if path == '.':
            return current_dir
        result = f"{current_dir}/{path}" if current_dir != '/' else f"/{path}"
        return result.rstrip('/')

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
