"""SSH Honeypot - Simulates an SSH server with fake shell and filesystem.

Enhanced with:
- Fake interactive shell with command tracking
- Fake filesystem navigation
- Command replay logging
- Realistic credential acceptance (honeytrap)
"""

import socket
import threading
import paramiko
import json
import os
from datetime import datetime

from app.honeypots.base import BaseHoneypot


# Generate RSA host key for the SSH server
HOST_KEY = paramiko.RSAKey.generate(2048)

# Fake filesystem structure
FAKE_FILESYSTEM = {
    '/': ['bin', 'etc', 'home', 'var', 'tmp', 'usr', 'root', 'opt'],
    '/etc': ['passwd', 'shadow', 'hosts', 'ssh', 'nginx', 'mysql'],
    '/etc/ssh': ['sshd_config', 'ssh_host_rsa_key'],
    '/home': ['admin', 'user', 'deploy', 'backup'],
    '/home/admin': ['.bash_history', '.ssh', 'scripts', 'notes.txt'],
    '/home/admin/.ssh': ['authorized_keys', 'id_rsa', 'known_hosts'],
    '/var': ['log', 'www', 'lib', 'backups'],
    '/var/log': ['auth.log', 'syslog', 'apache2', 'mysql'],
    '/var/www': ['html', 'app'],
    '/var/backups': ['db_dump_2024.sql.gz', 'config_backup.tar.gz'],
    '/root': ['.bash_history', '.ssh', 'credentials.txt', 'deploy.sh'],
    '/tmp': ['sess_a8f3d2', '.hidden_script.sh'],
    '/opt': ['app', 'monitoring'],
}

# Fake file contents
FAKE_FILE_CONTENTS = {
    '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nadmin:x:1000:1000:Admin User:/home/admin:/bin/bash\nmysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false\n',
    '/etc/hosts': '127.0.0.1 localhost\n192.168.1.10 db-server\n192.168.1.20 web-server\n192.168.1.30 backup-server\n',
    '/root/credentials.txt': '# Server Credentials\nDB_HOST=192.168.1.10\nDB_USER=admin\nDB_PASS=S3cur3P@ss!\nAWS_KEY=FAKEKEYID0000EXAMPLE\nAWS_SECRET=FakeSecret/XXXXXXXXXXXXXXXX\n',
    '/home/admin/notes.txt': 'TODO:\n- Update firewall rules\n- Rotate database credentials\n- Deploy new version to production\n- Check backup status on 192.168.1.30\n',
    '/root/deploy.sh': '#!/bin/bash\n# Deploy script\ncd /opt/app\ngit pull origin main\npip install -r requirements.txt\nsystemctl restart app\necho "Deploy complete"\n',
}

# Trap credentials that "work"
TRAP_CREDENTIALS = [
    ('admin', 'admin123'),
    ('root', 'toor'),
    ('user', 'password'),
    ('deploy', 'deploy2024'),
]


class SSHServerInterface(paramiko.ServerInterface):
    """Paramiko server interface with honeytrap authentication."""

    def __init__(self, client_ip, honeypot):
        self.client_ip = client_ip
        self.honeypot = honeypot
        self.event = threading.Event()
        self.authenticated_user = None

    def check_auth_password(self, username, password):
        """Log authentication attempts - accept trap credentials."""
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

        # Accept trap credentials to observe post-auth behavior
        for trap_user, trap_pass in TRAP_CREDENTIALS:
            if username == trap_user and password == trap_pass:
                self.authenticated_user = username
                self.honeypot.log_attack(
                    source_ip=self.client_ip,
                    action='successful_login_trap',
                    details=json.dumps({
                        'username': username,
                        'trap': True
                    }),
                    username_attempted=username,
                    severity='critical'
                )
                return paramiko.AUTH_SUCCESSFUL

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

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        self.event.set()
        return True


class FakeShell:
    """Simulates an interactive bash shell with command tracking."""

    def __init__(self, honeypot, client_ip, username):
        self.honeypot = honeypot
        self.client_ip = client_ip
        self.username = username
        self.cwd = f'/home/{username}' if username != 'root' else '/root'
        self.commands_executed = []
        self.hostname = 'prod-server-01'

    def get_prompt(self):
        """Generate shell prompt."""
        user_symbol = '#' if self.username == 'root' else '$'
        short_cwd = self.cwd if self.cwd != f'/home/{self.username}' else '~'
        return f"{self.username}@{self.hostname}:{short_cwd}{user_symbol} "

    def execute(self, command):
        """Execute a fake command and return output."""
        command = command.strip()
        if not command:
            return ''

        self.commands_executed.append(command)

        # Log the command
        self.honeypot.log_attack(
            source_ip=self.client_ip,
            action='shell_command',
            details=json.dumps({
                'command': command,
                'cwd': self.cwd,
                'username': self.username,
                'command_number': len(self.commands_executed)
            }),
            username_attempted=self.username,
            severity='critical'
        )

        # Parse and respond
        parts = command.split()
        cmd = parts[0] if parts else ''
        args = parts[1:] if len(parts) > 1 else []

        handlers = {
            'ls': self._cmd_ls,
            'cd': self._cmd_cd,
            'pwd': self._cmd_pwd,
            'cat': self._cmd_cat,
            'whoami': self._cmd_whoami,
            'id': self._cmd_id,
            'uname': self._cmd_uname,
            'hostname': self._cmd_hostname,
            'ifconfig': self._cmd_ifconfig,
            'ip': self._cmd_ip,
            'ps': self._cmd_ps,
            'wget': self._cmd_wget,
            'curl': self._cmd_curl,
            'chmod': self._cmd_chmod,
            'echo': self._cmd_echo,
            'history': self._cmd_history,
            'exit': self._cmd_exit,
            'logout': self._cmd_exit,
            'w': self._cmd_w,
            'last': self._cmd_last,
            'netstat': self._cmd_netstat,
            'ss': self._cmd_netstat,
        }

        handler = handlers.get(cmd)
        if handler:
            return handler(args)
        else:
            # Unknown command
            return f"-bash: {cmd}: command not found\n"

    def _cmd_ls(self, args):
        path = self.cwd
        if args and not args[0].startswith('-'):
            path = self._resolve_path(args[-1])

        contents = FAKE_FILESYSTEM.get(path, [])
        if not contents:
            return f"ls: cannot access '{path}': No such file or directory\n"

        if '-la' in ' '.join(args) or '-l' in args:
            output = f"total {len(contents) * 4}\n"
            for item in contents:
                if item.startswith('.'):
                    perm = 'drwx------'
                elif '.' in item:
                    perm = '-rw-r--r--'
                else:
                    perm = 'drwxr-xr-x'
                output += f"{perm}  1 root root  4096 Jan 15 10:30 {item}\n"
            return output
        else:
            return '  '.join(contents) + '\n'

    def _cmd_cd(self, args):
        if not args:
            self.cwd = f'/home/{self.username}' if self.username != 'root' else '/root'
            return ''
        target = self._resolve_path(args[0])
        if target in FAKE_FILESYSTEM:
            self.cwd = target
            return ''
        return f"-bash: cd: {args[0]}: No such file or directory\n"

    def _cmd_pwd(self, args):
        return self.cwd + '\n'

    def _cmd_cat(self, args):
        if not args:
            return ''
        filepath = self._resolve_path(args[0])
        content = FAKE_FILE_CONTENTS.get(filepath)
        if content:
            return content + '\n'
        return f"cat: {args[0]}: No such file or directory\n"

    def _cmd_whoami(self, args):
        return self.username + '\n'

    def _cmd_id(self, args):
        if self.username == 'root':
            return 'uid=0(root) gid=0(root) groups=0(root)\n'
        return f'uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo)\n'

    def _cmd_uname(self, args):
        if '-a' in args:
            return 'Linux prod-server-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n'
        return 'Linux\n'

    def _cmd_hostname(self, args):
        return self.hostname + '\n'

    def _cmd_ifconfig(self, args):
        return ('eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n'
                '        inet 192.168.1.50  netmask 255.255.255.0  broadcast 192.168.1.255\n'
                '        inet6 fe80::a00:27ff:fe8d:c04d  prefixlen 64  scopeid 0x20<link>\n'
                '        ether 08:00:27:8d:c0:4d  txqueuelen 1000  (Ethernet)\n\n')

    def _cmd_ip(self, args):
        if args and args[0] == 'addr':
            return self._cmd_ifconfig(args)
        return 'Usage: ip [ OPTIONS ] OBJECT { COMMAND }\n'

    def _cmd_ps(self, args):
        return ('  PID TTY          TIME CMD\n'
                '    1 ?        00:00:05 systemd\n'
                '  234 ?        00:00:01 sshd\n'
                '  567 ?        00:00:03 nginx\n'
                '  890 ?        00:00:12 python3\n'
                ' 1234 ?        00:00:00 mysql\n'
                f' {os.getpid()} pts/0    00:00:00 bash\n')

    def _cmd_wget(self, args):
        if args:
            self.honeypot.log_attack(
                source_ip=self.client_ip,
                action='malware_download_attempt',
                details=json.dumps({'url': args[0], 'command': f'wget {" ".join(args)}'}),
                severity='critical'
            )
        return f"--2024-01-15 10:30:00--  {args[0] if args else ''}\nResolving... failed: Name or service not known.\n"

    def _cmd_curl(self, args):
        if args:
            url = args[-1] if not args[-1].startswith('-') else args[0]
            self.honeypot.log_attack(
                source_ip=self.client_ip,
                action='curl_attempt',
                details=json.dumps({'url': url, 'command': f'curl {" ".join(args)}'}),
                severity='high'
            )
        return 'curl: (6) Could not resolve host\n'

    def _cmd_chmod(self, args):
        return ''

    def _cmd_echo(self, args):
        return ' '.join(args) + '\n'

    def _cmd_history(self, args):
        output = ''
        for i, cmd in enumerate(self.commands_executed[-20:], 1):
            output += f'  {i}  {cmd}\n'
        return output

    def _cmd_exit(self, args):
        return '__EXIT__'

    def _cmd_w(self, args):
        return (' 10:30:00 up 45 days, 3:21,  1 user,  load average: 0.15, 0.10, 0.05\n'
                'USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n'
                f'{self.username}  pts/0    {self.client_ip}  10:30    0.00s  0.01s  0.00s w\n')

    def _cmd_last(self, args):
        return (f'{self.username}  pts/0        {self.client_ip}  Mon Jan 15 10:30   still logged in\n'
                'admin    pts/1        10.0.0.5         Sun Jan 14 09:00 - 17:30  (08:30)\n'
                'reboot   system boot  5.15.0-91-generi Mon Jan  8 06:00   still running\n')

    def _cmd_netstat(self, args):
        return ('Active Internet connections (servers and established)\n'
                'Proto Recv-Q Send-Q Local Address           Foreign Address         State\n'
                'tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n'
                'tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n'
                'tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN\n'
                f'tcp        0      0 192.168.1.50:22         {self.client_ip}:54321   ESTABLISHED\n')

    def _resolve_path(self, path):
        """Resolve a relative path to absolute."""
        if path.startswith('/'):
            return path.rstrip('/')
        elif path == '..':
            parts = self.cwd.rsplit('/', 1)
            return parts[0] if parts[0] else '/'
        elif path == '.':
            return self.cwd
        else:
            return f"{self.cwd}/{path}".rstrip('/')


class SSHHoneypot(BaseHoneypot):
    """SSH Honeypot with fake interactive shell."""

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

            # Wait for channel
            channel = transport.accept(timeout=30)
            if channel is None:
                return

            # If authenticated, provide fake shell
            if server.authenticated_user:
                server.event.wait(10)
                self._run_fake_shell(channel, client_ip, server.authenticated_user)
            else:
                channel.close()

        except Exception as e:
            self.logger.error(f"SSH honeypot error handling {client_ip}: {e}")
        finally:
            try:
                transport.close()
            except Exception:
                pass
            client_socket.close()

    def _run_fake_shell(self, channel, client_ip, username):
        """Run the fake interactive shell session."""
        shell = FakeShell(self, client_ip, username)

        try:
            channel.send(f"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n")
            channel.send(f" * Documentation:  https://help.ubuntu.com\n")
            channel.send(f" * Management:     https://landscape.canonical.com\n\n")
            channel.send(f"Last login: Mon Jan 15 09:00:00 2024 from 10.0.0.5\n")
            channel.send(shell.get_prompt())

            command_buffer = ''
            while True:
                data = channel.recv(1024)
                if not data:
                    break

                for byte in data:
                    char = chr(byte)
                    if char == '\r' or char == '\n':
                        channel.send('\r\n')
                        output = shell.execute(command_buffer)
                        if output == '__EXIT__':
                            channel.send('logout\n')
                            return
                        if output:
                            channel.send(output)
                        channel.send(shell.get_prompt())
                        command_buffer = ''
                    elif char == '\x7f' or char == '\x08':  # backspace
                        if command_buffer:
                            command_buffer = command_buffer[:-1]
                            channel.send('\x08 \x08')
                    elif char == '\x03':  # Ctrl+C
                        channel.send('^C\r\n')
                        channel.send(shell.get_prompt())
                        command_buffer = ''
                    elif char == '\x04':  # Ctrl+D
                        return
                    else:
                        command_buffer += char
                        channel.send(char)

        except Exception as e:
            self.logger.debug(f"Shell session ended: {e}")
        finally:
            # Log session summary
            if shell.commands_executed:
                self.log_attack(
                    source_ip=client_ip,
                    action='shell_session_end',
                    details=json.dumps({
                        'username': username,
                        'total_commands': len(shell.commands_executed),
                        'commands': shell.commands_executed[-50:],
                        'session_summary': True
                    }),
                    username_attempted=username,
                    severity='critical'
                )
            channel.close()

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
