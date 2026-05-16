# Honeypot-as-a-Service (HaaS) Platform

A comprehensive cybersecurity research platform that deploys and manages honeypot services to detect, log, and analyze cyber attacks in real-time. Built as a university project to demonstrate network security monitoring and threat intelligence gathering.

## Features

- **Multi-Protocol Honeypots**: SSH, HTTP, and FTP honeypot services that simulate vulnerable servers
- **Real-Time Dashboard**: Live attack monitoring with WebSocket-powered notifications
- **Attack Analytics**: Charts, statistics, and severity classification of detected attacks
- **User Authentication**: Secure login/registration system for dashboard access
- **Service Management**: Start/stop individual honeypot services from the web interface
- **Attack Logging**: Comprehensive logging with filtering, search, and pagination
- **Threat Intelligence**: Top attacker IPs, attack trends, and severity distribution

## Architecture

```
+------------------------------------------+
|          Web Dashboard (Flask)            |
|   - Real-time monitoring (Socket.IO)     |
|   - Charts & Analytics (Chart.js)        |
|   - User Authentication (Flask-Login)    |
+------------------------------------------+
                    |
+------------------------------------------+
|            REST API Layer                 |
|   - Attack logs endpoint                 |
|   - Statistics endpoint                  |
|   - Service management endpoint          |
+------------------------------------------+
                    |
+------------------------------------------+
|         Honeypot Manager                 |
+--------+--------+--------+--------------+
|  SSH   |  HTTP  |  FTP   |   (Port)     |
| :2222  | :8080  | :2121  |              |
+--------+--------+--------+--------------+
                    |
+------------------------------------------+
|        SQLite Database                   |
|   - Attack logs                          |
|   - User accounts                        |
|   - Service status                       |
+------------------------------------------+
```

## Honeypot Services

### SSH Honeypot (Port 2222)
- Simulates an OpenSSH server using Paramiko
- Captures brute-force login attempts (username/password)
- Logs public key authentication attempts
- Records all connection metadata

### HTTP Honeypot (Port 8080)
- Simulates a vulnerable Apache web server
- Detects web scanning and directory enumeration
- Identifies SQL injection and command injection attempts
- Classifies path traversal attacks
- Serves fake login pages and admin panels

### FTP Honeypot (Port 2121)
- Simulates a ProFTPD server
- Captures FTP login credentials
- Logs file access attempts (download/upload/delete)
- Records directory traversal behavior
- Allows "authentication" to observe post-login behavior

## Project Structure

```
Honeypot/
├── app/
│   ├── __init__.py          # Flask app factory
│   ├── models.py            # Database models (User, AttackLog, HoneypotService)
│   ├── honeypots/
│   │   ├── __init__.py
│   │   ├── base.py          # Base honeypot class
│   │   ├── ssh_honeypot.py  # SSH honeypot implementation
│   │   ├── http_honeypot.py # HTTP honeypot implementation
│   │   ├── ftp_honeypot.py  # FTP honeypot implementation
│   │   └── manager.py       # Honeypot service manager
│   └── routes/
│       ├── __init__.py
│       ├── auth.py           # Authentication routes
│       ├── api.py            # REST API endpoints
│       └── dashboard.py      # Dashboard page routes
├── templates/
│   ├── base.html             # Base template
│   ├── auth/
│   │   ├── login.html        # Login page
│   │   └── register.html     # Registration page
│   └── dashboard/
│       ├── index.html        # Main dashboard
│       ├── attacks.html      # Attack logs page
│       ├── services.html     # Service management
│       └── analytics.html    # Analytics page
├── static/
│   ├── css/
│   │   └── style.css         # Main stylesheet
│   └── js/
│       ├── app.js            # WebSocket & notifications
│       ├── dashboard.js      # Dashboard logic
│       ├── attacks.js        # Attack logs logic
│       ├── services.js       # Service management logic
│       └── analytics.js      # Analytics charts
├── logs/                     # Log files directory
├── config.py                 # Configuration settings
├── run.py                    # Application entry point
├── requirements.txt          # Python dependencies
├── .env.example              # Environment variables template
└── .gitignore                # Git ignore rules
```

## Installation

### Prerequisites
- Python 3.9+
- pip (Python package manager)

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/kikki0515/Honeypot.git
   cd Honeypot
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or
   venv\Scripts\activate     # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables** (optional)
   ```bash
   cp .env.example .env
   # Edit .env with your preferred settings
   ```

5. **Run the application**
   ```bash
   python run.py
   ```

6. **Access the dashboard**
   - Open your browser and navigate to: `http://localhost:5000`
   - Register a new account to access the dashboard

## Configuration

Environment variables (set in `.env` file or system environment):

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | auto-generated | Flask session secret key |
| `DATABASE_URL` | `sqlite:///honeypot.db` | Database connection string |
| `SSH_HONEYPOT_PORT` | `2222` | SSH honeypot listening port |
| `HTTP_HONEYPOT_PORT` | `8080` | HTTP honeypot listening port |
| `FTP_HONEYPOT_PORT` | `2121` | FTP honeypot listening port |
| `WEB_PORT` | `5000` | Web dashboard port |
| `FLASK_CONFIG` | `default` | Configuration profile |

## Usage

### Dashboard Overview
The main dashboard provides:
- Total attack count and 24-hour statistics
- Unique attacker IP count
- Active service count
- Real-time attack trend chart
- Attack distribution by protocol
- Recent attacks table
- Top attacking IPs

### Managing Services
Navigate to the **Services** page to:
- View status of each honeypot (running/stopped)
- Start or stop individual services
- Monitor connection counts

### Viewing Attack Logs
The **Attack Logs** page provides:
- Full attack history with timestamp, source IP, type, and severity
- Filter by honeypot type (SSH/HTTP/FTP)
- Filter by severity level (Critical/High/Medium/Low)
- Paginated results

### Analytics
The **Analytics** page shows:
- Severity distribution pie chart
- Attacks by protocol bar chart
- Top attackers ranked table with threat levels

## Severity Classification

| Level | Description | Example |
|-------|-------------|---------|
| **Critical** | Active exploitation attempt | SQL injection, file upload, command injection |
| **High** | Direct attack activity | Brute-force login, path traversal, file download |
| **Medium** | Suspicious behavior | Directory listing, POST requests, scanning |
| **Low** | Reconnaissance | New connections, basic GET requests |

## Technology Stack

- **Backend**: Python, Flask, SQLAlchemy, Paramiko
- **Frontend**: HTML5, CSS3, JavaScript (vanilla)
- **Real-time**: Flask-SocketIO, WebSocket
- **Database**: SQLite
- **Charts**: Chart.js
- **Icons**: Font Awesome 6
- **Authentication**: Flask-Login, Werkzeug password hashing

## Security Considerations

> **WARNING**: This is a research/educational tool. Deploy honeypots with caution.

- Run honeypots on non-standard ports to avoid conflicts with real services
- Deploy in an isolated network or VM
- Never expose the web dashboard to the public internet without authentication
- Monitor system resources as honeypots may attract significant traffic
- Do not use in production environments without proper network segmentation

## License

This project is developed for educational purposes as part of a university cybersecurity course.

## Contributors

- University Project Team
