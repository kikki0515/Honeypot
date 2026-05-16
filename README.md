# HaaS - AI-Powered Distributed Threat Intelligence Platform

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-green?style=for-the-badge&logo=flask)
![Redis](https://img.shields.io/badge/Redis-7-red?style=for-the-badge&logo=redis)
![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=for-the-badge&logo=docker)
![License](https://img.shields.io/badge/License-Educational-purple?style=for-the-badge)

**A next-generation honeypot-as-a-service platform with AI-powered attack classification, real-time threat intelligence, distributed agent support, and automated alerting.**

</div>

---

## Overview

This platform transforms traditional honeypots into an enterprise-grade cybersecurity deception and threat intelligence system. It deploys simulated SSH, HTTP, and FTP services that attract and analyze malicious activity using machine learning classification, behavioral anomaly detection, and automated threat scoring.

Built as a university project demonstrating advanced concepts in:
- Network security monitoring
- AI/ML-based threat detection
- Distributed systems architecture
- Real-time data processing

---

## Key Features

### AI Analysis Engine
- **12-category attack classification** (brute force, SQL injection, XSS, command injection, etc.)
- **Composite threat scoring** (0-10 scale with weighted factors)
- **Behavioral anomaly detection** (rate, temporal, multi-protocol, new-attacker analysis)
- **Attacker fingerprinting** and campaign correlation
- **Human-readable AI summaries** for every attack

### Advanced Honeypots
- **SSH**: Full fake interactive shell, filesystem navigation, 15+ bash commands, trap credentials
- **HTTP**: Fake WordPress/phpMyAdmin/cPanel panels, scanner detection (SQLMap, Nikto, Nmap, Burp), hidden trap routes
- **FTP**: Realistic filesystem with fake sensitive documents, upload/download tracking

### Threat Intelligence
- **GeoIP enrichment** (country, city, ASN, ISP)
- **IP reputation scoring** via AbuseIPDB and VirusTotal integration
- **Campaign detection** for coordinated attacks
- **Threat intelligence caching** in database

### Distributed Architecture
- **Remote agent registration** with API key authentication
- **Centralized attack collection** from multiple nodes
- **Heartbeat monitoring** with automatic offline detection
- **Node management** via REST API

### Real-Time Dashboard
- Modern cyberpunk/security-themed UI (TailwindCSS)
- Live AI threat feed via WebSocket
- Attack trend charts (Chart.js)
- AI classification breakdown
- Real-time notifications for critical events

### Multi-Channel Alerting
- **Telegram** bot notifications
- **Discord** webhook with rich embeds
- **Email** alerts via SMTP
- Triggered on critical attacks, campaigns, and anomalies

### Async Processing
- **Celery** + **Redis** for background task processing
- Non-blocking AI analysis, GeoIP lookups, and reputation checks
- Scalable worker architecture

### Docker Deployment
- Full `docker-compose.yml` with Flask, PostgreSQL, Redis, Nginx, Celery worker
- Production-ready Nginx reverse proxy with rate limiting and WebSocket support
- Single-command deployment

---

## Architecture

```
                    Internet
                       |
         +-------------+-------------+
         |             |             |
    SSH :2222     HTTP :8080    FTP :2121
         |             |             |
         +-------------+-------------+
                       |
              Honeypot Manager
                       |
         +-------------+-------------+
         |                           |
    AI Analysis Engine      GeoIP + Reputation
    - Classifier                - MaxMind GeoLite2
    - Threat Scorer             - AbuseIPDB
    - Anomaly Detector          - VirusTotal
    - Summarizer                - IP Caching
         |                           |
         +-------------+-------------+
                       |
              SQLAlchemy Database
              (SQLite / PostgreSQL)
                       |
         +-------------+-------------+
         |             |             |
    REST API     Socket.IO     Celery Workers
         |        (real-time)    (async tasks)
         |             |             |
         +-------------+-------------+
                       |
              Web Dashboard
              (TailwindCSS + Chart.js)
                       |
         +-------------+-------------+
         |             |             |
    Telegram      Discord       Email
    Alerts        Webhooks      SMTP
```

---

## Project Structure

```
Honeypot/
├── app/
│   ├── __init__.py              # Flask app factory with service initialization
│   ├── models.py                # SQLAlchemy models (8 models)
│   ├── ai/
│   │   ├── __init__.py
│   │   ├── analyzer.py          # Central AI orchestrator
│   │   ├── classifier.py        # 12-category attack classifier
│   │   ├── scoring.py           # Weighted threat scoring engine
│   │   ├── anomaly.py           # Statistical anomaly detector
│   │   └── summarizer.py        # Human-readable summary generator
│   ├── honeypots/
│   │   ├── __init__.py
│   │   ├── base.py              # Base class with AI integration
│   │   ├── ssh_honeypot.py      # SSH with fake shell
│   │   ├── http_honeypot.py     # HTTP with fake panels + scanner detection
│   │   ├── ftp_honeypot.py      # FTP with fake filesystem
│   │   └── manager.py           # Service orchestration
│   ├── intel/
│   │   ├── __init__.py
│   │   ├── geoip.py             # GeoIP lookup (MaxMind + fallback)
│   │   └── reputation.py        # IP reputation (AbuseIPDB, VirusTotal)
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── manager.py           # Distributed agent management
│   │   └── client.py            # Remote agent client
│   ├── alerts/
│   │   ├── __init__.py
│   │   └── dispatcher.py        # Multi-channel alert dispatcher
│   ├── tasks/
│   │   ├── __init__.py
│   │   ├── celery_app.py        # Celery configuration
│   │   └── analysis_tasks.py    # Background analysis tasks
│   └── routes/
│       ├── __init__.py
│       ├── auth.py              # Authentication (login/register/logout)
│       ├── api.py               # REST API (attacks, stats, AI, campaigns, geo)
│       ├── dashboard.py         # Dashboard page routes
│       └── agents.py            # Agent registration/reporting API
├── templates/                   # Jinja2 HTML templates
├── static/                      # CSS + JavaScript (TailwindCSS, Chart.js)
├── config.py                    # Multi-environment configuration
├── run.py                       # Application entry point
├── requirements.txt             # Python dependencies
├── Dockerfile                   # Container build
├── docker-compose.yml           # Full stack deployment
├── nginx.conf                   # Nginx reverse proxy config
├── .env.example                 # Environment variables template
└── .gitignore
```

---

## Installation

### Option 1: Local Development

**Prerequisites:** Python 3.9+, pip

```bash
# Clone
git clone https://github.com/kikki0515/Honeypot.git
cd Honeypot

# Virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Configure (optional)
cp .env.example .env
# Edit .env with your API keys and settings

# Run
python run.py
```

Access dashboard at **http://localhost:5000** — register an account to get started.

### Option 2: Docker Deployment

**Prerequisites:** Docker, Docker Compose

```bash
# Clone
git clone https://github.com/kikki0515/Honeypot.git
cd Honeypot

# Configure
cp .env.example .env
# Edit .env with your settings

# Deploy
docker-compose up -d

# View logs
docker-compose logs -f app
```

Services:
- Web Dashboard: `http://localhost:80` (via Nginx)
- SSH Honeypot: port `2222`
- HTTP Honeypot: port `8080`
- FTP Honeypot: port `2121`

---

## Configuration

All configuration is via environment variables (`.env` file):

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | auto | Flask session secret |
| `DATABASE_URL` | `sqlite:///honeypot.db` | Database URI |
| `FLASK_CONFIG` | `default` | Config profile (development/production/docker) |

### Honeypot Ports

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_HONEYPOT_PORT` | `2222` | SSH service port |
| `HTTP_HONEYPOT_PORT` | `8080` | HTTP service port |
| `FTP_HONEYPOT_PORT` | `2121` | FTP service port |
| `WEB_PORT` | `5000` | Dashboard port |

### AI & Intelligence

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_ENABLED` | `true` | Enable AI analysis |
| `GEOIP_ENABLED` | `true` | Enable GeoIP lookups |
| `THREAT_INTEL_ENABLED` | `true` | Enable reputation checks |
| `ABUSEIPDB_API_KEY` | (empty) | AbuseIPDB API key |
| `VIRUSTOTAL_API_KEY` | (empty) | VirusTotal API key |

### Alerting

| Variable | Default | Description |
|----------|---------|-------------|
| `ALERTING_ENABLED` | `true` | Enable alert system |
| `TELEGRAM_BOT_TOKEN` | (empty) | Telegram bot token |
| `TELEGRAM_CHAT_ID` | (empty) | Telegram chat ID |
| `DISCORD_WEBHOOK_URL` | (empty) | Discord webhook URL |
| `SMTP_SERVER` | `smtp.gmail.com` | SMTP server |
| `SMTP_USERNAME` | (empty) | SMTP login |
| `SMTP_PASSWORD` | (empty) | SMTP password |
| `ALERT_EMAIL_TO` | (empty) | Alert recipient email |

### Redis & Celery

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection |
| `CELERY_BROKER_URL` | `redis://localhost:6379/1` | Celery broker |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/2` | Celery results |

---

## AI Classification Categories

| Category | Description | Severity |
|----------|-------------|----------|
| `brute_force` | Credential brute-force attacks | High |
| `sql_injection` | SQL injection payloads | Critical |
| `command_injection` | OS command injection | Critical |
| `xss_attack` | Cross-site scripting | High |
| `path_traversal` | Directory traversal | High |
| `web_scanning` | Automated vulnerability scanning | High |
| `credential_stuffing` | Testing leaked credentials | High |
| `data_exfiltration` | Attempting to steal data | Critical |
| `malware_delivery` | Uploading malicious files | Critical |
| `api_abuse` | API endpoint fuzzing | Medium |
| `reconnaissance` | Information gathering | Low |
| `dos_attempt` | Denial of service | Medium |

---

## Threat Scoring

Each attack receives a composite score (0-10) based on:

| Factor | Weight | Description |
|--------|--------|-------------|
| Severity | 25% | Base severity level |
| Sophistication | 20% | Attack complexity |
| Frequency | 15% | Attack rate from source |
| Target Value | 15% | Value of targeted resource |
| Persistence | 10% | Attacker persistence over time |
| Evasion | 10% | Evasion technique usage |
| Campaign | 5% | Part of coordinated campaign |

**Risk Levels:** Critical (8.5+), High (6.5+), Medium (4.0+), Low (<4.0)

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/attacks` | GET | Attack logs with filtering/pagination |
| `/api/attacks/recent` | GET | Most recent attacks |
| `/api/stats` | GET | Dashboard statistics + AI stats |
| `/api/services` | GET | Honeypot service status |
| `/api/services/<type>/toggle` | POST | Start/stop a service |
| `/api/ai/threats` | GET | AI threat intelligence summary |
| `/api/ai/ip/<ip>` | GET | Full IP analysis (attacks, intel, AI) |
| `/api/campaigns` | GET | Detected attack campaigns |
| `/api/geo/heatmap` | GET | Geographic attack data |
| `/api/alerts/history` | GET | Alert history |
| `/api/agents/` | GET | List registered agents |
| `/api/agents/register` | POST | Register new agent |
| `/api/agents/<id>/heartbeat` | POST | Agent heartbeat |
| `/api/agents/<id>/report` | POST | Report attack from agent |

---

## Real-Time WebSocket Events

| Event | Direction | Description |
|-------|-----------|-------------|
| `new_attack` | Server→Client | New attack detected |
| `ai_alert` | Server→Client | High-threat AI alert |
| `anomaly_detected` | Server→Client | Anomaly detected |
| `campaign_detected` | Server→Client | Campaign identified |
| `threat_detected` | Server→Client | General threat event |
| `alert_triggered` | Server→Client | Alert notification sent |
| `service_status` | Server→Client | Service state change |
| `agent_heartbeat` | Server→Client | Agent status update |

---

## Technology Stack

| Layer | Technologies |
|-------|-------------|
| **Backend** | Python 3.11, Flask 3.0, SQLAlchemy, Paramiko |
| **AI/ML** | scikit-learn, numpy, pandas |
| **Real-time** | Flask-SocketIO, WebSocket |
| **Async** | Celery, Redis |
| **Database** | SQLite (dev), PostgreSQL (prod) |
| **Frontend** | TailwindCSS, Chart.js, Font Awesome 6 |
| **Infrastructure** | Docker, Nginx, docker-compose |
| **Security** | Flask-Login, Flask-Limiter, Flask-Talisman |
| **Threat Intel** | AbuseIPDB, VirusTotal, MaxMind GeoLite2 |

---

## Security Considerations

> **WARNING**: This is a research/educational tool. Deploy responsibly.

- Run honeypots on non-standard ports to avoid conflicts
- Deploy in an isolated network, VM, or container
- Never expose the web dashboard without authentication
- Use strong `SECRET_KEY` in production
- Monitor system resources — honeypots can attract heavy traffic
- Rotate API keys and credentials regularly
- Enable rate limiting in production (`RATE_LIMIT_ENABLED=true`)

---

## Screenshots

The dashboard features:
- Dark cyberpunk/security theme
- Real-time AI threat feed (terminal-style)
- Attack trend visualization
- AI classification breakdown charts
- Service management cards
- Attack log table with GeoIP and threat scores

---

## Running Celery Workers (Optional)

For async processing (requires Redis):

```bash
# Start Redis
redis-server

# Start Celery worker
celery -A app.tasks.celery_app:celery_app worker --loglevel=info --concurrency=4
```

---

## Distributed Agent Setup

To deploy a remote honeypot node that reports to the central server:

```python
from app.agents.client import AgentClient

# Initialize client
client = AgentClient(central_url='https://your-central-server.com')

# Register
result = client.register(
    name='Node-Tokyo-01',
    hostname='honeypot-jp.example.com',
    location='Tokyo, Japan'
)

# Start heartbeat
client.start()

# Report attacks
client.report_attack({
    'source_ip': '1.2.3.4',
    'honeypot_type': 'ssh',
    'action': 'login_attempt',
    'severity': 'high'
})
```

---

## License

This project is developed for educational purposes as part of a university cybersecurity course.

---

## Author

University Project — Cybersecurity & Network Security Research
