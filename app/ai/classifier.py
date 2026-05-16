"""Attack Classification Engine.

Classifies attacks into categories using pattern matching and ML-based heuristics.
"""

import json
import re
import hashlib
from collections import defaultdict


# Attack classification taxonomy
ATTACK_CATEGORIES = {
    'brute_force': {
        'description': 'Credential brute-force attack',
        'indicators': ['login_attempt', 'password', 'auth'],
        'protocols': ['ssh', 'ftp']
    },
    'web_scanning': {
        'description': 'Automated web vulnerability scanning',
        'indicators': ['scanner', 'nikto', 'nmap', 'masscan', 'zap'],
        'protocols': ['http']
    },
    'sql_injection': {
        'description': 'SQL injection attack attempt',
        'indicators': ['union', 'select', 'drop', 'insert', '--', 'or 1=1', 'sqlmap'],
        'protocols': ['http']
    },
    'command_injection': {
        'description': 'OS command injection attempt',
        'indicators': [';', '|', '`', '$(', '/bin/', 'cmd.exe', 'powershell'],
        'protocols': ['http']
    },
    'path_traversal': {
        'description': 'Directory/path traversal attack',
        'indicators': ['../', '..\\', '/etc/passwd', '/etc/shadow'],
        'protocols': ['http', 'ftp']
    },
    'credential_stuffing': {
        'description': 'Automated credential testing from leaked databases',
        'indicators': ['rapid_login', 'multiple_users', 'known_passwords'],
        'protocols': ['ssh', 'ftp', 'http']
    },
    'reconnaissance': {
        'description': 'Information gathering and network reconnaissance',
        'indicators': ['connection', 'directory_listing', 'GET /'],
        'protocols': ['ssh', 'http', 'ftp']
    },
    'data_exfiltration': {
        'description': 'Attempt to download or steal data',
        'indicators': ['file_download', 'RETR', 'database', 'backup', 'credentials'],
        'protocols': ['ftp', 'http']
    },
    'malware_delivery': {
        'description': 'Attempt to upload malicious files',
        'indicators': ['file_upload', 'STOR', '.exe', '.php', '.jsp', 'shell'],
        'protocols': ['ftp', 'http']
    },
    'xss_attack': {
        'description': 'Cross-site scripting attack',
        'indicators': ['<script', 'javascript:', 'onerror=', 'onload=', 'alert('],
        'protocols': ['http']
    },
    'api_abuse': {
        'description': 'API endpoint abuse or fuzzing',
        'indicators': ['/api/', 'json', 'graphql', 'rest'],
        'protocols': ['http']
    },
    'dos_attempt': {
        'description': 'Denial of service attempt',
        'indicators': ['flood', 'rapid_connections', 'resource_exhaustion'],
        'protocols': ['ssh', 'http', 'ftp']
    }
}

# Known scanner user agents
SCANNER_SIGNATURES = [
    r'nikto', r'sqlmap', r'nmap', r'masscan', r'dirbuster',
    r'gobuster', r'wfuzz', r'burp', r'zap', r'acunetix',
    r'nessus', r'openvas', r'w3af', r'skipfish', r'arachni',
    r'python-requests', r'go-http-client', r'curl/', r'wget/',
    r'hydra', r'medusa', r'patator', r'metasploit'
]

# Common brute-force passwords (for credential stuffing detection)
COMMON_PASSWORDS = {
    'admin', 'password', '123456', 'root', 'toor', 'admin123',
    'password123', 'letmein', 'qwerty', 'abc123', 'monkey',
    'master', 'dragon', 'login', 'princess', 'solo', 'passw0rd',
    '12345678', 'welcome', 'shadow', '123456789', 'michael',
    'password1', 'superman', '1234567', 'trustno1', 'iloveyou'
}


class AttackClassifier:
    """Classifies attacks based on patterns, behaviors, and heuristics."""

    def __init__(self):
        self.ip_history = defaultdict(list)
        self.scanner_patterns = [re.compile(p, re.IGNORECASE) for p in SCANNER_SIGNATURES]

    def classify(self, attack_data):
        """
        Classify an attack event and return classification results.

        Args:
            attack_data: dict with keys: honeypot_type, action, details, source_ip,
                        username_attempted, password_attempted

        Returns:
            dict with: classification, confidence, sub_categories, indicators_matched
        """
        honeypot_type = attack_data.get('honeypot_type', '')
        action = attack_data.get('action', '')
        details_str = attack_data.get('details', '{}')
        source_ip = attack_data.get('source_ip', '')
        username = attack_data.get('username_attempted', '')
        password = attack_data.get('password_attempted', '')

        try:
            details = json.loads(details_str) if isinstance(details_str, str) else details_str
        except (json.JSONDecodeError, TypeError):
            details = {}

        # Track IP history for pattern detection
        self.ip_history[source_ip].append({
            'action': action,
            'honeypot_type': honeypot_type,
            'details': details
        })

        # Score each category
        scores = {}
        indicators_matched = []

        for category, cat_info in ATTACK_CATEGORIES.items():
            score = 0

            # Protocol match
            if honeypot_type in cat_info['protocols']:
                score += 0.1

            # Indicator matching
            combined_text = f"{action} {details_str} {username} {password}".lower()
            for indicator in cat_info['indicators']:
                if indicator.lower() in combined_text:
                    score += 0.3
                    indicators_matched.append(indicator)

            scores[category] = score

        # Special detection logic
        scores = self._apply_special_rules(
            scores, attack_data, details, indicators_matched
        )

        # Get top classification
        if scores:
            top_category = max(scores, key=scores.get)
            confidence = min(scores[top_category], 1.0)
        else:
            top_category = 'reconnaissance'
            confidence = 0.3

        # Get secondary classifications
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        sub_categories = [
            cat for cat, score in sorted_scores[1:4]
            if score > 0.2
        ]

        return {
            'classification': top_category,
            'confidence': round(confidence, 3),
            'sub_categories': sub_categories,
            'indicators_matched': list(set(indicators_matched)),
            'description': ATTACK_CATEGORIES.get(top_category, {}).get('description', 'Unknown')
        }

    def _apply_special_rules(self, scores, attack_data, details, indicators):
        """Apply special detection rules for enhanced classification."""
        source_ip = attack_data.get('source_ip', '')
        password = attack_data.get('password_attempted', '')
        action = attack_data.get('action', '')
        honeypot_type = attack_data.get('honeypot_type', '')

        # Credential stuffing: known leaked passwords
        if password and password.lower() in COMMON_PASSWORDS:
            scores['credential_stuffing'] = scores.get('credential_stuffing', 0) + 0.4
            indicators.append('known_common_password')

        # Brute force: multiple login attempts from same IP
        ip_actions = self.ip_history.get(source_ip, [])
        login_attempts = sum(1 for a in ip_actions if 'login' in a.get('action', ''))
        if login_attempts > 3:
            scores['brute_force'] = scores.get('brute_force', 0) + 0.5
            indicators.append('repeated_login_attempts')

        # Scanner detection via user agent
        user_agent = details.get('user_agent', '') or details.get('headers', {}).get('User-Agent', '')
        if user_agent:
            for pattern in self.scanner_patterns:
                if pattern.search(user_agent):
                    scores['web_scanning'] = scores.get('web_scanning', 0) + 0.6
                    indicators.append(f'scanner_ua:{pattern.pattern}')
                    break

        # XSS detection
        combined = f"{action} {details.get('body', '')} {details.get('path', '')}".lower()
        xss_patterns = ['<script', 'javascript:', 'onerror', 'onload', 'alert(']
        if any(p in combined for p in xss_patterns):
            scores['xss_attack'] = scores.get('xss_attack', 0) + 0.7
            indicators.append('xss_payload')

        # SQL injection detection
        sqli_patterns = [
            r"(?:'|\")?\s*(?:or|and)\s+[\d\w]+=[\d\w]+",
            r"union\s+(?:all\s+)?select",
            r"(?:insert|update|delete|drop)\s+",
            r";\s*(?:drop|alter|create|exec)",
        ]
        for pattern in sqli_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                scores['sql_injection'] = scores.get('sql_injection', 0) + 0.7
                indicators.append('sqli_pattern')
                break

        return scores

    def generate_fingerprint(self, attack_data):
        """
        Generate an attacker fingerprint based on behavioral patterns.

        Returns a hash that groups similar attackers together.
        """
        source_ip = attack_data.get('source_ip', '')
        details_str = attack_data.get('details', '{}')

        try:
            details = json.loads(details_str) if isinstance(details_str, str) else details_str
        except (json.JSONDecodeError, TypeError):
            details = {}

        # Build fingerprint components
        components = []

        # User agent (for HTTP)
        ua = details.get('user_agent', '') or details.get('headers', {}).get('User-Agent', '')
        if ua:
            components.append(f"ua:{ua[:50]}")

        # Attack patterns from IP history
        ip_actions = self.ip_history.get(source_ip, [])
        action_types = sorted(set(a.get('action', '') for a in ip_actions[-20:]))
        components.append(f"actions:{','.join(action_types[:10])}")

        # Protocol usage
        protocols = sorted(set(a.get('honeypot_type', '') for a in ip_actions))
        components.append(f"protocols:{','.join(protocols)}")

        # Generate hash
        fingerprint_str = '|'.join(components)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]

    def detect_campaign(self, attack_data):
        """
        Detect if an attack is part of a coordinated campaign.

        Returns campaign_id if detected, None otherwise.
        """
        source_ip = attack_data.get('source_ip', '')
        ip_actions = self.ip_history.get(source_ip, [])

        # Campaign indicators:
        # 1. Rapid succession of attacks (>5 in history)
        # 2. Multi-protocol attacks
        # 3. Systematic scanning patterns

        if len(ip_actions) < 5:
            return None

        protocols_used = set(a.get('honeypot_type', '') for a in ip_actions)
        actions_used = set(a.get('action', '') for a in ip_actions)

        is_campaign = (
            len(protocols_used) >= 2 or
            len(ip_actions) >= 10 or
            ('login_attempt' in actions_used and len(ip_actions) >= 5)
        )

        if is_campaign:
            # Generate campaign ID from IP and attack pattern
            campaign_str = f"{source_ip}:{','.join(sorted(protocols_used))}"
            return hashlib.md5(campaign_str.encode()).hexdigest()[:12]

        return None
