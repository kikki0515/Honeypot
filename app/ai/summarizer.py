"""Attack Summarizer.

Generates human-readable AI summaries of attack events and patterns.
"""

import json
from datetime import datetime


class AttackSummarizer:
    """Generates intelligent summaries of attack events."""

    TEMPLATES = {
        'brute_force': "Brute-force {protocol} attack from {ip}. Attempted {attempts} credential combinations. {password_info}",
        'sql_injection': "SQL injection attempt targeting {path}. Payload indicates {sophistication} attacker. {tool_info}",
        'command_injection': "Command injection attempt from {ip} via {protocol}. Attempted to execute system commands. Severity: {severity}.",
        'web_scanning': "Automated web scanning detected from {ip}. {tool_info}Scanner probed {paths_count} paths. {classification_info}",
        'path_traversal': "Path traversal attack from {ip}. Attempting to access {target}. {severity_info}",
        'credential_stuffing': "Credential stuffing attack from {ip}. Using {password_type} passwords. {attempts} attempts logged.",
        'reconnaissance': "Reconnaissance activity from {ip} on {protocol} service. Initial probing stage detected.",
        'data_exfiltration': "Data exfiltration attempt from {ip}. Targeting: {target}. Action: {action}.",
        'malware_delivery': "Malware delivery attempt from {ip}. Trying to upload {filename} via {protocol}.",
        'xss_attack': "Cross-site scripting (XSS) attack from {ip}. Injecting JavaScript payload into {target}.",
        'api_abuse': "API abuse/fuzzing from {ip}. Testing endpoints via {method} requests.",
        'dos_attempt': "Potential DoS attempt from {ip}. High rate of {protocol} connections detected."
    }

    def __init__(self):
        pass

    def summarize_attack(self, attack_data, classification=None, threat_score=None):
        """
        Generate a human-readable summary of an attack event.

        Args:
            attack_data: dict with attack details
            classification: dict from classifier
            threat_score: dict from scorer

        Returns:
            str: AI-generated summary text
        """
        source_ip = attack_data.get('source_ip', 'Unknown')
        honeypot_type = attack_data.get('honeypot_type', 'unknown')
        action = attack_data.get('action', '')
        severity = attack_data.get('severity', 'medium')
        username = attack_data.get('username_attempted', '')
        password = attack_data.get('password_attempted', '')
        details_str = attack_data.get('details', '{}')

        try:
            details = json.loads(details_str) if isinstance(details_str, str) else details_str
        except (json.JSONDecodeError, TypeError):
            details = {}

        # Determine classification type
        attack_type = 'reconnaissance'
        if classification:
            attack_type = classification.get('classification', 'reconnaissance')

        # Build template variables
        template_vars = {
            'ip': source_ip,
            'protocol': honeypot_type.upper(),
            'severity': severity,
            'action': action,
            'severity_info': f'Severity level: {severity.upper()}.',
            'attempts': '1',
            'password_info': '',
            'tool_info': '',
            'classification_info': '',
            'sophistication': 'intermediate',
            'path': details.get('path', '/unknown'),
            'paths_count': '1',
            'target': '',
            'filename': '',
            'method': details.get('method', 'GET'),
            'password_type': 'common'
        }

        # Enrich based on available data
        if username:
            template_vars['password_info'] = f'Username: "{username}".'
        if password:
            template_vars['password_info'] += f' Password attempted: "{"*" * min(len(password), 8)}".'

        # User agent / tool detection
        ua = details.get('user_agent', '') or details.get('headers', {}).get('User-Agent', '')
        if ua:
            known_tools = {
                'sqlmap': 'SQLMap',
                'nikto': 'Nikto',
                'nmap': 'Nmap',
                'hydra': 'Hydra',
                'gobuster': 'Gobuster',
                'burp': 'Burp Suite',
                'metasploit': 'Metasploit'
            }
            for key, name in known_tools.items():
                if key in ua.lower():
                    template_vars['tool_info'] = f'Tool detected: {name}. '
                    template_vars['sophistication'] = 'automated'
                    break

        # Target assessment
        if details.get('filename'):
            template_vars['filename'] = details['filename']
            template_vars['target'] = details['filename']
        elif details.get('path'):
            template_vars['target'] = details['path']
        elif details.get('directory'):
            template_vars['target'] = details['directory']

        # Score info
        if threat_score:
            score_val = threat_score.get('score', 0)
            if score_val >= 8:
                template_vars['sophistication'] = 'highly sophisticated'
            elif score_val >= 6:
                template_vars['sophistication'] = 'moderately sophisticated'

        # Classification enrichment
        if classification:
            conf = classification.get('confidence', 0)
            template_vars['classification_info'] = f'Classification confidence: {conf*100:.0f}%.'

        # Generate summary from template
        template = self.TEMPLATES.get(attack_type, self.TEMPLATES['reconnaissance'])
        try:
            summary = template.format(**template_vars)
        except (KeyError, IndexError):
            summary = f"{attack_type.replace('_', ' ').title()} detected from {source_ip} via {honeypot_type.upper()}. Action: {action}. Severity: {severity}."

        # Append threat score if available
        if threat_score:
            score_val = threat_score.get('score', 0)
            risk = threat_score.get('risk_level', 'medium')
            summary += f" Threat score: {score_val}/10 ({risk} risk)."

        return summary.strip()

    def summarize_ip_activity(self, ip_address, attacks):
        """
        Generate a summary of all activity from a specific IP.

        Args:
            ip_address: str IP address
            attacks: list of attack dicts

        Returns:
            str: Summary of IP's attack behavior
        """
        if not attacks:
            return f"No recorded activity from {ip_address}."

        total = len(attacks)
        protocols = set(a.get('honeypot_type', '') for a in attacks)
        severities = [a.get('severity', 'medium') for a in attacks]
        actions = set(a.get('action', '') for a in attacks)

        critical_count = severities.count('critical')
        high_count = severities.count('high')

        summary_parts = [
            f"IP {ip_address}: {total} total attack events detected.",
            f"Protocols targeted: {', '.join(p.upper() for p in protocols)}.",
        ]

        if critical_count > 0:
            summary_parts.append(f"{critical_count} critical-severity events.")
        if high_count > 0:
            summary_parts.append(f"{high_count} high-severity events.")

        if 'login_attempt' in actions:
            login_count = sum(1 for a in attacks if 'login' in a.get('action', ''))
            summary_parts.append(f"Performed {login_count} login attempts.")

        # Determine threat assessment
        if critical_count >= 3 or total >= 20:
            summary_parts.append("Assessment: HIGH THREAT - active exploitation attempts.")
        elif high_count >= 3 or total >= 10:
            summary_parts.append("Assessment: MODERATE THREAT - persistent attacker.")
        else:
            summary_parts.append("Assessment: LOW THREAT - reconnaissance stage.")

        return ' '.join(summary_parts)

    def summarize_campaign(self, campaign_id, attacks):
        """
        Generate a summary of a detected attack campaign.

        Args:
            campaign_id: str campaign identifier
            attacks: list of attack events in the campaign

        Returns:
            str: Campaign summary
        """
        if not attacks:
            return f"Campaign {campaign_id}: No data available."

        ips = set(a.get('source_ip', '') for a in attacks)
        protocols = set(a.get('honeypot_type', '') for a in attacks)
        total = len(attacks)

        timestamps = [a.get('timestamp') for a in attacks if a.get('timestamp')]
        duration = "unknown duration"
        if len(timestamps) >= 2:
            try:
                first = min(timestamps) if isinstance(timestamps[0], str) else timestamps[0]
                last = max(timestamps) if isinstance(timestamps[0], str) else timestamps[-1]
                duration = f"active period"
            except (TypeError, ValueError):
                duration = "unknown duration"

        return (
            f"Campaign {campaign_id}: {total} coordinated attacks from {len(ips)} IP(s). "
            f"Targeting {', '.join(p.upper() for p in protocols)} services. "
            f"Campaign shows {'coordinated multi-vector' if len(protocols) > 1 else 'focused'} "
            f"attack pattern."
        )
