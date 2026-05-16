"""Threat Scoring Engine.

Calculates composite threat scores for attacks and attackers based on
multiple factors including severity, frequency, sophistication, and context.
"""

import json
import math
from datetime import datetime, timedelta
from collections import defaultdict


class ThreatScorer:
    """Calculates threat scores for individual attacks and attackers."""

    # Weight factors for scoring components
    WEIGHTS = {
        'severity': 0.25,
        'sophistication': 0.20,
        'frequency': 0.15,
        'target_value': 0.15,
        'persistence': 0.10,
        'evasion': 0.10,
        'campaign': 0.05
    }

    # Severity base scores
    SEVERITY_SCORES = {
        'critical': 9.5,
        'high': 7.5,
        'medium': 5.0,
        'low': 2.5
    }

    # Action sophistication scores
    ACTION_SOPHISTICATION = {
        'sql_injection': 8.0,
        'command_injection': 9.0,
        'xss_attack': 7.0,
        'path_traversal': 6.5,
        'credential_stuffing': 7.5,
        'malware_delivery': 9.5,
        'data_exfiltration': 8.5,
        'api_abuse': 6.0,
        'brute_force': 4.0,
        'web_scanning': 5.0,
        'reconnaissance': 3.0,
        'dos_attempt': 6.5
    }

    def __init__(self):
        self.ip_scores = defaultdict(lambda: {'attacks': 0, 'last_seen': None, 'total_score': 0})
        self.ip_attack_times = defaultdict(list)

    def calculate_attack_score(self, attack_data, classification=None):
        """
        Calculate a threat score (0-10) for a single attack event.

        Args:
            attack_data: dict with attack details
            classification: dict from AttackClassifier

        Returns:
            dict with: score, breakdown, risk_level
        """
        breakdown = {}

        # 1. Severity component
        severity = attack_data.get('severity', 'medium')
        breakdown['severity'] = self.SEVERITY_SCORES.get(severity, 5.0)

        # 2. Sophistication component
        classification_type = ''
        if classification:
            classification_type = classification.get('classification', '')
        breakdown['sophistication'] = self.ACTION_SOPHISTICATION.get(
            classification_type, 4.0
        )

        # 3. Frequency component
        source_ip = attack_data.get('source_ip', '')
        now = datetime.utcnow()
        self.ip_attack_times[source_ip].append(now)
        # Keep only last hour of timestamps
        cutoff = now - timedelta(hours=1)
        self.ip_attack_times[source_ip] = [
            t for t in self.ip_attack_times[source_ip] if t > cutoff
        ]
        frequency = len(self.ip_attack_times[source_ip])
        breakdown['frequency'] = min(frequency / 5.0 * 10, 10.0)

        # 4. Target value component
        breakdown['target_value'] = self._assess_target_value(attack_data)

        # 5. Persistence component
        ip_info = self.ip_scores[source_ip]
        ip_info['attacks'] += 1
        ip_info['last_seen'] = now
        persistence = min(ip_info['attacks'] / 10.0 * 10, 10.0)
        breakdown['persistence'] = persistence

        # 6. Evasion component
        breakdown['evasion'] = self._assess_evasion(attack_data, classification)

        # 7. Campaign component
        campaign_id = None
        if classification:
            campaign_id = classification.get('campaign_id')
        breakdown['campaign'] = 8.0 if campaign_id else 0.0

        # Calculate weighted score
        total_score = sum(
            breakdown[component] * weight
            for component, weight in self.WEIGHTS.items()
            if component in breakdown
        )

        # Normalize to 0-10 scale
        total_score = min(max(total_score, 0), 10)

        # Update IP cumulative score
        ip_info['total_score'] = max(ip_info['total_score'], total_score)

        # Determine risk level
        risk_level = self._get_risk_level(total_score)

        return {
            'score': round(total_score, 2),
            'breakdown': {k: round(v, 2) for k, v in breakdown.items()},
            'risk_level': risk_level,
            'ip_cumulative_score': round(ip_info['total_score'], 2)
        }

    def _assess_target_value(self, attack_data):
        """Assess the value of the targeted resource."""
        details_str = attack_data.get('details', '{}')
        action = attack_data.get('action', '')

        try:
            details = json.loads(details_str) if isinstance(details_str, str) else details_str
        except (json.JSONDecodeError, TypeError):
            details = {}

        score = 5.0  # Base score

        # High-value targets
        high_value_indicators = [
            'database', 'backup', 'credentials', 'config', '.env',
            'admin', 'root', 'passwd', 'shadow', 'private', 'key'
        ]
        combined = f"{action} {details_str}".lower()
        for indicator in high_value_indicators:
            if indicator in combined:
                score += 1.5

        return min(score, 10.0)

    def _assess_evasion(self, attack_data, classification=None):
        """Assess evasion technique sophistication."""
        details_str = attack_data.get('details', '{}')

        try:
            details = json.loads(details_str) if isinstance(details_str, str) else details_str
        except (json.JSONDecodeError, TypeError):
            details = {}

        score = 2.0

        # Check for encoding evasion
        path = details.get('path', '')
        if '%' in path or '\\x' in path:
            score += 3.0

        # Check for unusual user agents
        ua = details.get('user_agent', '') or details.get('headers', {}).get('User-Agent', '')
        if ua and len(ua) > 200:
            score += 2.0  # Unusually long UA (possible evasion)
        if not ua:
            score += 1.5  # Missing UA (suspicious)

        # Multiple protocols suggest advanced attacker
        if classification and len(classification.get('sub_categories', [])) >= 2:
            score += 2.0

        return min(score, 10.0)

    def _get_risk_level(self, score):
        """Convert numeric score to risk level string."""
        if score >= 8.5:
            return 'critical'
        elif score >= 6.5:
            return 'high'
        elif score >= 4.0:
            return 'medium'
        else:
            return 'low'

    def get_ip_threat_score(self, source_ip):
        """Get cumulative threat score for an IP address."""
        info = self.ip_scores.get(source_ip)
        if not info:
            return {'score': 0, 'attacks': 0, 'risk_level': 'low'}

        return {
            'score': round(info['total_score'], 2),
            'attacks': info['attacks'],
            'last_seen': info['last_seen'].isoformat() if info['last_seen'] else None,
            'risk_level': self._get_risk_level(info['total_score'])
        }

    def get_top_threats(self, limit=10):
        """Get top threat IPs by cumulative score."""
        sorted_ips = sorted(
            self.ip_scores.items(),
            key=lambda x: x[1]['total_score'],
            reverse=True
        )[:limit]

        return [
            {
                'ip': ip,
                'score': round(info['total_score'], 2),
                'attacks': info['attacks'],
                'risk_level': self._get_risk_level(info['total_score'])
            }
            for ip, info in sorted_ips
        ]
