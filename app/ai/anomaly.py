"""Anomaly Detection Engine.

Detects unusual patterns in attack traffic using statistical methods
and behavioral analysis.
"""

import math
from datetime import datetime, timedelta
from collections import defaultdict, deque


class AnomalyDetector:
    """Detects anomalies in attack patterns using statistical analysis."""

    def __init__(self, window_size=100, sensitivity=2.0):
        self.window_size = window_size
        self.sensitivity = sensitivity
        
        # Rolling statistics
        self.attack_rates = deque(maxlen=window_size)
        self.ip_behavior = defaultdict(lambda: {
            'actions': deque(maxlen=50),
            'timestamps': deque(maxlen=50),
            'protocols': set(),
            'ports_targeted': set()
        })
        
        # Baseline statistics
        self.hourly_counts = defaultdict(int)
        self.protocol_distribution = defaultdict(int)
        self.total_observations = 0
        
        # Anomaly tracking
        self.detected_anomalies = deque(maxlen=200)

    def analyze(self, attack_data):
        """
        Analyze an attack event for anomalies.

        Args:
            attack_data: dict with attack information

        Returns:
            dict with: is_anomaly, anomaly_score, anomaly_types, description
        """
        source_ip = attack_data.get('source_ip', '')
        honeypot_type = attack_data.get('honeypot_type', '')
        action = attack_data.get('action', '')
        timestamp = datetime.utcnow()

        self.total_observations += 1

        # Update statistics
        self._update_statistics(attack_data, timestamp)

        # Run anomaly checks
        anomalies = []
        anomaly_score = 0.0

        # 1. Rate anomaly (sudden spike in traffic)
        rate_result = self._check_rate_anomaly(source_ip, timestamp)
        if rate_result['is_anomaly']:
            anomalies.append(rate_result)
            anomaly_score += rate_result['score']

        # 2. Behavioral anomaly (unusual patterns for this IP)
        behavior_result = self._check_behavior_anomaly(source_ip, action, honeypot_type)
        if behavior_result['is_anomaly']:
            anomalies.append(behavior_result)
            anomaly_score += behavior_result['score']

        # 3. Temporal anomaly (unusual time patterns)
        temporal_result = self._check_temporal_anomaly(timestamp)
        if temporal_result['is_anomaly']:
            anomalies.append(temporal_result)
            anomaly_score += temporal_result['score']

        # 4. Protocol anomaly (unusual protocol usage)
        protocol_result = self._check_protocol_anomaly(honeypot_type)
        if protocol_result['is_anomaly']:
            anomalies.append(protocol_result)
            anomaly_score += protocol_result['score']

        # 5. New attacker anomaly
        new_attacker_result = self._check_new_attacker(source_ip)
        if new_attacker_result['is_anomaly']:
            anomalies.append(new_attacker_result)
            anomaly_score += new_attacker_result['score']

        # Normalize score to 0-10
        anomaly_score = min(anomaly_score, 10.0)
        is_anomaly = anomaly_score >= 3.0

        result = {
            'is_anomaly': is_anomaly,
            'anomaly_score': round(anomaly_score, 2),
            'anomaly_types': [a['type'] for a in anomalies],
            'anomaly_details': anomalies,
            'description': self._generate_description(anomalies) if anomalies else 'Normal activity'
        }

        if is_anomaly:
            self.detected_anomalies.append({
                'timestamp': timestamp.isoformat(),
                'source_ip': source_ip,
                'score': anomaly_score,
                'types': result['anomaly_types']
            })

        return result

    def _update_statistics(self, attack_data, timestamp):
        """Update rolling statistics."""
        source_ip = attack_data.get('source_ip', '')
        honeypot_type = attack_data.get('honeypot_type', '')
        action = attack_data.get('action', '')

        # Update IP behavior
        ip_info = self.ip_behavior[source_ip]
        ip_info['actions'].append(action)
        ip_info['timestamps'].append(timestamp)
        ip_info['protocols'].add(honeypot_type)

        # Update global stats
        hour = timestamp.hour
        self.hourly_counts[hour] += 1
        self.protocol_distribution[honeypot_type] += 1

        # Update attack rate
        self.attack_rates.append(timestamp)

    def _check_rate_anomaly(self, source_ip, timestamp):
        """Check for unusual attack rate from an IP."""
        ip_info = self.ip_behavior[source_ip]
        timestamps = list(ip_info['timestamps'])

        if len(timestamps) < 3:
            return {'is_anomaly': False, 'type': 'rate', 'score': 0}

        # Calculate attacks per minute for this IP
        recent = [t for t in timestamps if (timestamp - t).total_seconds() < 60]
        rate_per_minute = len(recent)

        # High rate threshold
        if rate_per_minute >= 10:
            return {
                'is_anomaly': True,
                'type': 'rate_spike',
                'score': min(rate_per_minute / 5.0, 5.0),
                'description': f'High attack rate: {rate_per_minute} attacks/minute from {source_ip}'
            }

        return {'is_anomaly': False, 'type': 'rate', 'score': 0}

    def _check_behavior_anomaly(self, source_ip, action, protocol):
        """Check for behavioral anomalies from an IP."""
        ip_info = self.ip_behavior[source_ip]

        # Multi-protocol attack (unusual sophistication)
        if len(ip_info['protocols']) >= 3:
            return {
                'is_anomaly': True,
                'type': 'multi_protocol',
                'score': 4.0,
                'description': f'{source_ip} attacking multiple protocols: {", ".join(ip_info["protocols"])}'
            }

        # Rapid action changes (automated tool behavior)
        actions = list(ip_info['actions'])
        if len(actions) >= 5:
            unique_recent = set(actions[-5:])
            if len(unique_recent) >= 4:
                return {
                    'is_anomaly': True,
                    'type': 'automated_behavior',
                    'score': 3.5,
                    'description': f'{source_ip} showing automated scanning behavior'
                }

        return {'is_anomaly': False, 'type': 'behavior', 'score': 0}

    def _check_temporal_anomaly(self, timestamp):
        """Check for temporal anomalies (unusual time patterns)."""
        if self.total_observations < 50:
            return {'is_anomaly': False, 'type': 'temporal', 'score': 0}

        hour = timestamp.hour
        total = sum(self.hourly_counts.values())
        if total == 0:
            return {'is_anomaly': False, 'type': 'temporal', 'score': 0}

        # Calculate expected vs actual distribution
        avg_per_hour = total / 24.0
        current_hour_count = self.hourly_counts[hour]

        if avg_per_hour > 0 and current_hour_count > avg_per_hour * 3:
            return {
                'is_anomaly': True,
                'type': 'temporal_spike',
                'score': 2.5,
                'description': f'Unusual activity spike at hour {hour}:00'
            }

        return {'is_anomaly': False, 'type': 'temporal', 'score': 0}

    def _check_protocol_anomaly(self, honeypot_type):
        """Check for unusual protocol distribution."""
        if self.total_observations < 30:
            return {'is_anomaly': False, 'type': 'protocol', 'score': 0}

        total = sum(self.protocol_distribution.values())
        if total == 0:
            return {'is_anomaly': False, 'type': 'protocol', 'score': 0}

        expected_ratio = 1.0 / max(len(self.protocol_distribution), 1)
        actual_ratio = self.protocol_distribution[honeypot_type] / total

        # Significant deviation from expected
        if actual_ratio > expected_ratio * 4:
            return {
                'is_anomaly': True,
                'type': 'protocol_concentration',
                'score': 2.0,
                'description': f'Unusual concentration of {honeypot_type.upper()} attacks'
            }

        return {'is_anomaly': False, 'type': 'protocol', 'score': 0}

    def _check_new_attacker(self, source_ip):
        """Detect new attacker with aggressive behavior."""
        ip_info = self.ip_behavior[source_ip]
        timestamps = list(ip_info['timestamps'])

        if len(timestamps) == 1:
            return {'is_anomaly': False, 'type': 'new_attacker', 'score': 0}

        # New attacker with multiple quick attacks
        if len(timestamps) >= 3 and len(timestamps) <= 5:
            time_span = (timestamps[-1] - timestamps[0]).total_seconds()
            if time_span < 30:  # 3+ attacks in 30 seconds
                return {
                    'is_anomaly': True,
                    'type': 'aggressive_new_attacker',
                    'score': 3.0,
                    'description': f'New attacker {source_ip} with rapid attack pattern'
                }

        return {'is_anomaly': False, 'type': 'new_attacker', 'score': 0}

    def _generate_description(self, anomalies):
        """Generate human-readable anomaly description."""
        if not anomalies:
            return 'No anomalies detected'

        descriptions = [a.get('description', a['type']) for a in anomalies if a.get('description')]
        return '; '.join(descriptions) if descriptions else 'Anomalous behavior detected'

    def get_recent_anomalies(self, limit=20):
        """Get recent detected anomalies."""
        return list(self.detected_anomalies)[-limit:]

    def get_statistics(self):
        """Get current anomaly detection statistics."""
        return {
            'total_observations': self.total_observations,
            'unique_ips_tracked': len(self.ip_behavior),
            'total_anomalies_detected': len(self.detected_anomalies),
            'hourly_distribution': dict(self.hourly_counts),
            'protocol_distribution': dict(self.protocol_distribution)
        }
