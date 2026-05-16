"""Main AI Attack Analyzer - Orchestrates all AI analysis components.

This is the central entry point that coordinates classification, scoring,
anomaly detection, and summarization for each attack event.
"""

import logging
from datetime import datetime

from app.ai.classifier import AttackClassifier
from app.ai.scoring import ThreatScorer
from app.ai.anomaly import AnomalyDetector
from app.ai.summarizer import AttackSummarizer


class AttackAnalyzer:
    """
    Central AI analysis engine that orchestrates all analysis components.

    Usage:
        analyzer = AttackAnalyzer()
        result = analyzer.analyze_attack(attack_data)
    """

    _instance = None

    def __init__(self):
        self.classifier = AttackClassifier()
        self.scorer = ThreatScorer()
        self.anomaly_detector = AnomalyDetector()
        self.summarizer = AttackSummarizer()
        self.logger = logging.getLogger('honeypot.ai')
        AttackAnalyzer._instance = self

    @classmethod
    def get_instance(cls):
        """Get the singleton analyzer instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def analyze_attack(self, attack_data):
        """
        Perform full AI analysis on an attack event.

        Args:
            attack_data: dict with keys:
                - source_ip, source_port, honeypot_type, protocol
                - action, details, username_attempted, password_attempted
                - severity

        Returns:
            dict with complete analysis results:
                - classification: attack type and confidence
                - threat_score: numeric score and risk level
                - anomaly: anomaly detection results
                - summary: human-readable AI summary
                - fingerprint: attacker behavioral fingerprint
                - campaign_id: campaign identifier if detected
        """
        try:
            # 1. Classify the attack
            classification = self.classifier.classify(attack_data)

            # 2. Detect campaign participation
            campaign_id = self.classifier.detect_campaign(attack_data)
            classification['campaign_id'] = campaign_id

            # 3. Calculate threat score
            threat_score = self.scorer.calculate_attack_score(attack_data, classification)

            # 4. Detect anomalies
            anomaly = self.anomaly_detector.analyze(attack_data)

            # 5. Generate fingerprint
            fingerprint = self.classifier.generate_fingerprint(attack_data)

            # 6. Generate AI summary
            summary = self.summarizer.summarize_attack(
                attack_data, classification, threat_score
            )

            # 7. Boost score if anomaly detected
            if anomaly.get('is_anomaly'):
                anomaly_boost = min(anomaly['anomaly_score'] * 0.2, 2.0)
                threat_score['score'] = min(
                    threat_score['score'] + anomaly_boost, 10.0
                )
                threat_score['score'] = round(threat_score['score'], 2)

            result = {
                'classification': classification['classification'],
                'classification_confidence': classification['confidence'],
                'classification_details': classification,
                'threat_score': threat_score['score'],
                'threat_risk_level': threat_score['risk_level'],
                'threat_details': threat_score,
                'anomaly': anomaly,
                'is_anomaly': anomaly.get('is_anomaly', False),
                'summary': summary,
                'fingerprint': fingerprint,
                'campaign_id': campaign_id,
                'analyzed_at': datetime.utcnow().isoformat()
            }

            self.logger.debug(
                f"AI Analysis for {attack_data.get('source_ip')}: "
                f"class={classification['classification']} "
                f"score={threat_score['score']} "
                f"anomaly={anomaly.get('is_anomaly')}"
            )

            return result

        except Exception as e:
            self.logger.error(f"AI analysis error: {e}")
            return {
                'classification': 'unknown',
                'classification_confidence': 0.0,
                'classification_details': {},
                'threat_score': 5.0,
                'threat_risk_level': 'medium',
                'threat_details': {},
                'anomaly': {'is_anomaly': False, 'anomaly_score': 0},
                'is_anomaly': False,
                'summary': f"Attack from {attack_data.get('source_ip', 'unknown')} (analysis error)",
                'fingerprint': 'unknown',
                'campaign_id': None,
                'analyzed_at': datetime.utcnow().isoformat()
            }

    def get_threat_intelligence(self):
        """Get current threat intelligence summary."""
        return {
            'top_threats': self.scorer.get_top_threats(10),
            'recent_anomalies': self.anomaly_detector.get_recent_anomalies(20),
            'anomaly_stats': self.anomaly_detector.get_statistics()
        }

    def get_ip_analysis(self, source_ip):
        """Get comprehensive analysis for a specific IP."""
        return {
            'threat_score': self.scorer.get_ip_threat_score(source_ip),
            'behavior': dict(self.anomaly_detector.ip_behavior.get(source_ip, {}))
        }
