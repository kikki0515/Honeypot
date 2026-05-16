"""Background tasks for AI analysis and threat intelligence.

These tasks run asynchronously via Celery to avoid blocking honeypot operations.
"""

import logging
from datetime import datetime

from app.tasks.celery_app import celery_app

logger = logging.getLogger('honeypot.tasks')


@celery_app.task(name='tasks.analyze_attack_async')
def analyze_attack_async(attack_id):
    """Run full AI analysis on an attack asynchronously."""
    from app import db
    from app.models import AttackLog
    from app.ai.analyzer import AttackAnalyzer

    try:
        attack = AttackLog.query.get(attack_id)
        if not attack:
            return {'error': 'Attack not found'}

        analyzer = AttackAnalyzer.get_instance()
        attack_data = {
            'source_ip': attack.source_ip,
            'source_port': attack.source_port,
            'honeypot_type': attack.honeypot_type,
            'protocol': attack.protocol,
            'action': attack.action,
            'details': attack.details,
            'username_attempted': attack.username_attempted,
            'password_attempted': attack.password_attempted,
            'severity': attack.severity
        }

        result = analyzer.analyze_attack(attack_data)

        # Update attack record
        attack.ai_classification = result.get('classification')
        attack.ai_confidence = result.get('classification_confidence')
        attack.ai_summary = result.get('summary')
        attack.threat_score = result.get('threat_score')
        attack.threat_risk_level = result.get('threat_risk_level')
        attack.attacker_fingerprint = result.get('fingerprint')
        attack.campaign_id = result.get('campaign_id')
        attack.is_anomaly = result.get('is_anomaly', False)
        attack.anomaly_score = result.get('anomaly', {}).get('anomaly_score', 0)

        db.session.commit()

        return {'status': 'completed', 'attack_id': attack_id, 'classification': result.get('classification')}

    except Exception as e:
        logger.error(f"Async analysis failed for attack {attack_id}: {e}")
        return {'error': str(e)}


@celery_app.task(name='tasks.enrich_geoip_async')
def enrich_geoip_async(attack_id):
    """Enrich attack with GeoIP data asynchronously."""
    from app import db
    from app.models import AttackLog
    from app.intel.geoip import GeoIPLookup

    try:
        attack = AttackLog.query.get(attack_id)
        if not attack:
            return {'error': 'Attack not found'}

        geoip = GeoIPLookup.get_instance()
        if not geoip:
            return {'error': 'GeoIP not configured'}

        geo_data = geoip.lookup(attack.source_ip)
        if geo_data:
            attack.geoip_country = geo_data.get('country')
            attack.geoip_country_code = geo_data.get('country_code')
            attack.geoip_city = geo_data.get('city')
            attack.geoip_latitude = geo_data.get('latitude')
            attack.geoip_longitude = geo_data.get('longitude')
            attack.geoip_asn = geo_data.get('asn')
            attack.geoip_isp = geo_data.get('isp')
            db.session.commit()

        return {'status': 'completed', 'country': geo_data.get('country') if geo_data else None}

    except Exception as e:
        logger.error(f"GeoIP enrichment failed for attack {attack_id}: {e}")
        return {'error': str(e)}


@celery_app.task(name='tasks.check_reputation_async')
def check_reputation_async(attack_id):
    """Check IP reputation asynchronously."""
    from app import db
    from app.models import AttackLog
    from app.intel.reputation import ReputationChecker

    try:
        attack = AttackLog.query.get(attack_id)
        if not attack:
            return {'error': 'Attack not found'}

        checker = ReputationChecker.get_instance()
        if not checker:
            return {'error': 'Reputation checker not configured'}

        result = checker.check_ip(attack.source_ip)
        if result:
            attack.reputation_score = result.get('reputation_score', 0)
            attack.is_known_malicious = result.get('is_known_malicious', False)
            db.session.commit()

        return {'status': 'completed', 'reputation_score': result.get('reputation_score')}

    except Exception as e:
        logger.error(f"Reputation check failed for attack {attack_id}: {e}")
        return {'error': str(e)}


@celery_app.task(name='tasks.process_alert_async')
def process_alert_async(attack_id, alert_rule_id):
    """Process and send alert asynchronously."""
    from app.alerts.dispatcher import AlertDispatcher

    try:
        dispatcher = AlertDispatcher.get_instance()
        if dispatcher:
            dispatcher.process_alert(attack_id, alert_rule_id)
            return {'status': 'sent'}
    except Exception as e:
        logger.error(f"Alert processing failed: {e}")
        return {'error': str(e)}
