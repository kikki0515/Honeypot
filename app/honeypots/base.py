"""Base honeypot class with common functionality.

Enhanced with AI analysis integration, GeoIP enrichment, and real-time AI events.
"""

import logging
import threading
from datetime import datetime

from app import db, socketio
from app.models import AttackLog, HoneypotService


class BaseHoneypot:
    """Base class for all honeypot services."""

    def __init__(self, service_type, port, app=None):
        self.service_type = service_type
        self.port = port
        self.app = app
        self._running = False
        self._thread = None
        self.server_socket = None
        self.logger = logging.getLogger(f'honeypot.{service_type}')

    def log_attack(self, source_ip, action, details=None, source_port=None,
                   username_attempted=None, password_attempted=None, severity='medium'):
        """Log an attack event to the database, run AI analysis, and emit via WebSocket."""
        if not self.app:
            return

        with self.app.app_context():
            try:
                attack = AttackLog(
                    source_ip=source_ip,
                    source_port=source_port,
                    honeypot_type=self.service_type,
                    protocol=self.service_type.upper(),
                    action=action,
                    details=details,
                    username_attempted=username_attempted,
                    password_attempted=password_attempted,
                    severity=severity
                )
                db.session.add(attack)
                db.session.commit()

                # --- AI Analysis Integration ---
                ai_result = self._run_ai_analysis(attack)

                # Emit real-time event via WebSocket
                attack_dict = attack.to_dict()
                socketio.emit('new_attack', attack_dict, namespace='/')

                # Emit AI-specific events if significant
                if ai_result:
                    self._emit_ai_events(attack_dict, ai_result)

                self.logger.info(
                    f"[{self.service_type.upper()}] {action} from {source_ip} "
                    f"(severity: {severity}, ai_class: {attack.ai_classification})"
                )
            except Exception as e:
                self.logger.error(f"Failed to log attack: {e}")
                db.session.rollback()

    def _run_ai_analysis(self, attack):
        """Run AI analysis on the attack and update the database record."""
        try:
            from app.ai.analyzer import AttackAnalyzer

            if not self.app.config.get('AI_ENABLED', True):
                return None

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

            # Update attack record with AI results
            attack.ai_classification = result.get('classification')
            attack.ai_confidence = result.get('classification_confidence')
            attack.ai_summary = result.get('summary')
            attack.threat_score = result.get('threat_score')
            attack.threat_risk_level = result.get('threat_risk_level')
            attack.attacker_fingerprint = result.get('fingerprint')
            attack.campaign_id = result.get('campaign_id')
            attack.is_anomaly = result.get('is_anomaly', False)
            attack.anomaly_score = result.get('anomaly', {}).get('anomaly_score', 0)

            # Run GeoIP enrichment
            self._enrich_geoip(attack)

            db.session.commit()
            return result

        except Exception as e:
            self.logger.error(f"AI analysis error: {e}")
            return None

    def _enrich_geoip(self, attack):
        """Enrich attack record with GeoIP data."""
        try:
            from app.intel.geoip import GeoIPLookup

            if not self.app.config.get('GEOIP_ENABLED', True):
                return

            geoip = GeoIPLookup.get_instance()
            if geoip:
                geo_data = geoip.lookup(attack.source_ip)
                if geo_data:
                    attack.geoip_country = geo_data.get('country')
                    attack.geoip_country_code = geo_data.get('country_code')
                    attack.geoip_city = geo_data.get('city')
                    attack.geoip_latitude = geo_data.get('latitude')
                    attack.geoip_longitude = geo_data.get('longitude')
                    attack.geoip_asn = geo_data.get('asn')
                    attack.geoip_isp = geo_data.get('isp')
        except ImportError:
            pass
        except Exception as e:
            self.logger.debug(f"GeoIP enrichment skipped: {e}")

    def _emit_ai_events(self, attack_dict, ai_result):
        """Emit real-time AI events via WebSocket."""
        try:
            # Emit AI alert for high-threat attacks
            threat_score = ai_result.get('threat_score', 0)
            if threat_score >= 7.0:
                socketio.emit('ai_alert', {
                    'attack': attack_dict,
                    'classification': ai_result.get('classification'),
                    'threat_score': threat_score,
                    'risk_level': ai_result.get('threat_risk_level'),
                    'summary': ai_result.get('summary'),
                    'timestamp': datetime.utcnow().isoformat()
                }, namespace='/')

            # Emit anomaly event
            if ai_result.get('is_anomaly'):
                socketio.emit('anomaly_detected', {
                    'attack': attack_dict,
                    'anomaly_score': ai_result.get('anomaly', {}).get('anomaly_score'),
                    'anomaly_types': ai_result.get('anomaly', {}).get('anomaly_types', []),
                    'description': ai_result.get('anomaly', {}).get('description'),
                    'timestamp': datetime.utcnow().isoformat()
                }, namespace='/')

            # Emit campaign detection
            if ai_result.get('campaign_id'):
                socketio.emit('campaign_detected', {
                    'campaign_id': ai_result.get('campaign_id'),
                    'source_ip': attack_dict.get('source_ip'),
                    'classification': ai_result.get('classification'),
                    'timestamp': datetime.utcnow().isoformat()
                }, namespace='/')

            # General threat event for dashboard feed
            socketio.emit('threat_detected', {
                'source_ip': attack_dict.get('source_ip'),
                'honeypot_type': attack_dict.get('honeypot_type'),
                'classification': ai_result.get('classification'),
                'threat_score': threat_score,
                'risk_level': ai_result.get('threat_risk_level'),
                'summary': ai_result.get('summary'),
                'is_anomaly': ai_result.get('is_anomaly'),
                'campaign_id': ai_result.get('campaign_id'),
                'timestamp': datetime.utcnow().isoformat()
            }, namespace='/')

        except Exception as e:
            self.logger.error(f"Failed to emit AI events: {e}")

    def update_status(self, status):
        """Update the service status in the database."""
        if not self.app:
            return

        with self.app.app_context():
            try:
                service = HoneypotService.query.filter_by(
                    service_type=self.service_type
                ).first()

                if not service:
                    service = HoneypotService(
                        service_type=self.service_type,
                        port=self.port,
                        status=status
                    )
                    db.session.add(service)
                else:
                    service.status = status
                    if status == 'running':
                        service.started_at = datetime.utcnow()

                db.session.commit()

                # Emit status update via WebSocket
                socketio.emit('service_status', {
                    'service_type': self.service_type,
                    'status': status,
                    'port': self.port
                }, namespace='/')

            except Exception as e:
                self.logger.error(f"Failed to update status: {e}")
                db.session.rollback()

    def increment_connections(self):
        """Increment the total connection count."""
        if not self.app:
            return

        with self.app.app_context():
            try:
                service = HoneypotService.query.filter_by(
                    service_type=self.service_type
                ).first()
                if service:
                    service.total_connections += 1
                    service.last_activity = datetime.utcnow()
                    db.session.commit()
            except Exception as e:
                self.logger.error(f"Failed to increment connections: {e}")
                db.session.rollback()

    def start(self):
        """Start the honeypot service. Override in subclass."""
        raise NotImplementedError

    def stop(self):
        """Stop the honeypot service."""
        self._running = False
        self.update_status('stopped')
        self.logger.info(f"{self.service_type.upper()} Honeypot stopped")

    def start_threaded(self):
        """Start the honeypot in a separate thread."""
        self._thread = threading.Thread(target=self.start, daemon=True)
        self._thread.start()
        return self._thread

    @property
    def is_running(self):
        return self._running
