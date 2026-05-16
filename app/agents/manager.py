"""Distributed Agent Manager.

Manages remote honeypot agent registration, heartbeat monitoring,
and centralized attack data collection from multiple nodes.
"""

import logging
import json
import uuid
import secrets
from datetime import datetime, timedelta

from app import db, socketio
from app.models import HoneypotAgent, AttackLog

logger = logging.getLogger('honeypot.agents.manager')


class AgentManager:
    """Central manager for distributed honeypot agents."""

    _instance = None

    def __init__(self, app=None):
        self.app = app
        self.heartbeat_timeout = 60  # seconds
        if app:
            self.heartbeat_timeout = app.config.get('AGENT_HEARTBEAT_INTERVAL', 30) * 2
        AgentManager._instance = self

    @classmethod
    def get_instance(cls):
        return cls._instance

    def register_agent(self, name, hostname=None, ip_address=None, location=None, version=None):
        """
        Register a new honeypot agent.

        Returns:
            dict with agent_id and api_key for the new agent
        """
        agent_id = str(uuid.uuid4())[:16]
        api_key = secrets.token_urlsafe(48)

        agent = HoneypotAgent(
            agent_id=agent_id,
            name=name,
            hostname=hostname,
            ip_address=ip_address,
            location=location,
            status='online',
            version=version,
            api_key=api_key,
            last_heartbeat=datetime.utcnow()
        )
        db.session.add(agent)
        db.session.commit()

        logger.info(f"New agent registered: {name} ({agent_id})")

        # Notify dashboard
        socketio.emit('agent_registered', agent.to_dict(), namespace='/')

        return {
            'agent_id': agent_id,
            'api_key': api_key,
            'message': 'Agent registered successfully'
        }

    def authenticate_agent(self, agent_id, api_key):
        """Authenticate an agent by ID and API key."""
        agent = HoneypotAgent.query.filter_by(
            agent_id=agent_id, api_key=api_key
        ).first()
        return agent

    def heartbeat(self, agent_id, services_running=None):
        """
        Process heartbeat from a remote agent.

        Args:
            agent_id: str agent identifier
            services_running: list of active service types

        Returns:
            dict with acknowledgement
        """
        agent = HoneypotAgent.query.filter_by(agent_id=agent_id).first()
        if not agent:
            return {'error': 'Agent not found'}, 404

        agent.last_heartbeat = datetime.utcnow()
        agent.status = 'online'
        if services_running:
            agent.services_running = json.dumps(services_running)

        db.session.commit()

        # Emit status update
        socketio.emit('agent_heartbeat', {
            'agent_id': agent_id,
            'name': agent.name,
            'status': 'online',
            'last_heartbeat': agent.last_heartbeat.isoformat()
        }, namespace='/')

        return {'status': 'acknowledged', 'timestamp': datetime.utcnow().isoformat()}

    def report_attack(self, agent_id, attack_data):
        """
        Receive and store an attack report from a remote agent.

        Args:
            agent_id: str reporting agent identifier
            attack_data: dict with attack details

        Returns:
            dict with confirmation and assigned attack ID
        """
        agent = HoneypotAgent.query.filter_by(agent_id=agent_id).first()
        if not agent:
            return {'error': 'Agent not found'}, 404

        # Create attack log entry
        attack = AttackLog(
            source_ip=attack_data.get('source_ip', '0.0.0.0'),
            source_port=attack_data.get('source_port'),
            honeypot_type=attack_data.get('honeypot_type', 'unknown'),
            protocol=attack_data.get('protocol'),
            action=attack_data.get('action', 'unknown'),
            details=attack_data.get('details'),
            username_attempted=attack_data.get('username_attempted'),
            password_attempted=attack_data.get('password_attempted'),
            severity=attack_data.get('severity', 'medium'),
            agent_id=agent_id,
            node_name=agent.name
        )
        db.session.add(attack)

        # Update agent stats
        agent.total_attacks_reported = (agent.total_attacks_reported or 0) + 1
        agent.last_heartbeat = datetime.utcnow()

        db.session.commit()

        # Run AI analysis on remote attack
        self._analyze_remote_attack(attack)

        # Emit to dashboard
        socketio.emit('new_attack', attack.to_dict(), namespace='/')

        return {
            'status': 'received',
            'attack_id': attack.id,
            'timestamp': datetime.utcnow().isoformat()
        }

    def _analyze_remote_attack(self, attack):
        """Run AI analysis on attacks reported by remote agents."""
        try:
            from app.ai.analyzer import AttackAnalyzer

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

            # Update attack with AI results
            attack.ai_classification = result.get('classification')
            attack.ai_confidence = result.get('classification_confidence')
            attack.ai_summary = result.get('summary')
            attack.threat_score = result.get('threat_score')
            attack.threat_risk_level = result.get('threat_risk_level')
            attack.attacker_fingerprint = result.get('fingerprint')
            attack.campaign_id = result.get('campaign_id')
            attack.is_anomaly = result.get('is_anomaly', False)

            db.session.commit()

        except Exception as e:
            logger.error(f"AI analysis failed for remote attack: {e}")

    def get_all_agents(self):
        """Get status of all registered agents."""
        agents = HoneypotAgent.query.all()
        # Update status based on heartbeat timeout
        for agent in agents:
            if agent.last_heartbeat:
                elapsed = (datetime.utcnow() - agent.last_heartbeat).total_seconds()
                if elapsed > self.heartbeat_timeout and agent.status == 'online':
                    agent.status = 'offline'

        db.session.commit()
        return [a.to_dict() for a in agents]

    def remove_agent(self, agent_id):
        """Remove a registered agent."""
        agent = HoneypotAgent.query.filter_by(agent_id=agent_id).first()
        if agent:
            db.session.delete(agent)
            db.session.commit()
            logger.info(f"Agent removed: {agent.name} ({agent_id})")
            return {'status': 'removed'}
        return {'error': 'Agent not found'}, 404

    def get_agent_attacks(self, agent_id, limit=50):
        """Get recent attacks reported by a specific agent."""
        attacks = AttackLog.query.filter_by(agent_id=agent_id)\
            .order_by(AttackLog.timestamp.desc())\
            .limit(limit).all()
        return [a.to_dict() for a in attacks]
