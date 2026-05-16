"""API routes for distributed agent management."""

from flask import Blueprint, jsonify, request
from flask_login import login_required
from functools import wraps

from app import db
from app.models import HoneypotAgent
from app.agents.manager import AgentManager

agents_bp = Blueprint('agents', __name__)


def agent_auth_required(f):
    """Decorator to authenticate agent API requests."""
    @wraps(f)
    def decorated(*args, **kwargs):
        agent_id = kwargs.get('agent_id')
        api_key = request.headers.get('X-Agent-Key')

        if not agent_id or not api_key:
            return jsonify({'error': 'Missing agent credentials'}), 401

        manager = AgentManager.get_instance()
        if not manager:
            return jsonify({'error': 'Agent manager not initialized'}), 500

        agent = manager.authenticate_agent(agent_id, api_key)
        if not agent:
            return jsonify({'error': 'Invalid agent credentials'}), 401

        return f(*args, **kwargs)
    return decorated


@agents_bp.route('/register', methods=['POST'])
def register_agent():
    """Register a new honeypot agent."""
    data = request.get_json()
    if not data or not data.get('name'):
        return jsonify({'error': 'Agent name required'}), 400

    manager = AgentManager.get_instance()
    if not manager:
        return jsonify({'error': 'Agent manager not initialized'}), 500

    result = manager.register_agent(
        name=data['name'],
        hostname=data.get('hostname'),
        ip_address=data.get('ip_address', request.remote_addr),
        location=data.get('location'),
        version=data.get('version')
    )

    return jsonify(result)


@agents_bp.route('/<agent_id>/heartbeat', methods=['POST'])
@agent_auth_required
def agent_heartbeat(agent_id):
    """Process agent heartbeat."""
    data = request.get_json() or {}
    manager = AgentManager.get_instance()

    result = manager.heartbeat(
        agent_id=agent_id,
        services_running=data.get('services_running')
    )

    if isinstance(result, tuple):
        return jsonify(result[0]), result[1]
    return jsonify(result)


@agents_bp.route('/<agent_id>/report', methods=['POST'])
@agent_auth_required
def agent_report_attack(agent_id):
    """Receive attack report from a remote agent."""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Attack data required'}), 400

    manager = AgentManager.get_instance()
    result = manager.report_attack(agent_id, data)

    if isinstance(result, tuple):
        return jsonify(result[0]), result[1]
    return jsonify(result)


@agents_bp.route('/', methods=['GET'])
@login_required
def list_agents():
    """List all registered agents (dashboard use)."""
    manager = AgentManager.get_instance()
    if not manager:
        return jsonify({'agents': []})

    agents = manager.get_all_agents()
    return jsonify({'agents': agents})


@agents_bp.route('/<agent_id>', methods=['DELETE'])
@login_required
def remove_agent(agent_id):
    """Remove a registered agent."""
    manager = AgentManager.get_instance()
    if not manager:
        return jsonify({'error': 'Agent manager not initialized'}), 500

    result = manager.remove_agent(agent_id)
    if isinstance(result, tuple):
        return jsonify(result[0]), result[1]
    return jsonify(result)


@agents_bp.route('/<agent_id>/attacks', methods=['GET'])
@login_required
def get_agent_attacks(agent_id):
    """Get attacks reported by a specific agent."""
    limit = request.args.get('limit', 50, type=int)
    manager = AgentManager.get_instance()
    if not manager:
        return jsonify({'attacks': []})

    attacks = manager.get_agent_attacks(agent_id, limit)
    return jsonify({'attacks': attacks})
