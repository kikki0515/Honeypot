"""Distributed Agent Support Module.

Provides remote honeypot agent registration, heartbeat monitoring,
centralized reporting API, and node management.
"""

from app.agents.manager import AgentManager
from app.agents.client import AgentClient

__all__ = ['AgentManager', 'AgentClient']
