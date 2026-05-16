"""Distributed Agent Client.

Runs on remote honeypot nodes to report attacks back to the central server.
Handles heartbeat, registration, and attack reporting.
"""

import logging
import json
import threading
import time
from datetime import datetime

logger = logging.getLogger('honeypot.agents.client')


class AgentClient:
    """
    Agent client that runs on remote honeypot nodes.
    Reports attacks to the central HaaS server.
    """

    def __init__(self, central_url, agent_id=None, api_key=None, heartbeat_interval=30):
        self.central_url = central_url.rstrip('/')
        self.agent_id = agent_id
        self.api_key = api_key
        self.heartbeat_interval = heartbeat_interval
        self._running = False
        self._heartbeat_thread = None
        self._attack_queue = []

    def register(self, name, hostname=None, ip_address=None, location=None, version='2.0.0'):
        """
        Register this agent with the central server.

        Returns:
            dict with agent_id and api_key
        """
        try:
            import requests

            response = requests.post(
                f"{self.central_url}/api/agents/register",
                json={
                    'name': name,
                    'hostname': hostname,
                    'ip_address': ip_address,
                    'location': location,
                    'version': version
                },
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                self.agent_id = data['agent_id']
                self.api_key = data['api_key']
                logger.info(f"Agent registered: {name} -> {self.agent_id}")
                return data
            else:
                logger.error(f"Registration failed: {response.status_code}")
                return None

        except ImportError:
            logger.error("requests library required for agent client")
            return None
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return None

    def start(self):
        """Start the agent client (heartbeat loop)."""
        if not self.agent_id or not self.api_key:
            logger.error("Agent must be registered before starting")
            return

        self._running = True
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True
        )
        self._heartbeat_thread.start()
        logger.info(f"Agent client started (ID: {self.agent_id})")

    def stop(self):
        """Stop the agent client."""
        self._running = False
        logger.info("Agent client stopped")

    def report_attack(self, attack_data):
        """
        Report an attack to the central server.

        Args:
            attack_data: dict with attack details
        """
        if not self.agent_id or not self.api_key:
            self._attack_queue.append(attack_data)
            return

        try:
            import requests

            response = requests.post(
                f"{self.central_url}/api/agents/{self.agent_id}/report",
                json=attack_data,
                headers={'X-Agent-Key': self.api_key},
                timeout=10
            )

            if response.status_code == 200:
                logger.debug(f"Attack reported successfully")
            else:
                logger.warning(f"Attack report failed: {response.status_code}")
                self._attack_queue.append(attack_data)

        except ImportError:
            self._attack_queue.append(attack_data)
        except Exception as e:
            logger.error(f"Attack report error: {e}")
            self._attack_queue.append(attack_data)

    def _heartbeat_loop(self):
        """Periodic heartbeat to central server."""
        while self._running:
            try:
                self._send_heartbeat()
                # Flush any queued attacks
                self._flush_queue()
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")

            time.sleep(self.heartbeat_interval)

    def _send_heartbeat(self):
        """Send heartbeat to central server."""
        try:
            import requests

            response = requests.post(
                f"{self.central_url}/api/agents/{self.agent_id}/heartbeat",
                json={'services_running': []},
                headers={'X-Agent-Key': self.api_key},
                timeout=10
            )

            if response.status_code != 200:
                logger.warning(f"Heartbeat failed: {response.status_code}")

        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"Heartbeat send error: {e}")

    def _flush_queue(self):
        """Try to send queued attacks."""
        if not self._attack_queue:
            return

        queue_copy = self._attack_queue[:]
        self._attack_queue = []

        for attack_data in queue_copy:
            self.report_attack(attack_data)
