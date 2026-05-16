"""IP Reputation Checking Service.

Integrates with AbuseIPDB and VirusTotal for threat intelligence on IP addresses.
Includes caching to avoid repeated API calls.
"""

import logging
import json
import hashlib
from datetime import datetime, timedelta

logger = logging.getLogger('honeypot.intel.reputation')


class ReputationChecker:
    """Checks IP reputation against threat intelligence feeds."""

    _instance = None

    def __init__(self, app=None):
        self.app = app
        self.abuseipdb_key = ''
        self.virustotal_key = ''
        self.cache_hours = 24
        self.enabled = False

        if app:
            self.configure(app)

        ReputationChecker._instance = self

    @classmethod
    def get_instance(cls):
        """Get singleton instance."""
        return cls._instance

    def configure(self, app):
        """Configure with Flask app settings."""
        self.app = app
        self.abuseipdb_key = app.config.get('ABUSEIPDB_API_KEY', '')
        self.virustotal_key = app.config.get('VIRUSTOTAL_API_KEY', '')
        self.cache_hours = app.config.get('THREAT_INTEL_CACHE_HOURS', 24)
        self.enabled = app.config.get('THREAT_INTEL_ENABLED', True)

    def check_ip(self, ip_address):
        """
        Check IP reputation from multiple sources.

        Args:
            ip_address: str IP to check

        Returns:
            dict with reputation data:
                - abuse_confidence: int 0-100
                - total_reports: int
                - is_tor_exit: bool
                - is_vpn: bool
                - is_proxy: bool
                - is_known_malicious: bool
                - reputation_score: float 0-100
                - categories: list
                - source: str
        """
        if not self.enabled:
            return self._default_result()

        # Check cache first
        cached = self._get_cached(ip_address)
        if cached:
            return cached

        result = self._default_result()

        # Try AbuseIPDB
        if self.abuseipdb_key:
            abuseipdb_data = self._check_abuseipdb(ip_address)
            if abuseipdb_data:
                result.update(abuseipdb_data)
                result['source'] = 'abuseipdb'

        # Try VirusTotal
        if self.virustotal_key and not result.get('abuse_confidence'):
            vt_data = self._check_virustotal(ip_address)
            if vt_data:
                result.update(vt_data)
                result['source'] = 'virustotal'

        # If no API keys, use heuristic scoring
        if not self.abuseipdb_key and not self.virustotal_key:
            result = self._heuristic_check(ip_address)

        # Cache the result
        self._cache_result(ip_address, result)

        return result

    def _check_abuseipdb(self, ip_address):
        """Query AbuseIPDB for IP reputation."""
        try:
            import requests

            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_key
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': True
            }

            response = requests.get(url, headers=headers, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'abuse_confidence': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'is_tor_exit': data.get('isTor', False),
                    'is_vpn': data.get('isVPN', False) if 'isVPN' in data else False,
                    'is_proxy': data.get('isProxy', False) if 'isProxy' in data else False,
                    'is_known_malicious': data.get('abuseConfidenceScore', 0) >= 50,
                    'reputation_score': data.get('abuseConfidenceScore', 0),
                    'categories': [str(c) for c in data.get('reports', [])[:5]],
                    'raw_data': json.dumps(data)
                }
            else:
                logger.warning(f"AbuseIPDB returned status {response.status_code}")

        except ImportError:
            logger.debug("requests library not available for AbuseIPDB")
        except Exception as e:
            logger.error(f"AbuseIPDB check failed for {ip_address}: {e}")

        return None

    def _check_virustotal(self, ip_address):
        """Query VirusTotal for IP reputation."""
        try:
            import requests

            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
            headers = {
                'x-apikey': self.virustotal_key
            }

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                total = sum(stats.values()) if stats else 1

                reputation_score = (malicious / max(total, 1)) * 100

                return {
                    'abuse_confidence': int(reputation_score),
                    'total_reports': malicious,
                    'is_known_malicious': malicious >= 3,
                    'reputation_score': reputation_score,
                    'categories': list(data.get('tags', []))[:5],
                    'raw_data': json.dumps({'malicious': malicious, 'total': total})
                }
            else:
                logger.warning(f"VirusTotal returned status {response.status_code}")

        except ImportError:
            logger.debug("requests library not available for VirusTotal")
        except Exception as e:
            logger.error(f"VirusTotal check failed for {ip_address}: {e}")

        return None

    def _heuristic_check(self, ip_address):
        """
        Heuristic reputation scoring when no API keys are available.
        Uses IP characteristics and attack patterns for basic scoring.
        """
        import ipaddress as ipaddr

        result = self._default_result()
        score = 0

        try:
            ip = ipaddr.ip_address(ip_address)

            # Known malicious IP ranges (examples - simplified)
            suspicious_ranges = [
                ipaddr.ip_network('185.0.0.0/8'),    # Often used for scanning
                ipaddr.ip_network('45.0.0.0/8'),     # Common hosting/VPS
                ipaddr.ip_network('195.0.0.0/8'),    # Eastern European ranges
            ]

            for net in suspicious_ranges:
                if ip in net:
                    score += 20
                    break

            # Check if it's a common VPS/cloud range
            vps_indicators = ['45.', '185.', '195.', '5.', '91.', '77.']
            if any(ip_address.startswith(prefix) for prefix in vps_indicators):
                score += 15
                result['is_vpn'] = True

        except (ValueError, TypeError):
            pass

        result['reputation_score'] = min(score, 100)
        result['abuse_confidence'] = min(score, 100)
        result['is_known_malicious'] = score >= 50
        result['source'] = 'heuristic'

        return result

    def _get_cached(self, ip_address):
        """Get cached reputation data from database."""
        if not self.app:
            return None

        try:
            from app.models import ThreatIntelFeed
            from app import db

            cached = ThreatIntelFeed.query.filter_by(ip_address=ip_address).first()
            if cached:
                # Check if cache is still valid
                if cached.last_checked:
                    age = datetime.utcnow() - cached.last_checked
                    if age < timedelta(hours=self.cache_hours):
                        return {
                            'abuse_confidence': cached.abuse_confidence or 0,
                            'total_reports': cached.total_reports or 0,
                            'is_tor_exit': cached.is_tor_exit or False,
                            'is_vpn': cached.is_vpn or False,
                            'is_proxy': cached.is_proxy or False,
                            'is_known_malicious': (cached.abuse_confidence or 0) >= 50,
                            'reputation_score': cached.abuse_confidence or 0,
                            'source': cached.data_source or 'cache'
                        }
        except Exception as e:
            logger.debug(f"Cache lookup failed: {e}")

        return None

    def _cache_result(self, ip_address, result):
        """Cache reputation result in database."""
        if not self.app:
            return

        try:
            from app.models import ThreatIntelFeed
            from app import db

            existing = ThreatIntelFeed.query.filter_by(ip_address=ip_address).first()
            if existing:
                existing.abuse_confidence = result.get('abuse_confidence', 0)
                existing.total_reports = result.get('total_reports', 0)
                existing.is_tor_exit = result.get('is_tor_exit', False)
                existing.is_vpn = result.get('is_vpn', False)
                existing.is_proxy = result.get('is_proxy', False)
                existing.last_checked = datetime.utcnow()
                existing.data_source = result.get('source', 'unknown')
                existing.raw_response = result.get('raw_data')
            else:
                feed = ThreatIntelFeed(
                    ip_address=ip_address,
                    abuse_confidence=result.get('abuse_confidence', 0),
                    total_reports=result.get('total_reports', 0),
                    is_tor_exit=result.get('is_tor_exit', False),
                    is_vpn=result.get('is_vpn', False),
                    is_proxy=result.get('is_proxy', False),
                    data_source=result.get('source', 'unknown'),
                    raw_response=result.get('raw_data'),
                    last_checked=datetime.utcnow()
                )
                db.session.add(feed)

            db.session.commit()
        except Exception as e:
            logger.debug(f"Cache write failed: {e}")

    def _default_result(self):
        """Return default empty reputation result."""
        return {
            'abuse_confidence': 0,
            'total_reports': 0,
            'is_tor_exit': False,
            'is_vpn': False,
            'is_proxy': False,
            'is_bot': False,
            'is_known_malicious': False,
            'reputation_score': 0,
            'categories': [],
            'source': 'none'
        }
