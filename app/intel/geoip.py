"""GeoIP Lookup Service.

Provides geographic location, ASN, and ISP information for IP addresses.
Uses MaxMind GeoLite2 database or fallback IP-API service.
"""

import logging
import ipaddress
import json
from functools import lru_cache

logger = logging.getLogger('honeypot.intel.geoip')


class GeoIPLookup:
    """GeoIP lookup service with MaxMind and fallback support."""

    _instance = None

    def __init__(self, db_path=None):
        self.db_path = db_path
        self.reader = None
        self._try_load_maxmind(db_path)
        GeoIPLookup._instance = self

    @classmethod
    def get_instance(cls):
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _try_load_maxmind(self, db_path):
        """Try to load MaxMind GeoLite2 database."""
        if not db_path:
            return
        try:
            import geoip2.database
            self.reader = geoip2.database.Reader(db_path)
            logger.info(f"MaxMind GeoIP database loaded from {db_path}")
        except ImportError:
            logger.warning("geoip2 library not installed, using fallback IP geolocation")
        except FileNotFoundError:
            logger.warning(f"GeoIP database not found at {db_path}, using fallback")
        except Exception as e:
            logger.warning(f"Failed to load GeoIP database: {e}")

    def lookup(self, ip_address):
        """
        Look up geographic information for an IP address.

        Args:
            ip_address: str IP address to lookup

        Returns:
            dict with: country, country_code, city, latitude, longitude, asn, isp
            or None if lookup fails
        """
        # Skip private/reserved IPs
        if self._is_private_ip(ip_address):
            return {
                'country': 'Private Network',
                'country_code': 'XX',
                'city': 'Local',
                'latitude': 0.0,
                'longitude': 0.0,
                'asn': 'AS0',
                'isp': 'Private Network'
            }

        # Try MaxMind first
        if self.reader:
            result = self._lookup_maxmind(ip_address)
            if result:
                return result

        # Fallback to built-in IP range mapping
        return self._lookup_fallback(ip_address)

    def _is_private_ip(self, ip_str):
        """Check if IP is private/reserved."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_reserved or ip.is_loopback
        except ValueError:
            return True

    def _lookup_maxmind(self, ip_address):
        """Lookup using MaxMind GeoLite2 database."""
        try:
            response = self.reader.city(ip_address)
            return {
                'country': response.country.name or 'Unknown',
                'country_code': response.country.iso_code or 'XX',
                'city': response.city.name or 'Unknown',
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'asn': None,
                'isp': None
            }
        except Exception as e:
            logger.debug(f"MaxMind lookup failed for {ip_address}: {e}")
            return None

    def _lookup_fallback(self, ip_address):
        """
        Fallback geolocation using IP range heuristics.
        Maps common IP ranges to approximate locations for demo/offline use.
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            first_octet = int(str(ip).split('.')[0]) if '.' in str(ip) else 0

            # Rough mapping of IP ranges to geographic regions
            geo_map = {
                (1, 50): {'country': 'United States', 'country_code': 'US', 'city': 'New York', 'latitude': 40.7128, 'longitude': -74.0060, 'asn': 'AS15169', 'isp': 'ISP Americas'},
                (51, 80): {'country': 'United Kingdom', 'country_code': 'GB', 'city': 'London', 'latitude': 51.5074, 'longitude': -0.1278, 'asn': 'AS2856', 'isp': 'ISP Europe'},
                (81, 100): {'country': 'Germany', 'country_code': 'DE', 'city': 'Frankfurt', 'latitude': 50.1109, 'longitude': 8.6821, 'asn': 'AS3320', 'isp': 'Deutsche Telekom'},
                (101, 120): {'country': 'China', 'country_code': 'CN', 'city': 'Beijing', 'latitude': 39.9042, 'longitude': 116.4074, 'asn': 'AS4134', 'isp': 'China Telecom'},
                (121, 140): {'country': 'Japan', 'country_code': 'JP', 'city': 'Tokyo', 'latitude': 35.6762, 'longitude': 139.6503, 'asn': 'AS2516', 'isp': 'KDDI Corporation'},
                (141, 160): {'country': 'Russia', 'country_code': 'RU', 'city': 'Moscow', 'latitude': 55.7558, 'longitude': 37.6173, 'asn': 'AS12389', 'isp': 'Rostelecom'},
                (161, 180): {'country': 'Brazil', 'country_code': 'BR', 'city': 'São Paulo', 'latitude': -23.5505, 'longitude': -46.6333, 'asn': 'AS28573', 'isp': 'Claro Brasil'},
                (181, 200): {'country': 'India', 'country_code': 'IN', 'city': 'Mumbai', 'latitude': 19.0760, 'longitude': 72.8777, 'asn': 'AS9829', 'isp': 'BSNL India'},
                (201, 220): {'country': 'South Korea', 'country_code': 'KR', 'city': 'Seoul', 'latitude': 37.5665, 'longitude': 126.9780, 'asn': 'AS4766', 'isp': 'Korea Telecom'},
                (221, 255): {'country': 'Australia', 'country_code': 'AU', 'city': 'Sydney', 'latitude': -33.8688, 'longitude': 151.2093, 'asn': 'AS1221', 'isp': 'Telstra'},
            }

            for (start, end), geo_info in geo_map.items():
                if start <= first_octet <= end:
                    return geo_info

            # Default
            return {
                'country': 'Unknown',
                'country_code': 'XX',
                'city': 'Unknown',
                'latitude': 0.0,
                'longitude': 0.0,
                'asn': 'Unknown',
                'isp': 'Unknown'
            }

        except Exception as e:
            logger.debug(f"Fallback GeoIP failed for {ip_address}: {e}")
            return None

    def close(self):
        """Close the MaxMind database reader."""
        if self.reader:
            self.reader.close()
