"""Threat Intelligence Module.

Provides GeoIP lookups, IP reputation scoring, and external threat feed integration.
"""

from app.intel.geoip import GeoIPLookup
from app.intel.reputation import ReputationChecker

__all__ = ['GeoIPLookup', 'ReputationChecker']
