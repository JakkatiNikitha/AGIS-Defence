"""Core module for shared instances across the AGIS Defence System."""

from agis_defence.core.ai_agent import ai_agent
from agis_defence.core.system_monitor import get_stats, get_network_stats
from agis_defence.core.threat_detector import threat_detector
from agis_defence.firewall.manager import FirewallManager
from agis_defence.models.historical_data import HistoricalData
from agis_defence.healing.healer import SystemHealer

# Initialize shared instances
system_monitor = SystemMonitor()
firewall = FirewallManager()
historical_data = HistoricalData()
healer = SystemHealer()

__all__ = ['ai_agent', 'get_stats', 'get_network_stats', 'threat_detector'] 