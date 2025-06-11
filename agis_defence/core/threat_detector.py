"""Threat detection module for AGIS Defence System."""

import logging
from datetime import datetime
import time
import random
from .ai_agent import ai_agent

# Configure logging
logger = logging.getLogger(__name__)

class ThreatDetector:
    def __init__(self):
        self.active_threats = []
        self.blocked_count = 0
        self.last_attack_time = None
        self.threat_types = ['brute_force', 'ddos', 'sql_injection']
        self.threat_sources = ['192.168.1.100', '192.168.1.103']
        self.threat_details = {
            'brute_force': 'Brute force login attempt detected',
            'ddos': 'DDoS attack detected',
            'sql_injection': 'SQL injection attempt detected'
        }
        self.threat_distribution = {
            'brute_force': 1,
            'ddos': 3,
            'sql_injection': 4
        }
        
    def get_active_threats(self):
        """Get list of currently active threats."""
        try:
            # Simulate threat detection
            self._detect_threats()
            
            # Process threats through AI agent
            current_time = time.time()
            # Remove threats older than 5 minutes
            self.active_threats = [
                threat for threat in self.active_threats 
                if current_time - threat['timestamp_unix'] < 300
            ]
            
            # Process new threats through AI agent
            for threat in self.active_threats:
                if not threat.get('processed'):
                    analysis = ai_agent.analyze_threats(threat)
                    threat['processed'] = True
                    threat['ai_response'] = analysis.get('response', 'monitoring')
                    
                    if analysis.get('response') == 'block':
                        self.blocked_count += 1
                        self.threat_distribution[threat['type']] = self.threat_distribution.get(threat['type'], 0) + 1
                    elif analysis.get('response') == 'heal':
                        self.threat_distribution[threat['type']] = self.threat_distribution.get(threat['type'], 0) + 1
            
            return self.active_threats
        except Exception as e:
            logger.error(f"Error getting active threats: {e}")
            return []
    
    def get_blocked_count(self):
        """Get count of blocked attacks."""
        return self.blocked_count
    
    def get_last_attack_time(self):
        """Get timestamp of last detected attack."""
        return self.last_attack_time
        
    def get_threat_distribution(self):
        """Get the distribution of threat types."""
        return self.threat_distribution
        
    def _detect_threats(self):
        """Simulate threat detection."""
        # Randomly detect new threats
        if random.random() < 0.3:  # 30% chance of new threat
            threat_type = random.choice(self.threat_types)
            source_ip = random.choice(self.threat_sources)
            
            new_threat = {
                'type': threat_type,
                'severity': 'high',
                'source': source_ip,
                'ip': source_ip,
                'details': self.threat_details[threat_type],
                'timestamp': datetime.now().isoformat(),
                'timestamp_unix': time.time(),
                'processed': False
            }
            self.active_threats.append(new_threat)
            self.last_attack_time = time.time()
            logger.info(f"New threat detected: {new_threat}")

# Create a global instance
threat_detector = ThreatDetector()