import subprocess
import logging
import json
from typing import Dict, List, Optional, Union
from datetime import datetime
import os
from pathlib import Path
import threading
import time

from ..config import FIREWALL_CONFIG

logger = logging.getLogger(__name__)

class AIFirewall:
    """AI-enhanced firewall with dynamic rule generation."""

    def __init__(self):
        self.config = FIREWALL_CONFIG
        self.blocked_ips = set()
        self.rate_limits = {}
        self.rules_file = Path("firewall_rules.json")
        self._load_existing_rules()
        
        # Start rate limit monitoring
        self.rate_monitor = threading.Thread(target=self._monitor_rates)
        self.rate_monitor.daemon = True
        self.rate_monitor.start()

    def _load_existing_rules(self):
        """Load existing firewall rules from file."""
        try:
            if self.rules_file.exists():
                with open(self.rules_file, 'r') as f:
                    rules = json.load(f)
                    self.blocked_ips = set(rules.get('blocked_ips', []))
                    self.rate_limits = rules.get('rate_limits', {})
        except Exception as e:
            logger.error(f"Error loading firewall rules: {str(e)}")

    def _save_rules(self):
        """Save current rules to file."""
        try:
            rules = {
                'blocked_ips': list(self.blocked_ips),
                'rate_limits': self.rate_limits,
                'last_updated': datetime.now().isoformat()
            }
            with open(self.rules_file, 'w') as f:
                json.dump(rules, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving firewall rules: {str(e)}")

    def block_ip(self, ip: str, reason: str = "Suspicious activity") -> bool:
        """Block an IP address."""
        try:
            if os.name == 'nt':  # Windows
                cmd = f'netsh advfirewall firewall add rule name="AGIS_BLOCK_{ip}" dir=in action=block remoteip={ip}'
            else:  # Linux
                cmd = f'iptables -A INPUT -s {ip} -j DROP'
            
            subprocess.run(cmd, shell=True, check=True)
            self.blocked_ips.add(ip)
            self._save_rules()
            
            logger.info(f"Blocked IP {ip}: {reason}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error blocking IP {ip}: {str(e)}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address."""
        try:
            if os.name == 'nt':  # Windows
                cmd = f'netsh advfirewall firewall delete rule name="AGIS_BLOCK_{ip}"'
            else:  # Linux
                cmd = f'iptables -D INPUT -s {ip} -j DROP'
            
            subprocess.run(cmd, shell=True, check=True)
            self.blocked_ips.discard(ip)
            self._save_rules()
            
            logger.info(f"Unblocked IP {ip}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error unblocking IP {ip}: {str(e)}")
            return False

    def set_rate_limit(self, ip: str, port: int, rate: int):
        """Set rate limit for an IP/port combination."""
        try:
            key = f"{ip}:{port}"
            self.rate_limits[key] = {
                'rate': rate,
                'count': 0,
                'last_reset': datetime.now().timestamp()
            }
            self._save_rules()
            
            logger.info(f"Set rate limit for {key}: {rate} requests/minute")
            return True
            
        except Exception as e:
            logger.error(f"Error setting rate limit: {str(e)}")
            return False

    def check_rate_limit(self, ip: str, port: int) -> bool:
        """Check if a connection should be allowed based on rate limits."""
        key = f"{ip}:{port}"
        
        # Get service-specific or default rate limit
        service_name = self._get_service_name(port)
        max_rate = self.config['rate_limits'].get(
            service_name,
            self.config['rate_limits']['default']
        )
        
        # Initialize rate limit if not exists
        if key not in self.rate_limits:
            self.set_rate_limit(ip, port, max_rate)
        
        limit_info = self.rate_limits[key]
        current_time = datetime.now().timestamp()
        
        # Reset counter if minute has passed
        if current_time - limit_info['last_reset'] >= 60:
            limit_info['count'] = 0
            limit_info['last_reset'] = current_time
        
        # Check and update counter
        if limit_info['count'] >= limit_info['rate']:
            logger.warning(f"Rate limit exceeded for {key}")
            return False
        
        limit_info['count'] += 1
        return True

    def _get_service_name(self, port: int) -> str:
        """Get service name for a port number."""
        services = {
            22: 'ssh',
            80: 'http',
            443: 'https'
        }
        return services.get(port, 'default')

    def _monitor_rates(self):
        """Monitor and reset rate limits periodically."""
        while True:
            try:
                current_time = datetime.now().timestamp()
                for key, limit_info in self.rate_limits.items():
                    if current_time - limit_info['last_reset'] >= 60:
                        limit_info['count'] = 0
                        limit_info['last_reset'] = current_time
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                logger.error(f"Error in rate monitoring: {str(e)}")
                time.sleep(5)  # Wait before retrying

    def handle_threat(self, threat_data: Dict) -> Dict:
        """Handle a detected threat."""
        response = {
            'action_taken': [],
            'success': True
        }

        try:
            # Extract threat information
            ip = threat_data.get('source_ip')
            port = threat_data.get('port')
            severity = threat_data.get('severity', 'LOW')

            if not ip:
                return {'success': False, 'error': 'No IP address provided'}

            # Apply actions based on severity
            if severity in ['HIGH', 'CRITICAL']:
                # Block the IP
                if self.block_ip(ip, reason=str(threat_data)):
                    response['action_taken'].append(f"Blocked IP {ip}")
            
            elif severity == 'MEDIUM':
                # Set strict rate limit
                if port and self.set_rate_limit(ip, port, 10):  # 10 requests/minute
                    response['action_taken'].append(f"Set strict rate limit for {ip}:{port}")
            
            else:  # LOW severity
                # Monitor more closely
                if port:
                    self.set_rate_limit(ip, port, 50)  # 50 requests/minute
                    response['action_taken'].append(f"Set monitoring rate limit for {ip}:{port}")

            return response

        except Exception as e:
            logger.error(f"Error handling threat: {str(e)}")
            return {'success': False, 'error': str(e)}

    def get_status(self) -> Dict:
        """Get current firewall status."""
        return {
            'blocked_ips': list(self.blocked_ips),
            'rate_limits': self.rate_limits,
            'last_updated': datetime.now().isoformat()
        }


if __name__ == "__main__":
    # Example usage
    firewall = AIFirewall()
    
    # Example threat
    threat = {
        'source_ip': '192.168.1.100',
        'port': 22,
        'severity': 'HIGH',
        'type': 'brute_force_attempt'
    }
    
    # Handle threat
    result = firewall.handle_threat(threat)
    print("Threat handling result:", result)
    
    # Check status
    status = firewall.get_status()
    print("\nFirewall status:", json.dumps(status, indent=2)) 