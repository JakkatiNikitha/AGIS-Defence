import subprocess
import ipaddress
from typing import Dict, List, Any
from datetime import datetime
import logging
import platform
import ctypes
import os

class FirewallManager:
    def __init__(self):
        self.logger = logging.getLogger('firewall_manager')
        self.blocked_ips = set()
        self.rules = []
        self.last_updated = datetime.now()
        self.is_windows = platform.system().lower() == 'windows'
        self.has_admin = self._check_admin()
        self.simulation_mode = not self.has_admin
        self.simulation_rules = []
        self._initialize_firewall()
    
    def _check_admin(self) -> bool:
        """Check if the program has administrator privileges."""
        try:
            if self.is_windows:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception as e:
            self.logger.error(f"Error checking admin privileges: {str(e)}")
            return False
    
    def _initialize_firewall(self):
        """Initialize firewall with default rules."""
        if self.simulation_mode:
            self.logger.warning("Running without administrator privileges. Firewall management will be simulated.")
            # Add default simulation rules
            self.simulation_rules = [
                {
                    'name': 'AGIS_DEFAULT_INBOUND',
                    'direction': 'in',
                    'action': 'allow',
                    'description': 'Default inbound rule (simulation)',
                    'enabled': True
                },
                {
                    'name': 'AGIS_DEFAULT_OUTBOUND',
                    'direction': 'out',
                    'action': 'allow',
                    'description': 'Default outbound rule (simulation)',
                    'enabled': True
                }
            ]
            return
            
        try:
            if self.is_windows:
                # Enable Windows Firewall
                subprocess.run(['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'], check=True)
                
                # Allow established connections
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    'name="AGIS_ALLOW_ESTABLISHED"',
                    'dir=in', 'action=allow',
                    'description="Allow established connections"'
                ], check=True)
            else:
                # Linux iptables commands
                subprocess.run(['iptables', '-F'], check=True)
                subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'], check=True)
                subprocess.run(['iptables', '-P', 'FORWARD', 'ACCEPT'], check=True)
                subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)
                subprocess.run([
                    'iptables', '-A', 'INPUT', 
                    '-m', 'state', 
                    '--state', 'ESTABLISHED,RELATED', 
                    '-j', 'ACCEPT'
                ], check=True)
            
            self.logger.info("Firewall initialized with default rules")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to initialize firewall: {e}")
            if not self.has_admin:
                self.logger.warning("This error may be due to lack of administrator privileges")
            self.simulation_mode = True
    
    def get_status(self) -> Dict[str, Any]:
        """Get current firewall status."""
        try:
            status = {
                'active': True,  # Always active in simulation mode
                'active_rules': len(self.rules) if not self.simulation_mode else len(self.simulation_rules),
                'blocked_ips': list(self.blocked_ips),
                'last_updated': self.last_updated.isoformat(),
                'rules': self.rules if not self.simulation_mode else self.simulation_rules,
                'has_admin': self.has_admin,
                'mode': 'simulation' if self.simulation_mode else 'active'
            }
            
            if self.simulation_mode:
                status.update({
                    'simulation_info': {
                        'blocked_ips_count': len(self.blocked_ips),
                        'active_rules_count': len(self.simulation_rules),
                        'last_rule_update': self.last_updated.isoformat()
                    }
                })
                
            return status
        except Exception as e:
            self.logger.error(f"Error getting firewall status: {str(e)}")
            return {
                'active': False,
                'active_rules': 0,
                'blocked_ips': [],
                'last_updated': datetime.now().isoformat(),
                'rules': [],
                'has_admin': False,
                'mode': 'error',
                'error': str(e)
            }
    
    def block_ip(self, ip: str) -> Dict[str, Any]:
        """Block specific IP address."""
        try:
            # Validate IP address
            ipaddress.ip_address(ip)
            
            if ip in self.blocked_ips:
                return {
                    'status': 'already_blocked',
                    'message': f'IP {ip} is already blocked'
                }
            
            if self.simulation_mode:
                self.blocked_ips.add(ip)
                self.last_updated = datetime.now()
                new_rule = {
                    'name': f'BLOCK_{ip.replace(".", "_")}',
                    'direction': 'in',
                    'action': 'block',
                    'source': ip,
                    'description': f'Blocked IP {ip} (simulation)',
                    'added': datetime.now().isoformat(),
                    'enabled': True
                }
                self.simulation_rules.append(new_rule)
                return {
                    'status': 'simulated',
                    'message': f'IP {ip} blocked (simulation mode)',
                    'rule': new_rule
                }
            
            # Add IP to blocked list
            if self.is_windows:
                rule_name = f'AGIS_BLOCK_{ip.replace(".", "_")}'
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name="{rule_name}"',
                    'dir=in', 'action=block',
                    f'remoteip={ip}',
                    f'description="Blocked by AGIS Defence System"'
                ], check=True)
            else:
                subprocess.run([
                    'iptables', '-A', 'INPUT', 
                    '-s', ip, 
                    '-j', 'DROP'
                ], check=True)
            
            self.blocked_ips.add(ip)
            self.last_updated = datetime.now()
            
            self.logger.info(f"Blocked IP: {ip}")
            return {
                'status': 'success',
                'message': f'Successfully blocked IP {ip}'
            }
            
        except ValueError:
            self.logger.error(f"Invalid IP address: {ip}")
            return {
                'status': 'error',
                'message': f'Invalid IP address: {ip}'
            }
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block IP {ip}: {e}")
            return {
                'status': 'error',
                'message': f'Failed to block IP {ip}: {str(e)}'
            }
        except Exception as e:
            self.logger.error(f"Unexpected error blocking IP {ip}: {str(e)}")
            return {
                'status': 'error',
                'message': f'Unexpected error: {str(e)}'
            }
    
    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        """Unblock specific IP address."""
        try:
            # Validate IP address
            ipaddress.ip_address(ip)
            
            if ip not in self.blocked_ips:
                return {
                    'status': 'not_blocked',
                    'message': f'IP {ip} is not blocked'
                }
            
            if not self.has_admin:
                self.blocked_ips.remove(ip)
                self.last_updated = datetime.now()
                return {
                    'status': 'simulated',
                    'message': f'IP {ip} unblocked (simulation mode)'
                }
            
            # Remove IP from blocked list
            if self.is_windows:
                rule_name = f'AGIS_BLOCK_{ip.replace(".", "_")}'
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name="{rule_name}"'
                ], check=True)
            else:
                subprocess.run([
                    'iptables', '-D', 'INPUT',
                    '-s', ip,
                    '-j', 'DROP'
                ], check=True)
            
            self.blocked_ips.remove(ip)
            self.last_updated = datetime.now()
            
            self.logger.info(f"Unblocked IP: {ip}")
            return {
                'status': 'success',
                'message': f'Successfully unblocked IP {ip}'
            }
            
        except ValueError:
            self.logger.error(f"Invalid IP address: {ip}")
            return {
                'status': 'error',
                'message': f'Invalid IP address: {ip}'
            }
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to unblock IP {ip}: {e}")
            return {
                'status': 'error',
                'message': f'Failed to unblock IP {ip}: {str(e)}'
            }
        except Exception as e:
            self.logger.error(f"Unexpected error unblocking IP {ip}: {str(e)}")
            return {
                'status': 'error',
                'message': f'Unexpected error: {str(e)}'
            }
    
    def block_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Block threat based on its characteristics."""
        threat_type = threat_data.get('type')
        source = threat_data.get('source')
        
        if not source:
            return {
                'status': 'error',
                'message': 'No source IP provided for threat'
            }
        
        if not self.has_admin:
            self.blocked_ips.add(source)
            self.last_updated = datetime.now()
            return {
                'status': 'simulated',
                'message': f'Threat from {source} blocked (simulation mode)'
            }
        
        # Add specific rules based on threat type
        rules = self._generate_threat_rules(threat_type, source)
        
        try:
            for rule in rules:
                if self.is_windows:
                    subprocess.run(rule, check=True)
                else:
                    subprocess.run(['iptables'] + rule, check=True)
                    
                self.rules.append({
                    'type': threat_type,
                    'source': source,
                    'rule': ' '.join(rule),
                    'added': datetime.now().isoformat()
                })
            
            self.blocked_ips.add(source)
            self.last_updated = datetime.now()
            
            return {
                'status': 'success',
                'message': f'Successfully blocked threat from {source}',
                'rules_added': len(rules)
            }
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block threat {threat_type} from {source}: {e}")
            return {
                'status': 'error',
                'message': f'Failed to block threat: {str(e)}'
            }
    
    def _generate_threat_rules(self, threat_type: str, source: str) -> List[List[str]]:
        """Generate firewall rules based on threat type."""
        rules = []
        
        if self.is_windows:
            # Basic block rule
            rule_name = f'AGIS_BLOCK_{source.replace(".", "_")}_{threat_type}'
            rules.append([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name="{rule_name}"',
                'dir=in', 'action=block',
                f'remoteip={source}',
                f'description="Blocked {threat_type} threat from {source}"'
            ])
            
            if threat_type == 'ddos':
                # Rate limiting rule (using connection limit)
                rule_name = f'AGIS_RATELIMIT_{source.replace(".", "_")}'
                rules.append([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name="{rule_name}"',
                    'dir=in', 'action=block',
                    f'remoteip={source}',
                    'protocol=TCP',
                    'description="Rate limiting for DDoS protection"'
                ])
            
            elif threat_type in ['brute_force', 'ssh_attack']:
                # Block common remote access ports
                for port in ['22', '3389']:  # SSH and RDP ports
                    rule_name = f'AGIS_BLOCK_{source.replace(".", "_")}_{threat_type}_{port}'
                    rules.append([
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name="{rule_name}"',
                        'dir=in', 'action=block',
                        f'remoteip={source}',
                        f'localport={port}',
                        'protocol=TCP',
                        f'description="Blocked {threat_type} attempt on port {port}"'
                    ])
        else:
            # Linux iptables rules
            rules.append(['-A', 'INPUT', '-s', source, '-j', 'DROP'])
            
            if threat_type == 'ddos':
                rules.extend([
                    ['-A', 'INPUT', '-s', source, 
                     '-m', 'limit', '--limit', '5/minute', '--limit-burst', '10', 
                     '-j', 'ACCEPT'],
                    ['-A', 'INPUT', '-s', source, 
                     '-m', 'connlimit', '--connlimit-above', '20', 
                     '-j', 'DROP']
                ])
            
            elif threat_type == 'brute_force':
                rules.extend([
                    ['-A', 'INPUT', '-s', source, '-p', 'tcp', '--dport', '22', '-j', 'DROP'],
                    ['-A', 'INPUT', '-s', source, '-p', 'tcp', '--dport', '3389', '-j', 'DROP']
                ])
        
        return rules 