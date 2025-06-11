from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import numpy as np
import logging
from ..config import ATTACK_TYPES
import psutil
import scapy.all as scapy
import time

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create console handler if no handlers exist
if not logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

class ThreatDetector:
    def __init__(self):
        self.active_threats = []
        self.threat_history = {}
        self.blocked_ips = set()
        self.detection_stats = {
            attack_type['id']: {
                'detected': 0,
                'blocked': 0,
                'healed': 0,
                'lastSeen': None
            }
            for category in ATTACK_TYPES.values()
            for attack_type in category['types']
        }
        self.anomaly_thresholds = {
            'cpu_usage': 90,  # CPU usage percentage
            'memory_usage': 90,  # Memory usage percentage
            'disk_usage': 90,  # Disk usage percentage
            'network_traffic': 1000000,  # bytes per second
            'connection_rate': 1000,  # connections per minute
            'error_rate': 100  # errors per minute
        }
        self.last_scan_time = datetime.now()
        self.threat_distribution = {}
        self.last_cleanup = time.time()
        self.recent_ai_actions = []  # Store recent AI actions
        self.healed_threats = {}  # Track healed threats
        self._initialize_threat_distribution()
        
    def _initialize_threat_distribution(self):
        """Initialize threat distribution with zero counts"""
        self.threat_distribution = {
            'brute_force': 0,
            'ddos': 0,
            'sql_injection': 0,
            'xss': 0,
            'high_cpu_usage': 0,
            'high_memory_usage': 0,
            'port_scan': 0
        }
        
    def update_threat_distribution(self, threat_type: str, increment: bool = True):
        """Update threat distribution counts"""
        if threat_type in self.threat_distribution:
            if increment:
                self.threat_distribution[threat_type] += 1
            else:
                self.threat_distribution[threat_type] = max(0, self.threat_distribution[threat_type] - 1)
                
    def cleanup_old_threats(self):
        """Remove expired threats and update distribution"""
        current_time = time.time()
        
        # Keep track of removed threats to update distribution
        removed_threats = set()
        
        # Remove threats older than 5 minutes
        self.active_threats = [
            threat for threat in self.active_threats 
            if current_time - threat.get('timestamp_unix', 0) < 300
        ]
        
        # Update distribution for removed threats
        for threat_type in self.threat_distribution:
            active_count = sum(1 for threat in self.active_threats 
                             if threat.get('type') == threat_type)
            self.threat_distribution[threat_type] = active_count
        
    def detect_threats(self) -> List[Dict]:
        """Detect potential security threats."""
        current_time = datetime.now()
        threats = []
        
        try:
            # Network-based threat detection
            network_threats = self._detect_network_threats()
            threats.extend(network_threats)
            
            # System-based threat detection
            system_threats = self._detect_system_threats()
            threats.extend(system_threats)
            
            # Update active threats
            self._update_active_threats(threats)
            
            # Update scan time
            self.last_scan_time = current_time
            
            return threats
        
        except Exception as e:
            logger.error(f"Error in threat detection: {str(e)}")
            return []
    
    def _detect_network_threats(self) -> List[Dict]:
        """Detect network-based threats."""
        threats = []
        try:
            # Monitor network connections
            connections = psutil.net_connections()
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    # Check for suspicious ports
                    if conn.raddr and conn.raddr.port in [22, 23, 3389]:  # SSH, Telnet, RDP
                        source_ip = conn.raddr.ip
                        threat = {
                            'type': 'suspicious_connection',
                            'source': source_ip,
                            'severity': 'medium',
                            'timestamp': datetime.now().isoformat(),
                            'details': f'Suspicious connection on port {conn.raddr.port}'
                        }
                        threats.append(threat)
                        
                    # Check for brute force attempts
                    if self._is_brute_force_attempt(conn.raddr.ip if conn.raddr else None):
                        source_ip = conn.raddr.ip if conn.raddr else 'unknown'
                        threat = {
                            'type': 'brute_force',
                            'source': source_ip,
                            'severity': 'high',
                            'timestamp': datetime.now().isoformat(),
                            'details': 'Multiple failed connection attempts detected'
                        }
                        threats.append(threat)
            
            return threats
            
        except Exception as e:
            logger.error(f"Error in network threat detection: {str(e)}")
            return []
    
    def _detect_system_threats(self) -> List[Dict]:
        """Detect system-based threats."""
        threats = []
        try:
            # Monitor CPU usage for potential DOS
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                threat = {
                    'type': 'high_cpu_usage',
                    'source': 'system',
                    'severity': 'medium',
                    'timestamp': datetime.now().isoformat(),
                    'details': f'High CPU usage detected: {cpu_percent}%'
                }
                threats.append(threat)
            
            # Monitor memory usage
            memory = psutil.virtual_memory()
            if memory.percent > 90:
                threat = {
                    'type': 'high_memory_usage',
                    'source': 'system',
                    'severity': 'medium',
                    'timestamp': datetime.now().isoformat(),
                    'details': f'High memory usage detected: {memory.percent}%'
                }
                threats.append(threat)
            
            return threats
            
        except Exception as e:
            logger.error(f"Error in system threat detection: {str(e)}")
            return []
    
    def _is_brute_force_attempt(self, ip: Optional[str]) -> bool:
        """Detect potential brute force attacks based on connection frequency."""
        if not ip:
            return False
            
        current_time = datetime.now()
        threshold_time = current_time - timedelta(minutes=5)
        
        # Initialize history for new IP
        if ip not in self.threat_history:
            self.threat_history[ip] = {
                'connection_attempts': [],
                'last_seen': current_time
            }
        
        # Update connection history
        history = self.threat_history[ip]
        history['connection_attempts'].append(current_time)
        history['last_seen'] = current_time
        
        # Remove old attempts
        history['connection_attempts'] = [
            attempt for attempt in history['connection_attempts']
            if attempt > threshold_time
        ]
        
        # Check if number of recent attempts exceeds threshold
        return len(history['connection_attempts']) > 10
    
    def _update_active_threats(self, new_threats: List[Dict]):
        """Update the list of active threats."""
        current_time = datetime.now()
        threat_timeout = timedelta(minutes=15)
        
        # Remove expired threats
        self.active_threats = [
            threat for threat in self.active_threats
            if datetime.fromisoformat(threat['timestamp']) > (current_time - threat_timeout)
        ]
        
        # Add new threats
        for threat in new_threats:
            threat_key = f"{threat['type']}:{threat['source']}"
            
            # Check if threat already exists
            existing = next(
                (t for t in self.active_threats 
                 if f"{t['type']}:{t['source']}" == threat_key),
                None
            )
            
            if existing:
                # Update existing threat
                existing.update(threat)
            else:
                # Add new threat
                self.active_threats.append(threat)
    
    def get_active_threats(self) -> List[Dict]:
        """Get list of currently active threats."""
        try:
            # Cleanup old threats before returning
            self.cleanup_old_threats()
            return self.active_threats
        except Exception as e:
            logger.error(f"Error getting active threats: {e}")
            return []
        
    def detect_anomalies(self, system_stats: Dict[str, Any], network_stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect system and network anomalies."""
        anomalies = []
        current_time = datetime.now()
        
        try:
            # Check system metrics
            if system_stats.get('cpu', 0) > self.anomaly_thresholds['cpu_usage']:
                anomalies.append({
                    'type': 'high_cpu',
                    'severity': 'medium',
                    'source': 'system',
                    'details': f"High CPU usage: {system_stats['cpu']}%",
                    'detected_at': current_time
                })
                
            if system_stats.get('memory', 0) > self.anomaly_thresholds['memory_usage']:
                anomalies.append({
                    'type': 'high_memory',
                    'severity': 'medium',
                    'source': 'system',
                    'details': f"High memory usage: {system_stats['memory']}%",
                    'detected_at': current_time
                })
                
            if system_stats.get('disk', 0) > self.anomaly_thresholds['disk_usage']:
                anomalies.append({
                    'type': 'high_disk',
                    'severity': 'medium',
                    'source': 'system',
                    'details': f"High disk usage: {system_stats['disk']}%",
                    'detected_at': current_time
                })
                
            # Check network metrics
            if network_stats.get('bandwidth_usage', 0) > self.anomaly_thresholds['network_traffic']:
                anomalies.append({
                    'type': 'high_traffic',
                    'severity': 'high',
                    'source': 'network',
                    'details': f"High network traffic: {network_stats['bandwidth_usage']} bytes/s",
                    'detected_at': current_time
                })
                
            if network_stats.get('connection_rate', 0) > self.anomaly_thresholds['connection_rate']:
                anomalies.append({
                    'type': 'high_connections',
                    'severity': 'high',
                    'source': 'network',
                    'details': f"High connection rate: {network_stats['connection_rate']} conn/min",
                    'detected_at': current_time
                })
                
            # Add anomalies to active threats
            for anomaly in anomalies:
                self._add_active_threat(anomaly)
                
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {str(e)}")
            return []
            
    def _add_active_threat(self, threat: Dict[str, Any]) -> None:
        """Add a threat to active threats list."""
        try:
            threat_type = threat.get('type', 'unknown')
            threat_source = threat.get('source', 'unknown')
            threat_key = f"{threat_type}:{threat_source}"
            
            # Update detection stats
            if threat_type in self.detection_stats:
                self.detection_stats[threat_type]['detected'] += 1
                self.detection_stats[threat_type]['lastSeen'] = datetime.now()
            
            # Add to active threats if not already present
            if not any(t.get('type') == threat_type and t.get('source') == threat_source 
                      for t in self.active_threats):
                threat['detected_at'] = datetime.now()
                self.active_threats.append(threat)
            
            # Update threat history
            if threat_key not in self.threat_history:
                self.threat_history[threat_key] = []
            self.threat_history[threat_key].append({
                'timestamp': datetime.now().isoformat(),
                'severity': threat.get('severity', 'low'),
                'details': threat.get('details', ''),
                'type': threat_type,
                'source': threat_source
            })
            
            logger.info(f"Added active threat: {threat_type} from {threat_source}")
            
            # Update threat distribution
            self.update_threat_distribution(threat_type, True)
            
        except Exception as e:
            logger.error(f"Error adding active threat: {str(e)}")
    
    def get_detection_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all types of attacks."""
        try:
            return self.detection_stats
        except Exception as e:
            logger.error(f"Error getting detection stats: {str(e)}")
            return {}
    
    def get_threat_trends(self) -> Dict[str, Any]:
        """Get threat detection trends."""
        try:
            current_time = datetime.now()
            day_ago = current_time - timedelta(days=1)
            
            # Calculate daily statistics
            daily_stats = {
                'total': 0,
                'blocked': 0,
                'critical': 0
            }
            
            # Calculate threat distribution
            distribution = {}
            
            for threat_id, history in self.threat_history.items():
                for event in history['events']:
                    if event['timestamp'] > day_ago:
                        daily_stats['total'] += 1
                        if event.get('action') == 'block':
                            daily_stats['blocked'] += 1
                        if event.get('severity') == 'critical':
                            daily_stats['critical'] += 1
                        
                        threat_type = history['type']
                        distribution[threat_type] = distribution.get(threat_type, 0) + 1
            
            return {
                'daily': daily_stats,
                'distribution': distribution
            }
        except Exception as e:
            logger.error(f"Error getting threat trends: {str(e)}")
            return {
                'daily': {'total': 0, 'blocked': 0, 'critical': 0},
                'distribution': {}
            }
    
    def detect_network_threats(self, network_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect network-based threats."""
        try:
            threats = []
            
            # Check for DDoS
            if self._detect_ddos(network_data):
                threats.append(self._create_threat('ddos', 'network', network_data['source']))
            
            # Check for port scanning
            if self._detect_port_scan(network_data):
                threats.append(self._create_threat('port_scan', 'network', network_data['source']))
            
            # Check for SYN flood
            if self._detect_syn_flood(network_data):
                threats.append(self._create_threat('syn_flood', 'network', network_data['source']))
            
            return threats
        except Exception as e:
            logger.error(f"Error detecting network threats: {str(e)}")
            return []
    
    def detect_intrusion_attempts(self, auth_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect intrusion attempts."""
        try:
            threats = []
            
            # Check for brute force
            if self._detect_brute_force(auth_data):
                threats.append(self._create_threat('brute_force', 'intrusion', auth_data['source']))
            
            # Check for SSH attacks
            if self._detect_ssh_attack(auth_data):
                threats.append(self._create_threat('ssh_attack', 'intrusion', auth_data['source']))
            
            return threats
        except Exception as e:
            logger.error(f"Error detecting intrusion attempts: {str(e)}")
            return []
    
    def detect_malware(self, system_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect malware activity."""
        try:
            threats = []
            
            # Check for ransomware
            if self._detect_ransomware(system_data):
                threats.append(self._create_threat('ransomware', 'malware', 'system'))
            
            # Check for cryptomining
            if self._detect_cryptomining(system_data):
                threats.append(self._create_threat('cryptominer', 'malware', 'system'))
            
            return threats
        except Exception as e:
            logger.error(f"Error detecting malware: {str(e)}")
            return []
    
    def _create_threat(self, threat_type: str, category: str, source: str, severity: str = "medium", details: str = None):
        """Create and record a new threat."""
        try:
            current_time = time.time()
            threat = {
                'type': threat_type,
                'category': category,
                'source': source,
                'severity': severity,
                'details': details or f"Detected {threat_type} from {source}",
                'timestamp': datetime.now().isoformat(),
                'timestamp_unix': current_time,
                'action_taken': 'detect'  # Default action
            }
            
            # Add to active threats
            self.active_threats.append(threat)
            
            # Update threat distribution
            self.update_threat_distribution(threat_type, True)
            
            # Determine and record AI action
            ai_action = self._determine_ai_action(threat)
            self._record_ai_action(ai_action)
            
            # Cleanup old threats periodically
            if current_time - self.last_cleanup > 60:  # Cleanup every minute
                self.cleanup_old_threats()
                self.last_cleanup = current_time
            
            return threat
            
        except Exception as e:
            logger.error(f"Error creating threat: {str(e)}")
            return None
    
    def _determine_ai_action(self, threat: dict) -> dict:
        """Determine appropriate AI action based on threat characteristics."""
        current_time = datetime.now().isoformat()
        action = {
            'timestamp': current_time,
            'threat_type': threat['type'],
            'severity': threat['severity'],
            'source': threat['source'],
            'details': threat['details']
        }

        # Determine if healing is possible for this threat
        healing_strategy = self._get_healing_strategy(threat)
        
        # Determine action type based on threat characteristics and healing possibility
        if threat['severity'] == 'critical':
            if healing_strategy:
                action['type'] = 'heal'
                action['response'] = f"Automatic threat remediation: {healing_strategy['description']}"
                action['healing_steps'] = healing_strategy['steps']
            else:
                action['type'] = 'block'
                action['response'] = 'Immediate IP blocking and system isolation'
        elif threat['severity'] == 'high':
            if healing_strategy:
                action['type'] = 'heal'
                action['response'] = f"Threat remediation: {healing_strategy['description']}"
                action['healing_steps'] = healing_strategy['steps']
            else:
                action['type'] = 'restrict'
                action['response'] = 'Traffic restriction and enhanced monitoring'
        else:
            action['type'] = 'monitor'
            action['response'] = 'Continuous monitoring and analysis'

        # Add AI confidence level
        action['ai_confidence'] = self._calculate_ai_confidence(threat)
        
        return action

    def _get_healing_strategy(self, threat: dict) -> Optional[dict]:
        """Determine healing strategy based on threat type."""
        healing_strategies = {
            'sql_injection': {
                'description': 'SQL Injection remediation',
                'steps': [
                    'Sanitize affected database inputs',
                    'Apply WAF rules to block SQL injection patterns',
                    'Reset affected database connections',
                    'Verify database integrity'
                ]
            },
            'brute_force': {
                'description': 'Brute Force attack remediation',
                'steps': [
                    'Temporarily increase login attempt threshold',
                    'Enable additional authentication factors',
                    'Reset affected account lockouts',
                    'Update password policies'
                ]
            },
            'ddos': {
                'description': 'DDoS attack mitigation',
                'steps': [
                    'Enable traffic rate limiting',
                    'Activate DDoS protection rules',
                    'Scale resources to handle load',
                    'Filter malicious traffic patterns'
                ]
            },
            'high_cpu_usage': {
                'description': 'System resource optimization',
                'steps': [
                    'Identify resource-intensive processes',
                    'Terminate suspicious processes',
                    'Adjust system resource limits',
                    'Apply performance optimization'
                ]
            },
            'high_memory_usage': {
                'description': 'Memory usage optimization',
                'steps': [
                    'Clear system cache',
                    'Release unused memory',
                    'Restart memory-intensive services',
                    'Apply memory limits'
                ]
            }
        }
        
        return healing_strategies.get(threat['type'])

    def attempt_heal(self, threat: dict) -> bool:
        """Attempt to heal/remediate a threat."""
        try:
            healing_strategy = self._get_healing_strategy(threat)
            if not healing_strategy:
                return False

            # Record healing attempt
            if threat['type'] not in self.healed_threats:
                self.healed_threats[threat['type']] = {
                    'attempts': 0,
                    'successes': 0,
                    'last_attempt': None
                }

            self.healed_threats[threat['type']]['attempts'] += 1
            self.healed_threats[threat['type']]['last_attempt'] = datetime.now()

            # Execute healing steps
            success = self._execute_healing_steps(threat, healing_strategy['steps'])
            
            if success:
                self.healed_threats[threat['type']]['successes'] += 1
                # Update threat status
                threat['status'] = 'healed'
                threat['healed_at'] = datetime.now().isoformat()
                
            return success

        except Exception as e:
            logger.error(f"Error attempting to heal threat: {str(e)}")
            return False

    def _execute_healing_steps(self, threat: dict, steps: List[str]) -> bool:
        """Execute healing steps for a threat."""
        try:
            for step in steps:
                # Log healing step
                logger.info(f"Executing healing step for {threat['type']}: {step}")
                
                # Here you would implement the actual healing logic for each step
                # For now, we'll simulate success
                time.sleep(0.1)  # Simulate step execution
                
            return True
        except Exception as e:
            logger.error(f"Error executing healing steps: {str(e)}")
            return False

    def get_healing_stats(self) -> dict:
        """Get statistics about healing attempts."""
        return {
            threat_type: {
                'success_rate': (stats['successes'] / stats['attempts'] * 100 
                               if stats['attempts'] > 0 else 0),
                'total_attempts': stats['attempts'],
                'last_attempt': stats['last_attempt'].isoformat() 
                               if stats['last_attempt'] else None
            }
            for threat_type, stats in self.healed_threats.items()
        }

    def _record_ai_action(self, action: dict):
        """Record an AI action in the recent actions list."""
        self.recent_ai_actions.append(action)
        # Keep only last 20 actions
        self.recent_ai_actions = self.recent_ai_actions[-20:]

    def _calculate_ai_confidence(self, threat: dict) -> float:
        """Calculate AI confidence level for the threat assessment."""
        base_confidence = 0.85  # Base confidence level
        
        # Adjust confidence based on threat characteristics
        if threat['severity'] == 'critical':
            base_confidence += 0.1
        elif threat['severity'] == 'high':
            base_confidence += 0.05
            
        # Adjust based on threat type
        if threat['type'] in ['sql_injection', 'brute_force']:
            base_confidence += 0.05  # Higher confidence for well-defined threats
            
        return min(0.99, base_confidence)  # Cap at 99%

    def get_recent_ai_actions(self, limit: int = 5) -> List[dict]:
        """Get the most recent AI actions."""
        return self.recent_ai_actions[-limit:]
    
    def _determine_severity(self, threat_type: str) -> str:
        """Determine threat severity based on type and context."""
        high_severity_threats = {'ransomware', 'ddos', 'apt'}
        medium_severity_threats = {'port_scan', 'brute_force', 'ssh_attack'}
        
        if threat_type in high_severity_threats:
            return 'high'
        elif threat_type in medium_severity_threats:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_detection_confidence(self, threat_type: str) -> float:
        """Calculate confidence level in threat detection."""
        # Placeholder - implement actual confidence calculation
        base_confidence = {
            'ddos': 0.9,
            'ransomware': 0.95,
            'port_scan': 0.85,
            'brute_force': 0.8,
            'ssh_attack': 0.85
        }
        return base_confidence.get(threat_type, 0.75)
    
    # Threat detection methods
    def _detect_ddos(self, data: Dict[str, Any]) -> bool:
        """Detect DDoS attacks."""
        return (
            data.get('connections_per_second', 0) > 1000 or
            data.get('bandwidth_usage', 0) > 90
        )
    
    def _detect_port_scan(self, data: Dict[str, Any]) -> bool:
        """Detect port scanning activity."""
        return data.get('unique_ports_accessed', 0) > 20
    
    def _detect_syn_flood(self, data: Dict[str, Any]) -> bool:
        """Detect SYN flood attacks."""
        return data.get('syn_packets_ratio', 0) > 0.8
    
    def _detect_brute_force(self, data: Dict[str, Any]) -> bool:
        """Detect brute force attempts."""
        return data.get('failed_logins', 0) > 5
    
    def _detect_ssh_attack(self, data: Dict[str, Any]) -> bool:
        """Detect SSH-based attacks."""
        return data.get('ssh_failed_attempts', 0) > 3
    
    def _detect_ransomware(self, data: Dict[str, Any]) -> bool:
        """Detect ransomware activity."""
        return (
            data.get('file_entropy', 0) > 0.9 and
            data.get('file_operations_per_second', 0) > 100
        )
    
    def _detect_cryptomining(self, data: Dict[str, Any]) -> bool:
        """Detect cryptomining activity."""
        return data.get('cpu_usage', 0) > 90
    
    def _block_ip(self, ip: str) -> bool:
        """Block an IP address."""
        try:
            if ip not in self.blocked_ips:
                self.blocked_ips.add(ip)
                # Update stats for any active threats from this IP
                for threat in self.active_threats:
                    if threat['source'] == ip:
                        threat_type = threat['type']
                        if threat_type in self.detection_stats:
                            self.detection_stats[threat_type]['blocked'] += 1
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
            
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked."""
        return ip in self.blocked_ips 

    def get_blocked_count(self) -> int:
        """Get the total number of blocked attacks."""
        try:
            return sum(stats['blocked'] for stats in self.detection_stats.values())
        except Exception as e:
            logger.error(f"Error getting blocked count: {str(e)}")
            return 0

    def get_last_attack_time(self) -> float:
        """Get the timestamp of the last detected attack."""
        try:
            if not self.threat_history:
                return None
            
            latest_time = None
            for history in self.threat_history.values():
                if history:
                    last_attack = datetime.fromisoformat(history[-1]['timestamp'])
                    if latest_time is None or last_attack > latest_time:
                        latest_time = last_attack
            
            return latest_time.timestamp() if latest_time else None
        except Exception as e:
            logger.error(f"Error getting last attack time: {str(e)}")
            return None

    def add_threat(self, threat: Dict):
        """Add a threat to the active threats list."""
        if not threat.get('timestamp'):
            threat['timestamp'] = datetime.now().isoformat()
        self._update_active_threats([threat]) 

    def get_threat_distribution(self) -> Dict[str, int]:
        """Get the current distribution of threats."""
        try:
            # Ensure distribution matches active threats
            self.cleanup_old_threats()
            return self.threat_distribution
        except Exception as e:
            logger.error(f"Error getting threat distribution: {e}")
            return {} 