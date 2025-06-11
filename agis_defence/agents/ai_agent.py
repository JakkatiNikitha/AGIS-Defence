from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging
import collections
from ..models.threat_detection import ThreatDetector
from ..models.system_monitor import SystemMonitor
from ..firewall.manager import FirewallManager
from ..healing.healer import SystemHealer
from .data_recovery_agent import DataRecoveryAgent
import numpy as np
import random
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

class AISecurityAgent:
    def __init__(self):
        """Initialize the AI Security Agent."""
        self.system_monitor = SystemMonitor()
        self.threat_detector = ThreatDetector()
        self.healer = SystemHealer()
        self.firewall = FirewallManager()
        self.data_recovery = DataRecoveryAgent()
        self.attack_history = {}
        self.last_analysis = {
            'timestamp': datetime.now().isoformat(),
            'threat_level': 'low',
            'confidence': 95.0,
            'predictions': [],
            'vulnerabilities': [],
            'recommendations': [],
            'actions': [],
            'recent_actions': [],
            'healthScore': 100,
            'healthStatus': 'Healthy',
            'threat_distribution': {},
            'coverage': 100.0,
            'active_threats': 0,
            'blocked_attacks': 0,
            'recovered_data_count': 0
        }
        self.historical_actions = collections.deque(maxlen=100)
        self.monitoring = False
        self.monitoring_thread = None
        
        # Start data recovery agent
        self.data_recovery.start()
        
    def start_monitoring(self):
        """Start continuous system monitoring."""
        if self.monitoring:
            return
            
        self.monitoring = True
        
        while self.monitoring:
            try:
                # Analyze current threats
                active_threats = self.threat_detector.get_active_threats()
                for threat in active_threats:
                    self.analyze_and_respond(threat)
                
                # Update system state
                self.analyze_system_state()
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(1)

    def stop_monitoring(self):
        """Stop system monitoring."""
        self.monitoring = False
        
    def analyze_system_state(self):
        """Analyze current system state and update analysis."""
        try:
            # Get system metrics
            metrics = self.system_monitor.get_stats()
            
            # Update health score based on metrics
            cpu_score = 100 - metrics.get('cpu', 0)
            memory_score = 100 - metrics.get('memory', 0)
            disk_score = 100 - metrics.get('disk', 0)
            health_score = min(100, (cpu_score + memory_score + disk_score) / 3)
            
            # Get active threats
            active_threats = self.threat_detector.get_active_threats()
            
            # Calculate threat distribution
            threat_distribution = {}
            for threat in active_threats:
                threat_type = threat.get('type', 'unknown')
                threat_distribution[threat_type] = threat_distribution.get(threat_type, 0) + 1
            
            # Get recovery stats
            recovery_stats = self.data_recovery.get_recovery_stats()
            
            # Update analysis
            self.last_analysis.update({
                'timestamp': datetime.now().isoformat(),
                'threat_level': self._calculate_threat_level(metrics, {}, active_threats),
                'healthScore': health_score,
                'healthStatus': 'Critical' if health_score < 50 else 'Warning' if health_score < 70 else 'Healthy',
                'threat_distribution': threat_distribution,
                'active_threats': len(active_threats),
                'blocked_attacks': len([a for a in self.last_analysis['recent_actions'] if a.get('action') == 'block']),
                'recovered_data_count': recovery_stats['successful_recoveries']
            })
            
            return self.last_analysis
            
        except Exception as e:
            logger.error(f"Error in analyze_system_state: {str(e)}")
            return self.last_analysis
    
    def analyze_and_respond(self, threat):
        """Analyze a threat and determine appropriate response."""
        try:
            source = threat.get('source', 'unknown')
            threat_type = threat.get('type', 'unknown')
            attack_key = f"{threat_type}:{source}"
            
            # Record the attack
            if attack_key not in self.attack_history:
                self.attack_history[attack_key] = {
                    'count': 0,
                    'first_seen': datetime.now(),
                    'actions_taken': []
                }
            self.attack_history[attack_key]['count'] += 1
            count = self.attack_history[attack_key]['count']
            
            # Take data snapshot before response
            self._protect_system_data()
            
            action_taken = None
            if count == 1:
                # First attack - Try to heal
                logger.info(f"First attack from {source} - Attempting to heal")
                self.healer.heal_system(threat)
                action_taken = 'heal'
            else:
                # Repeated attack - Block immediately
                logger.info(f"Repeated attack from {source} - Blocking")
                self.firewall.block_ip(source)
                action_taken = 'block'
            
            # Check for data loss and recover if needed
            self._check_and_recover_data(threat)
            
            # Record action
            action = {
                'action': action_taken,
                'timestamp': datetime.now().isoformat(),
                'threat_type': threat_type,
                'source': source,
                'severity': threat.get('severity', 'low'),
                'details': f"{'Healing' if action_taken == 'heal' else 'Blocking'} system from {threat_type} attack"
            }
            
            self.attack_history[attack_key]['actions_taken'].append(action)
            self.historical_actions.appendleft(action)
            self.last_analysis['recent_actions'] = list(self.historical_actions)
            self.last_analysis['recent_actions'] = self.last_analysis['recent_actions'][:10]
            
            return {
                'success': True,
                'action': action_taken,
                'message': f"Threat handled with action: {action_taken}"
            }
            
        except Exception as e:
            logger.error(f"Error in analyze_and_respond: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
            
    def _protect_system_data(self):
        """Protect critical system data before responding to threat."""
        try:
            # Get current system state
            system_state = self.system_monitor.get_stats()
            
            # Protect critical data
            self.data_recovery.protect_data('system_state', system_state)
            self.data_recovery.protect_data('network_config', self.firewall.get_config())
            self.data_recovery.protect_data('security_rules', self.firewall.get_rules())
            
        except Exception as e:
            logger.error(f"Error protecting system data: {str(e)}")
            
    def _check_and_recover_data(self, threat):
        """Check for data loss and recover if needed."""
        try:
            # Check if threat type indicates potential data loss
            if threat.get('type') in ['data_exfil', 'ransomware', 'malware']:
                # Attempt to recover system state
                system_state = self.data_recovery.recover_data('system_state')
                if system_state:
                    self.system_monitor.restore_state(system_state)
                    
                # Recover network configuration
                network_config = self.data_recovery.recover_data('network_config')
                if network_config:
                    self.firewall.restore_config(network_config)
                    
                # Recover security rules
                security_rules = self.data_recovery.recover_data('security_rules')
                if security_rules:
                    self.firewall.restore_rules(security_rules)
                    
                # Update recovery stats
                stats = self.data_recovery.get_recovery_stats()
                self.last_analysis['recovered_data_count'] = stats['successful_recoveries']
                
        except Exception as e:
            logger.error(f"Error checking and recovering data: {str(e)}")
    
    def _store_recommendation(self, recommendation):
        """Store a recommendation."""
        try:
            if recommendation:
                if 'recommendations' not in self.last_analysis:
                    self.last_analysis['recommendations'] = []
                if recommendation not in self.last_analysis['recommendations']:
                    self.last_analysis['recommendations'].append(recommendation)
        except Exception as e:
            logger.error(f"Error storing recommendation: {str(e)}")
                
    def _store_vulnerability(self, vulnerability):
        """Store a vulnerability."""
        try:
            if vulnerability:
                if 'vulnerabilities' not in self.last_analysis:
                    self.last_analysis['vulnerabilities'] = []
                if vulnerability not in self.last_analysis['vulnerabilities']:
                    self.last_analysis['vulnerabilities'].append(vulnerability)
        except Exception as e:
            logger.error(f"Error storing vulnerability: {str(e)}")
        
    def analyze_threats(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze specific threats and provide detailed analysis."""
        try:
            if not isinstance(data, dict):
                data = {}
                
            threats = data.get('threats', [])
            current_time = datetime.now()
            
            if not threats:
                return {
                    'timestamp': current_time.isoformat(),
                    'threats': [],
                    'system_impact': 'none',
                    'actions': [],
                    'status': 'success'
                }
                
            # Analyze each threat
            analyzed_threats = []
            actions_taken = []
            system_impact = 'low'
            
            for threat in threats:
                # Get threat history
                threat_type = threat.get('type', 'unknown')
                threat_source = threat.get('source', 'unknown')
                threat_key = f"{threat_type}:{threat_source}"
                history = self.attack_history.get(threat_key, {})
                
                # Determine severity and impact
                severity = threat.get('severity', 'low')
                if severity == 'critical':
                    system_impact = 'critical'
                elif severity == 'high' and system_impact != 'critical':
                    system_impact = 'high'
                elif severity == 'medium' and system_impact not in ['critical', 'high']:
                    system_impact = 'medium'
                
                # Determine action based on history
                action = None
                if not history:
                    # First time seeing this attack - heal
                    action = {
                        'action': 'heal',
                        'details': f'Healing system from {threat_type} attack',
                        'severity': severity,
                        'threat_type': threat_type,
                        'source': threat_source,
                        'timestamp': current_time.isoformat()
                    }
                else:
                    # Seen this attack before - block
                    action = {
                        'action': 'block',
                        'details': f'Blocking {threat_source} due to repeated {threat_type} attack',
                        'severity': severity,
                        'threat_type': threat_type,
                        'source': threat_source,
                        'timestamp': current_time.isoformat()
                    }
                    # Block the source
                    if threat_source != 'unknown':
                        self.firewall.block_ip(threat_source)
                
                if action:
                    actions_taken.append(action)
                    self.historical_actions.appendleft(action)
                    self.last_analysis['recent_actions'] = list(self.historical_actions)
                    self.last_analysis['recent_actions'] = self.last_analysis['recent_actions'][:10]  # Keep last 10 actions
                
                # Store analysis
                analyzed_threat = {
                    'id': threat.get('id', str(np.random.randint(1000, 9999))),
                    'type': threat_type,
                    'severity': severity,
                    'source': threat_source,
                    'action_taken': action['action'] if action else 'No action required',
                    'timestamp': current_time.isoformat()
                }
                analyzed_threats.append(analyzed_threat)
                
                # Update history
                history['actions_taken'].append({
                    'timestamp': current_time.isoformat(),
                    'severity': severity,
                    'action': action['action'] if action else None
                })
                self.attack_history[threat_key] = history
            
            return {
                'timestamp': current_time.isoformat(),
                'threats': analyzed_threats,
                'system_impact': system_impact,
                'actions': actions_taken,
                'status': 'success'
            }
        except Exception as e:
            logger.error(f"Error analyzing threats: {str(e)}")
            return {
                'timestamp': datetime.now().isoformat(),
                'threats': [],
                'system_impact': 'unknown',
                'actions': [],
                'status': 'error',
                'error': str(e)
            }
    
    def _calculate_threat_level(self, system_stats: Dict[str, Any], network_stats: Dict[str, Any], active_threats: List[Dict[str, Any]]) -> str:
        """Calculate overall threat level."""
        try:
            if len(active_threats) > 5:
                return 'critical'
            elif len(active_threats) > 2:
                return 'high'
            elif len(active_threats) > 0:
                return 'medium'
            return 'low'
        except Exception as e:
            logger.error(f"Error calculating threat level: {str(e)}")
            return 'unknown'
    
    def _generate_threat_predictions(self) -> List[Dict[str, Any]]:
        """Generate predictions about potential future threats."""
        predictions = []
        
        # Analyze historical patterns
        for threat_key, history in self.attack_history.items():
            if history['last_seen']:
                time_since_last = datetime.now() - history['first_seen']
                attack_frequency = history['count'] / max(1, (datetime.now() - history['first_seen']).days)
                
                if attack_frequency > 0.5 and time_since_last.days < 7:
                    predictions.append({
                        'type': threat_key.split('-')[0],
                        'probability': min(0.9, attack_frequency / 10 + 0.3),
                        'timeframe': '24 hours',
                        'basis': 'Historical pattern'
                    })
        
        return predictions
    
    def _identify_vulnerabilities(self, system_stats: Dict) -> List[Dict[str, Any]]:
        """Identify system vulnerabilities."""
        vulnerabilities = []
        
        if system_stats['cpu'] > 80:
            vulnerabilities.append({
                'type': 'Resource Exhaustion',
                'description': 'High CPU usage may indicate resource exhaustion attack',
                'severity': 'high'
            })
        
        if system_stats['memory'] > 80:
            vulnerabilities.append({
                'type': 'Memory Usage',
                'description': 'High memory usage increases vulnerability to DoS',
                'severity': 'medium'
            })
        
        return vulnerabilities
    
    def _generate_recommendations(self, threats, system_status):
        """Generate recommendations based on current threats and system status."""
        recommendations = []
        
        # Threat-specific recommendations
        for threat in threats:
            threat_type = threat.get('type', 'unknown')
            severity = threat.get('severity', 'low')
            source = threat.get('source', 'unknown')
            
            if threat_type == 'brute_force':
                recommendations.append({
                    'title': 'Strengthen Password Policy',
                    'description': f'Multiple failed login attempts detected from {source}. Consider implementing rate limiting and account lockout policies.',
                    'priority': severity,
                    'category': 'security'
                })
                recommendations.append({
                    'title': 'Enable Two-Factor Authentication',
                    'description': 'Implement 2FA to add an additional layer of security against brute force attacks.',
                    'priority': severity,
                    'category': 'security'
                })
                
            elif threat_type == 'port_scan':
                recommendations.append({
                    'title': 'Review Firewall Rules',
                    'description': f'Port scanning detected from {source}. Consider blocking this IP and reviewing exposed ports.',
                    'priority': severity,
                    'category': 'network'
                })
                recommendations.append({
                    'title': 'Enable Port Scan Detection',
                    'description': 'Configure IDS/IPS to actively monitor and block port scanning attempts.',
                    'priority': severity,
                    'category': 'network'
                })
                
            elif threat_type == 'ddos':
                recommendations.append({
                    'title': 'Implement DDoS Protection',
                    'description': 'High traffic volume detected. Consider implementing rate limiting and DDoS mitigation services.',
                    'priority': severity,
                    'category': 'network'
                })
                recommendations.append({
                    'title': 'Scale Resources',
                    'description': 'Consider scaling system resources or implementing load balancing to handle increased traffic.',
                    'priority': severity,
                    'category': 'system'
                })
                
            elif threat_type == 'sql_injection':
                recommendations.append({
                    'title': 'Update SQL Query Sanitization',
                    'description': f'SQL injection attempt detected from {source}. Review and update input validation.',
                    'priority': severity,
                    'category': 'application'
                })
                recommendations.append({
                    'title': 'Implement Prepared Statements',
                    'description': 'Use prepared statements or stored procedures to prevent SQL injection attacks.',
                    'priority': severity,
                    'category': 'application'
                })
                
            elif threat_type == 'xss':
                recommendations.append({
                    'title': 'Enhance XSS Protection',
                    'description': f'Cross-site scripting attempt detected from {source}. Review input/output encoding.',
                    'priority': severity,
                    'category': 'application'
                })
                recommendations.append({
                    'title': 'Enable Content Security Policy',
                    'description': 'Implement CSP headers to prevent XSS attacks.',
                    'priority': severity,
                    'category': 'application'
                })
                
            elif threat_type == 'ransomware':
                recommendations.append({
                    'title': 'URGENT: Isolate Affected Systems',
                    'description': f'Potential ransomware activity detected from {source}. Isolate affected systems immediately.',
                    'priority': 'critical',
                    'category': 'security'
                })
                recommendations.append({
                    'title': 'Verify Backup Systems',
                    'description': 'Ensure all critical data is backed up and backups are isolated from the network.',
                    'priority': 'critical',
                    'category': 'backup'
                })
                
            elif threat_type == 'data_exfil':
                recommendations.append({
                    'title': 'Review Data Access Patterns',
                    'description': f'Unusual data transfer patterns detected from {source}. Review and restrict data access.',
                    'priority': severity,
                    'category': 'data'
                })
                recommendations.append({
                    'title': 'Enable Data Loss Prevention',
                    'description': 'Implement DLP solutions to monitor and prevent unauthorized data transfers.',
                    'priority': severity,
                    'category': 'data'
                })
        
        # System status recommendations
        if system_status:
            if isinstance(system_status, dict):
                cpu = system_status.get('cpu', 0)
                memory = system_status.get('memory', 0)
                disk = system_status.get('disk', 0)
                
                if cpu > 80:
                    recommendations.append({
                        'title': 'High CPU Usage',
                        'description': f'CPU usage at {cpu}%. Consider investigating high CPU processes.',
                        'priority': 'high',
                        'category': 'system'
                    })
                
                if memory > 80:
                    recommendations.append({
                        'title': 'High Memory Usage',
                        'description': f'Memory usage at {memory}%. Review memory-intensive applications.',
                        'priority': 'high',
                        'category': 'system'
                    })
                
                if disk > 80:
                    recommendations.append({
                        'title': 'High Disk Usage',
                        'description': f'Disk usage at {disk}%. Clean up unnecessary files or add storage.',
                        'priority': 'high',
                        'category': 'system'
                    })
        
        return recommendations

    def _assess_vulnerabilities(self, threats, system_status):
        """Assess system vulnerabilities based on threats and system status."""
        vulnerabilities = []
        
        # Track recurring threats to identify vulnerabilities
        for threat_key, history in self.attack_history.items():
            if history['count'] > 2:  # If threat occurred multiple times
                threat_type = threat_key.split('-')[0]
                
                if threat_type == 'sql_injection':
                    vulnerabilities.append({
                        'type': 'SQL Injection Vulnerability',
                        'description': 'Multiple SQL injection attempts detected. Database access points may be vulnerable.',
                        'risk_level': 'high',
                        'affected_component': 'database'
                    })
                    
                elif threat_type == 'xss':
                    vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'description': 'Recurring XSS attempts indicate vulnerable input handling in web forms.',
                        'risk_level': 'high',
                        'affected_component': 'web_application'
                    })
                    
                elif threat_type == 'brute_force':
                    vulnerabilities.append({
                        'type': 'Weak Authentication',
                        'description': 'Multiple brute force attempts suggest insufficient login security measures.',
                        'risk_level': 'critical',
                        'affected_component': 'authentication'
                    })
                    
                elif threat_type == 'port_scan':
                    vulnerabilities.append({
                        'type': 'Open Port Exposure',
                        'description': 'Frequent port scans detected. Review network exposure and firewall rules.',
                        'risk_level': 'medium',
                        'affected_component': 'network'
                    })
                    
                elif threat_type == 'data_exfil':
                    vulnerabilities.append({
                        'type': 'Data Exfiltration Risk',
                        'description': 'Repeated data exfiltration attempts indicate potential data security gaps.',
                        'risk_level': 'critical',
                        'affected_component': 'data_storage'
                    })
        
        # Check system status for vulnerabilities
        if system_status.get('firewall', {}).get('mode') == 'simulation':
            vulnerabilities.append({
                'type': 'Limited Firewall Protection',
                'description': 'Firewall running in simulation mode. Full protection not active.',
                'risk_level': 'high',
                'affected_component': 'firewall'
            })
        
        if system_status.get('updates_pending', False):
            vulnerabilities.append({
                'type': 'System Updates Required',
                'description': 'Pending security updates may leave system vulnerable.',
                'risk_level': 'medium',
                'affected_component': 'system'
            })
        
        return vulnerabilities
    
    def _calculate_health_score(self, system_stats: Dict[str, Any], network_stats: Dict[str, Any], threat_count: int) -> int:
        """Calculate system health score."""
        try:
            base_score = 100
            
            # Deduct for high resource usage
            if system_stats.get('cpu', 0) > 90: base_score -= 20
            elif system_stats.get('cpu', 0) > 70: base_score -= 10
            
            if system_stats.get('memory', 0) > 90: base_score -= 20
            elif system_stats.get('memory', 0) > 70: base_score -= 10
            
            if system_stats.get('disk', 0) > 90: base_score -= 20
            elif system_stats.get('disk', 0) > 70: base_score -= 10
            
            # Deduct for network issues
            if network_stats.get('packet_loss', 0) > 10: base_score -= 20
            elif network_stats.get('packet_loss', 0) > 5: base_score -= 10
            
            # Deduct for active threats
            base_score -= min(50, threat_count * 10)
            
            return max(0, base_score)
        except Exception as e:
            logger.error(f"Error calculating health score: {str(e)}")
            return 0
    
    def _get_health_status(self, health_score: int) -> str:
        """Get health status based on score."""
        try:
            if health_score > 80:
                return 'Healthy'
            elif health_score > 60:
                return 'Warning'
            elif health_score > 40:
                return 'Critical'
            else:
                return 'Emergency'
        except Exception as e:
            logger.error(f"Error getting health status: {str(e)}")
            return 'Error'
    
    def _calculate_confidence(self) -> float:
        """Calculate confidence in current analysis."""
        try:
            # Simple confidence calculation
            return 0.85
        except Exception as e:
            logger.error(f"Error calculating confidence: {str(e)}")
            return 0.0
    
    def _calculate_threat_confidence(self, threat: Dict[str, Any], history: List[Dict[str, Any]]) -> float:
        """Calculate confidence score for a threat based on its characteristics and history."""
        try:
            # Base confidence from threat data
            base_confidence = threat.get('confidence', 0.5)
            
            # Adjust based on history
            if history:
                # Calculate historical severity distribution
                severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
                for entry in history[-10:]:  # Look at last 10 entries
                    severity = entry.get('severity', 'low')
                    severity_counts[severity] += 1
                
                # Calculate historical confidence boost
                history_factor = min(len(history) / 10, 1.0)  # Max boost from history
                severity_weight = (
                    severity_counts['critical'] * 0.4 +
                    severity_counts['high'] * 0.3 +
                    severity_counts['medium'] * 0.2 +
                    severity_counts['low'] * 0.1
                ) / max(sum(severity_counts.values()), 1)
                
                # Adjust confidence based on history
                confidence = base_confidence * (1 + history_factor * severity_weight)
            else:
                confidence = base_confidence
            
            # Additional factors
            if threat.get('details'):
                detail_factor = 0.1  # Boost for having detailed information
                confidence += detail_factor
            
            if threat.get('source') and threat['source'] != 'unknown':
                source_factor = 0.1  # Boost for having source information
                confidence += source_factor
            
            # Ensure confidence is between 0 and 1
            confidence = max(0.0, min(1.0, confidence))
            
            return confidence
            
        except Exception as e:
            logger.error(f"Error calculating threat confidence: {str(e)}")
            return 0.5  # Return moderate confidence as fallback

    def _determine_action(self, threat: Dict[str, Any], history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Determine appropriate action for a threat."""
        threat_type = threat.get('type', 'unknown')
        severity = threat.get('severity', 'low')
        source = threat.get('source', 'unknown')
        
        if threat_type == 'ddos':
            return {
                'action': 'Block DDoS Attack',
                'details': 'Implementing rate limiting for multiple IPs',
                'severity': severity
            }
        elif threat_type == 'ransomware':
            return {
                'action': 'Isolate Affected System',
                'details': f'Isolating system at {source} to prevent encryption spread',
                'severity': severity
            }
        elif threat_type == 'brute_force':
            return {
                'action': 'Block IP',
                'details': f'Blocking malicious IP {source}',
                'severity': severity
            }
        elif threat_type == 'port_scan':
            return {
                'action': 'Enhanced Monitoring',
                'details': f'Monitoring {source} for suspicious activity',
                'severity': severity
            }
        elif threat_type == 'data_exfil':
            return {
                'action': 'Traffic Analysis',
                'details': f'Analyzing outbound traffic from {source}',
                'severity': severity
            }
        elif threat_type in ['sql_injection', 'xss']:
            return {
                'action': 'Update WAF Rules',
                'details': f'Updating Web Application Firewall rules for {threat_type}',
                'severity': severity
            }
        else:
            return {
                'action': 'Monitor',
                'details': f'Monitoring {threat_type} threat from {source}',
                'severity': severity
            }

    def handle_threat(self, threat_data: Dict) -> Dict:
        """Handle detected threat based on history."""
        try:
            threat_key = f"{threat_data['type']}:{threat_data['source']}"
            
            # Initialize attack count if not exists
            if threat_key not in self.attack_history:
                self.attack_history[threat_key] = {
                    'count': 0,
                    'first_seen': datetime.now(),
                    'actions_taken': []
                }
            
            # Increment attack count
            self.attack_history[threat_key]['count'] += 1
            count = self.attack_history[threat_key]['count']
            
            action_taken = None
            if count == 1:
                # First attack - Try to heal
                logger.info(f"First attack from {threat_data['source']} - Attempting to heal")
                heal_result = self.healer.heal_system(threat_data)
                action_taken = 'heal'
            else:
                # Subsequent attacks - Block
                logger.info(f"Repeated attack from {threat_data['source']} - Blocking")
                self.firewall.block_ip(threat_data['source'])
                action_taken = 'block'
            
            # Record action
            action = {
                'action': action_taken,
                'timestamp': datetime.now().isoformat(),
                'threat_type': threat_data['type'],
                'source': threat_data['source'],
                'severity': threat_data['severity'],
                'details': f"{'Healing' if action_taken == 'heal' else 'Blocking'} system from {threat_data['type']} attack"
            }
            
            # Update history and analysis
            self.attack_history[threat_key]['actions_taken'].append(action)
            if 'recent_actions' not in self.last_analysis:
                self.last_analysis['recent_actions'] = []
            self.last_analysis['recent_actions'].insert(0, action)
            self.last_analysis['recent_actions'] = self.last_analysis['recent_actions'][:10]  # Keep last 10 actions
            
            # Update threat distribution
            if 'threat_distribution' not in self.last_analysis:
                self.last_analysis['threat_distribution'] = {}
            if threat_data['type'] not in self.last_analysis['threat_distribution']:
                self.last_analysis['threat_distribution'][threat_data['type']] = 0
            self.last_analysis['threat_distribution'][threat_data['type']] += 1
            
            # Update blocked attacks count
            if action_taken == 'block':
                self.last_analysis['blocked_attacks'] = self.last_analysis.get('blocked_attacks', 0) + 1
            
            # Update active threats
            self.last_analysis['active_threats'] = len(self.threat_detector.get_active_threats())
            
            return {
                'success': True,
                'action': action_taken,
                'message': f"Threat handled with action: {action_taken}"
            }
            
        except Exception as e:
            logger.error(f"Error handling threat: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

# Initialize the AI agent
ai_agent = AISecurityAgent()
             