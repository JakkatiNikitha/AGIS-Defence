# This file makes the api directory a Python package 

from flask import Blueprint, jsonify, request
from agis_defence.models.threat_detection import ThreatDetector
from agis_defence.models.system_monitor import SystemMonitor
from agis_defence.agents.ai_agent import AISecurityAgent
from agis_defence.firewall.manager import FirewallManager
from agis_defence.models.historical_data import HistoricalData
from ..alerts import alert_manager
from ..config import ALERT_CONFIG
import psutil
import time
from datetime import datetime
import random

# Create blueprint
api = Blueprint('api', __name__)

# Initialize components
system_monitor = SystemMonitor()
threat_detector = ThreatDetector()
ai_agent = AISecurityAgent()
firewall = FirewallManager()
historical_data = HistoricalData()

# Import routes after components are initialized
from . import routes 

# Keep track of detected threats
active_threats = []
threat_types = {
    'Network Attacks': ['Port Scan', 'DDoS Attack', 'Brute Force Attempt', 'SQL Injection'],
    'Malware': ['Ransomware', 'Trojan', 'Spyware', 'Cryptominer'],
    'Intrusion Attempts': ['Unauthorized Access', 'Privilege Escalation', 'SSH Attack', 'RDP Attack'],
    'Data Breaches': ['Data Exfiltration', 'Credential Theft', 'File Access Violation', 'Database Breach']
}

@api.route('/threat/analyze', methods=['POST', 'OPTIONS'])
def analyze_threat():
    """Analyze incoming threat data"""
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', '*')
        response.headers.add('Access-Control-Allow-Methods', '*')
        return response

    try:
        global active_threats
        # Clean up old threats (older than 5 minutes)
        current_time = datetime.now()
        active_threats = [
            threat for threat in active_threats 
            if (current_time - datetime.fromisoformat(threat['timestamp'])).total_seconds() < 300
        ]

        # Simulate threat analysis
        threat_data = request.json
        
        # Random chance of detecting a threat
        if random.random() < 0.3:  # 30% chance of threat detection
            threat_category = random.choice(list(threat_types.keys()))
            threat_subtype = random.choice(threat_types[threat_category])
            severity = random.choice(['low', 'medium', 'high'])
            
            threat = {
                'id': len(active_threats) + 1,
                'type': threat_category,
                'subtype': threat_subtype,
                'severity': severity,
                'description': f'Potential {threat_subtype} detected in {threat_category.lower()}',
                'timestamp': datetime.now().isoformat(),
                'details': {
                    'source_ip': f'192.168.{random.randint(1, 255)}.{random.randint(1, 255)}',
                    'target_port': random.randint(1, 65535),
                    'protocol': random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS']),
                    'attempts': random.randint(1, 100)
                }
            }
            
            # Add to active threats if not already present
            if not any(t['subtype'] == threat['subtype'] for t in active_threats):
                active_threats.append(threat)
            
            # If it's a high severity threat, send WhatsApp alert
            if severity == 'high':
                alert_manager.send_alert(
                    subject=f"High Severity Threat: {threat_subtype}",
                    message=f"ALERT: {threat_subtype} ({threat_category}) detected with {severity} severity.\n" +
                           f"Source IP: {threat['details']['source_ip']}\n" +
                           f"Protocol: {threat['details']['protocol']}\n" +
                           f"Attempts: {threat['details']['attempts']}",
                    threat_level='high'
                )
            
            return jsonify({
                'status': 'threat_detected',
                'threat': threat
            })
        
        return jsonify({
            'status': 'no_threat',
            'message': 'No immediate threats detected'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/system/status', methods=['GET', 'OPTIONS'])
def get_system_status():
    """Get current system status and metrics"""
    if request.method == 'OPTIONS':
        # Handle CORS preflight request
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', '*')
        response.headers.add('Access-Control-Allow-Methods', '*')
        return response

    try:
        # Get system metrics
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Network stats (simulated for now)
        network_stats = {
            'active_connections': len(psutil.net_connections()),
            'bandwidth_usage': round(random.uniform(1.5, 5.0), 2),  # Simulated MB/s
            'packet_loss': round(random.uniform(0.1, 2.0), 2)  # Simulated percentage
        }

        # Calculate threat level based on active threats
        threat_level = 'low'
        if any(threat['severity'] == 'high' for threat in active_threats):
            threat_level = 'high'
        elif any(threat['severity'] == 'medium' for threat in active_threats):
            threat_level = 'medium'

        # Calculate health score based on various factors
        health_factors = {
            'cpu': max(0, 100 - cpu_usage),
            'memory': max(0, 100 - memory.percent),
            'disk': max(0, 100 - disk.percent),
            'threats': max(0, 100 - (len(active_threats) * 10)),
            'network': max(0, 100 - (network_stats['packet_loss'] * 5))
        }
        health_score = int(sum(health_factors.values()) / len(health_factors))

        # Count threats by type
        threat_distribution = {threat_type: 0 for threat_type in threat_types.keys()}
        for threat in active_threats:
            threat_distribution[threat['type']] += 1

        # Generate recent actions
        recent_actions = []
        if active_threats:
            for threat in sorted(active_threats, key=lambda x: x['timestamp'], reverse=True)[:5]:
                recent_actions.append({
                    'action': f'Threat Detection: {threat["subtype"]}',
                    'severity': threat['severity'],
                    'details': threat['description'],
                    'timestamp': threat['timestamp'],
                    'threat_type': threat['type']
                })
        else:
            recent_actions.append({
                'action': 'System scan completed',
                'severity': 'info',
                'details': 'No threats detected',
                'timestamp': datetime.now().isoformat(),
                'threat_type': None
            })

        status_data = {
            'data': {
                'systemMetrics': {
                    'cpu': cpu_usage,
                    'memory': memory.percent,
                    'disk': disk.percent
                },
                'networkStats': network_stats,
                'firewall': {
                    'active': True,
                    'mode': 'simulation'
                },
                'aiAnalysis': {
                    'threat_level': threat_level,
                    'confidence': 95,
                    'coverage': 98,
                    'healthScore': health_score,
                    'recent_actions': recent_actions,
                    'threat_distribution': threat_distribution
                },
                'anomalies': active_threats
            }
        }

        response = jsonify(status_data)
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/settings', methods=['GET'])
def get_settings():
    """Get current alert settings"""
    return jsonify({
        'whatsapp': {
            'enabled': ALERT_CONFIG['whatsapp']['enabled'],
            'recipient_numbers': ALERT_CONFIG['whatsapp']['recipient_numbers']
        }
    })

@api.route('/settings', methods=['POST'])
def update_settings():
    """Update alert settings"""
    settings = request.json
    alert_manager.update_settings(settings)
    return jsonify({'status': 'success'})

# Export the Blueprint
app = api 