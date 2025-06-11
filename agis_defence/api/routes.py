from flask import Blueprint, jsonify, request
from agis_defence.models.threat_detection import ThreatDetector
from agis_defence.models.system_monitor import SystemMonitor
from agis_defence.agents.ai_agent import AISecurityAgent
from agis_defence.firewall.manager import FirewallManager
from agis_defence.healing.healer import SystemHealer
from agis_defence.models.historical_data import HistoricalData
from datetime import datetime, timedelta
import threading
import queue
import collections
import logging
from ..core import (
    ai_agent,
    system_monitor,
    threat_detector,
    firewall,
    historical_data,
    healer
)
from flask_cors import CORS

# Configure logger
logger = logging.getLogger(__name__)

api = Blueprint('api', __name__)
threat_detector = ThreatDetector()
system_monitor = SystemMonitor()
firewall = FirewallManager()
healer = SystemHealer()
historical_data = HistoricalData()  # Initialize as a class instance

# Import routes after components are initialized
from . import routes

# Enable CORS for all routes
CORS(api)

@api.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Historical data storage
MAX_HISTORY_SIZE = 1000

def store_historical_data(category, data):
    """Store data in the historical record."""
    try:
        if category == 'network_stats':
            historical_data.add_network_stats(data)
        elif category == 'threats':
            historical_data.add_threat(data)
        elif category == 'system_metrics':
            historical_data.add_system_metrics(data)
        elif category == 'ai_analysis':
            historical_data.add_ai_analysis(data)
    except Exception as e:
        logger.error(f"Error storing historical data for {category}: {str(e)}")

def parse_timestamp(timestamp_str):
    """Parse a timestamp string into a datetime object."""
    try:
        if isinstance(timestamp_str, datetime):
            # Convert to timezone naive if it's timezone aware
            if timestamp_str.tzinfo is not None:
                timestamp_str = timestamp_str.replace(tzinfo=None)
            return timestamp_str
            
        if not isinstance(timestamp_str, str):
            return None
            
        # Handle timezone
        timestamp_str = timestamp_str.replace('Z', '+00:00')
        if '+' not in timestamp_str and 'Z' not in timestamp_str:
            timestamp_str += '+00:00'
            
        # Convert to timezone naive
        dt = datetime.fromisoformat(timestamp_str)
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None)
        return dt
    except (ValueError, TypeError) as e:
        logger.warning(f"Error parsing timestamp: {e}")
        return None

@api.route('/system/status')
def get_system_status():
    """Get current system status including metrics, threats, and analysis."""
    try:
        # Get system metrics
        system_metrics = system_monitor.get_stats()
        network_stats = system_monitor.get_network_stats()
        
        # Get active threats and analysis
        active_threats = threat_detector.get_active_threats()
        ai_analysis = ai_agent.analyze_system_state()
        
        # Get firewall status
        firewall_status = firewall.get_status()
        
        # Calculate threat distribution
        threat_types = {}
        if active_threats:
            for threat in active_threats:
                threat_type = threat.get('type', 'unknown')
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        # Generate recent actions
        recent_actions = []
        if active_threats:
            for threat in sorted(active_threats, key=lambda x: x['timestamp'], reverse=True)[:5]:
                action_type = 'block' if threat['severity'] in ['critical', 'high'] else 'monitor'
                recent_actions.append({
                    'action': f"{action_type.title()}: {threat['type']}",
                    'severity': threat['severity'],
                    'details': threat['description'],
                    'timestamp': threat['timestamp'],
                    'threat_type': threat['type']
                })
        
        # Prepare response data
        response_data = {
            'status': 'success',
            'data': {
                'systemMetrics': {
                    'cpu': system_metrics.get('cpu', 0),
                    'memory': system_metrics.get('memory', 0),
                    'disk': system_metrics.get('disk', 0)
                },
                'networkStats': {
                    'bandwidth_usage': network_stats.get('bandwidth_usage', 0),
                    'active_connections': network_stats.get('active_connections', 0),
                    'packet_loss': network_stats.get('packet_loss', 0)
                },
                'firewall': {
                    'active': firewall_status.get('active', False),
                    'mode': firewall_status.get('mode', 'simulation'),
                    'blocked_ips': len(firewall_status.get('blocked_ips', [])),
                    'rules': len(firewall_status.get('rules', []))
                },
                'anomalies': active_threats or [],
                'aiAnalysis': {
                    'threat_level': ai_analysis.get('threat_level', 'low'),
                    'confidence': ai_analysis.get('confidence', 0.0),
                    'healthScore': ai_analysis.get('healthScore', 100),
                    'healthStatus': ai_analysis.get('healthStatus', 'Healthy'),
                    'predictions': ai_analysis.get('predictions', []),
                    'vulnerabilities': ai_analysis.get('vulnerabilities', []),
                    'recommendations': ai_analysis.get('recommendations', []),
                    'recent_actions': recent_actions,
                    'threat_distribution': threat_types,
                    'coverage': ai_analysis.get('coverage', 100)
                },
                'timestamp': datetime.now().isoformat()
            }
        }
        
        return jsonify(response_data)
    except Exception as e:
        logger.error(f"Error getting system status: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to get system status',
            'error': str(e)
        }), 500

@api.route('/history/network', methods=['GET'])
def get_network_history():
    """Get historical network statistics."""
    try:
        hours = request.args.get('hours', 24, type=int)
        cutoff = datetime.now() - timedelta(hours=hours)
        
        history = []
        for item in historical_data.data.get('network_stats', []):
            try:
                timestamp = parse_timestamp(item.get('timestamp'))
                if timestamp and timestamp > cutoff:
                    history.append(item)
            except (ValueError, KeyError, TypeError) as e:
                logger.warning(f"Error parsing network history timestamp: {e}")
                continue
        
        return jsonify({
            'status': 'success',
            'history': history
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/history/threats', methods=['GET'])
def get_threat_history():
    """Get historical threat data."""
    try:
        hours = request.args.get('hours', 24, type=int)
        cutoff = datetime.now() - timedelta(hours=hours)
        
        history = []
        for item in historical_data.data.get('threats', []):
            try:
                timestamp = parse_timestamp(item.get('timestamp'))
                if timestamp and timestamp > cutoff:
                    history.append(item)
            except (ValueError, KeyError, TypeError) as e:
                logger.warning(f"Error parsing threat history timestamp: {e}")
                continue
        
        return jsonify({
            'status': 'success',
            'history': history
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/history/system', methods=['GET'])
def get_system_history():
    """Get historical system metrics."""
    try:
        hours = request.args.get('hours', 24, type=int)
        cutoff = datetime.now() - timedelta(hours=hours)
        
        history = []
        for item in historical_data.data.get('system_metrics', []):
            try:
                timestamp = parse_timestamp(item.get('timestamp'))
                if timestamp and timestamp > cutoff:
                    history.append(item)
            except (ValueError, KeyError, TypeError) as e:
                logger.warning(f"Error parsing system history timestamp: {e}")
                continue
        
        return jsonify({
            'status': 'success',
            'history': history
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/threat/analyze', methods=['POST'])
def analyze_threat():
    """Analyze incoming threat data."""
    try:
        data = request.get_json()
        if not data or 'threats' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Invalid threat data'
            }), 400

        threats = data['threats']
        if not isinstance(threats, list):
            threats = [threats]

        # Process each threat
        for threat in threats:
            # Add to active threats
            threat['detected_at'] = datetime.now()
            threat_detector._add_active_threat(threat)
            
            # Analyze and respond
            ai_agent.analyze_and_respond(threat)

        return jsonify({
            'status': 'success',
            'message': f'Processed {len(threats)} threats'
        })
    except Exception as e:
        logger.error(f"Error analyzing threat: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@api.route('/threat/handle', methods=['POST'])
def handle_threat():
    """Handle detected threats with specified action."""
    try:
        data = request.get_json()
        action = data.get('action', 'analyze')
        
        if action == 'block':
            result = firewall.block_threat(data)
        elif action == 'heal':
            result = healer.heal_threat(data)
        elif action == 'analyze':
            result = ai_agent.analyze_and_respond(data)
        else:
            return jsonify({
                'status': 'error',
                'message': f'Unknown action: {action}'
            }), 400
            
        return jsonify({
            'status': 'success',
            'action': action,
            'result': result
        })
    except Exception as e:
        logger.error(f"Error handling threat: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'error_details': {
                'type': type(e).__name__,
                'data_received': data if 'data' in locals() else None
            }
        }), 500

@api.route('/firewall/block/<ip>', methods=['POST'])
def block_ip(ip):
    """Block specific IP address."""
    try:
        result = firewall.block_ip(ip)
        return jsonify({'status': 'success', 'message': f'IP {ip} blocked', 'result': result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/firewall/unblock/<ip>', methods=['POST'])
def unblock_ip(ip):
    """Unblock specific IP address."""
    try:
        result = firewall.unblock_ip(ip)
        return jsonify({'status': 'success', 'message': f'IP {ip} unblocked', 'result': result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/network/stats', methods=['GET'])
def get_network_stats():
    """Get detailed network statistics."""
    try:
        stats = system_monitor.get_network_stats()
        return jsonify({'status': 'success', 'stats': stats})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/network/anomalies', methods=['GET'])
def get_network_anomalies():
    """Get detected network anomalies."""
    try:
        anomalies = threat_detector.get_network_anomalies()
        return jsonify({'status': 'success', 'anomalies': anomalies})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@api.route('/healing/status', methods=['GET'])
def get_healing_status():
    """Get system healing status."""
    try:
        status = healer.get_status()
        return jsonify({'status': 'success', 'healing_status': status})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500 