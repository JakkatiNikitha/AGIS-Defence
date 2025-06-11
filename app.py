from flask import Flask, send_from_directory, jsonify, request
from flask_cors import CORS
import os
import logging
import time
from datetime import datetime
from agis_defence.core.system_monitor import get_stats, get_network_stats
from agis_defence.core.threat_detector import threat_detector
from agis_defence.core.ai_agent import ai_agent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='agis.log'
)
logger = logging.getLogger(__name__)

# Check for admin privileges
if os.name == 'nt':  # Windows
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False
else:  # Unix/Linux
    is_admin = os.geteuid() == 0

if not is_admin:
    logger.warning("Running without administrator privileges. Firewall management will be simulated.")
    print("Running without administrator privileges. Firewall management will be simulated.")

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Get the absolute path to the dashboard directory
dashboard_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'agis_defence', 'dashboard')
logger.info(f"Dashboard directory: {dashboard_dir}")

@app.route('/')
def serve_dashboard():
    """Serve the main dashboard page."""
    return send_from_directory(dashboard_dir, 'index.html')

@app.route('/js/<path:filename>')
def serve_js(filename):
    """Serve JavaScript files."""
    return send_from_directory(os.path.join(dashboard_dir, 'js'), filename)

@app.route('/assets/<path:filename>')
def serve_assets(filename):
    """Serve static assets."""
    return send_from_directory(os.path.join(dashboard_dir, 'assets'), filename)

@app.route('/favicon.ico')
def favicon():
    """Serve favicon."""
    return send_from_directory(os.path.join(dashboard_dir, 'assets'), 'favicon.ico')

@app.route('/api/system/status', methods=['GET'])
def get_system_status():
    """Get the current system status including threats and AI analysis."""
    try:
        # Get system stats
        system_stats = get_stats()
        
        # Get network stats
        network_stats = get_network_stats()
        
        # Get active threats and threat distribution
        active_threats = threat_detector.get_active_threats()
        threat_distribution = threat_detector.get_threat_distribution()
        
        # Get AI analysis
        ai_state = ai_agent.analyze_system_state()
        
        # Format the response
        response = {
            'system': system_stats,
            'network': network_stats,
            'threats': {
                'active_threats': len(active_threats),
                'threat_level': ai_state['threat_level'],
                'blocked_attacks': threat_detector.get_blocked_count(),
                'last_attack': threat_detector.get_last_attack_time(),
                'recent_actions': ai_state['recent_actions']
            },
            'aiAnalysis': {
                'confidence': ai_state['confidence'],
                'coverage': ai_state['coverage'],
                'threat_level': ai_state['threat_level'],
                'threat_distribution': threat_distribution
            }
        }
        
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 