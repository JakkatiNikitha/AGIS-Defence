from flask import Blueprint, jsonify, request
from .alerts import alert_manager
from .config import ALERT_CONFIG

app = Blueprint('api', __name__)

@app.route('/settings', methods=['GET'])
def get_settings():
    """Get current alert settings"""
    return jsonify({
        'whatsapp': {
            'enabled': ALERT_CONFIG['whatsapp']['enabled'],
            'recipient_numbers': ALERT_CONFIG['whatsapp']['recipient_numbers']
        }
    })

@app.route('/settings', methods=['POST'])
def update_settings():
    """Update alert settings"""
    settings = request.json
    alert_manager.update_settings(settings)
    return jsonify({'status': 'success'})

# ... existing routes ... 