from flask import Blueprint, jsonify
from ..services.realtime_monitor import RealtimeMonitor
import psutil
import time

bp = Blueprint('system_status', __name__)
monitor = RealtimeMonitor()

@bp.route('/api/system/status')
def get_system_status():
    """Get real-time system status including threats"""
    # Get system metrics
    cpu_percent = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # Get network stats
    net_io = psutil.net_io_counters()
    
    # Get threat data from monitor
    active_threats = monitor.threat_detector.get_active_threats()
    threat_distribution = monitor.threat_detector.get_threat_distribution()
    
    # Get recent AI actions
    recent_actions = monitor.threat_detector.get_recent_ai_actions(5)
    
    # Calculate threat level based on active threats and their severity
    threat_level = "low"
    critical_threats = sum(1 for t in active_threats if t['severity'] == 'critical')
    high_threats = sum(1 for t in active_threats if t['severity'] == 'high')
    
    if critical_threats > 0 or high_threats > 2:
        threat_level = "high"
    elif high_threats > 0 or len(active_threats) > 2:
        threat_level = "medium"
    
    # Calculate AI confidence based on recent actions
    if recent_actions:
        avg_confidence = sum(action['ai_confidence'] for action in recent_actions) / len(recent_actions)
    else:
        avg_confidence = 0.85  # Default confidence
    
    return jsonify({
        "system": {
            "cpu_usage": cpu_percent,
            "memory_usage": memory.percent,
            "disk_usage": disk.percent,
            "health_score": 100 - (cpu_percent + memory.percent) / 2
        },
        "network": {
            "active_connections": len(psutil.net_connections()),
            "incoming_traffic": net_io.bytes_recv / 1024 / 1024,  # Convert to MB
            "packet_loss": 0  # Placeholder, implement actual packet loss calculation if needed
        },
        "threats": {
            "active_threats": len(active_threats),
            "recent_actions": recent_actions
        },
        "aiAnalysis": {
            "threat_level": threat_level,
            "confidence": round(avg_confidence * 100, 1),  # Convert to percentage
            "coverage": 85,  # Placeholder, implement actual coverage calculation if needed
            "threat_distribution": threat_distribution
        }
    }) 