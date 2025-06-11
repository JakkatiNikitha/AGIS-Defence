from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from typing import Dict, List, Optional
import logging
from datetime import datetime
from pathlib import Path
import os

from ..collectors.network_monitor import NetworkMonitor
from ..models.anomaly_detector import AnomalyDetector
from ..models.llm_analyzer import LLMAnalyzer
from ..firewall.ai_firewall import AIFirewall
from ..healing.self_healing import SelfHealing

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Get the absolute path to the dashboard directory
current_dir = Path(__file__).resolve().parent
dashboard_dir = current_dir.parent / "dashboard"
js_dir = dashboard_dir / "js"

logger.info(f"Current directory: {current_dir}")
logger.info(f"Dashboard directory: {dashboard_dir}")
logger.info(f"JS directory: {js_dir}")

if not dashboard_dir.exists():
    logger.error(f"Dashboard directory not found: {dashboard_dir}")
    raise RuntimeError("Dashboard directory not found")

app = FastAPI(title="AGIS Defence API", version="0.1.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
try:
    # Mount the dashboard directory
    app.mount("/static", StaticFiles(directory=str(dashboard_dir)), name="static")
    # Explicitly mount the js directory
    app.mount("/js", StaticFiles(directory=str(js_dir)), name="js")
    logger.info(f"Successfully mounted static directory: {dashboard_dir}")
    logger.info(f"Successfully mounted js directory: {js_dir}")
    
    # List files in dashboard directory for debugging
    logger.debug("Dashboard directory contents:")
    for item in dashboard_dir.glob("**/*"):
        logger.debug(f"  {item.relative_to(dashboard_dir)}")
except Exception as e:
    logger.error(f"Error mounting static directory: {str(e)}")
    raise

@app.get("/")
async def root(request: Request):
    """Serve the dashboard."""
    try:
        index_path = dashboard_dir / "index.html"
        logger.debug(f"Request headers: {request.headers}")
        logger.info(f"Serving index.html from: {index_path}")
        
        if not index_path.exists():
            logger.error(f"index.html not found at {index_path}")
            raise HTTPException(status_code=404, detail="Dashboard not found")
            
        return FileResponse(str(index_path), media_type="text/html")
    except Exception as e:
        logger.error(f"Error serving dashboard: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/js/{file_path:path}")
async def serve_js(file_path: str):
    """Serve JavaScript files."""
    try:
        file_full_path = js_dir / file_path
        logger.info(f"Serving JS file from: {file_full_path}")
        
        if not file_full_path.exists():
            logger.error(f"JS file not found: {file_full_path}")
            raise HTTPException(status_code=404, detail=f"File {file_path} not found")
            
        return FileResponse(str(file_full_path), media_type="application/javascript")
    except Exception as e:
        logger.error(f"Error serving JS file: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/js/app.js")
async def serve_app_js():
    """Explicitly serve the app.js file."""
    try:
        app_js_path = js_dir / "app.js"
        logger.debug(f"Attempting to serve app.js from: {app_js_path}")
        
        if not app_js_path.exists():
            logger.error(f"app.js not found at {app_js_path}")
            raise HTTPException(status_code=404, detail="app.js not found")
            
        return FileResponse(
            path=str(app_js_path),
            media_type="application/javascript",
            headers={"Content-Type": "application/javascript"}
        )
    except Exception as e:
        logger.error(f"Error serving app.js: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Initialize components
try:
    network_monitor = NetworkMonitor()
    anomaly_detector = AnomalyDetector()
    llm_analyzer = LLMAnalyzer()
    firewall = AIFirewall()
    healing = SelfHealing()

    # Start monitoring
    network_monitor.start_monitoring()
except Exception as e:
    logger.error(f"Error initializing components: {str(e)}")

@app.get("/network/stats")
async def get_network_stats():
    """Get current network statistics."""
    return network_monitor.get_current_stats()

@app.get("/network/anomalies")
async def get_network_anomalies():
    """Get detected network anomalies."""
    return network_monitor.detect_anomalies()

@app.get("/firewall/status")
async def get_firewall_status():
    """Get current firewall status."""
    return firewall.get_status()

@app.post("/firewall/block/{ip}")
async def block_ip(ip: str, reason: Optional[str] = None):
    """Block an IP address."""
    success = firewall.block_ip(ip, reason=reason or "Manual block")
    if not success:
        raise HTTPException(status_code=500, detail="Failed to block IP")
    return {"status": "success", "message": f"Blocked IP {ip}"}

@app.post("/firewall/unblock/{ip}")
async def unblock_ip(ip: str):
    """Unblock an IP address."""
    success = firewall.unblock_ip(ip)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to unblock IP")
    return {"status": "success", "message": f"Unblocked IP {ip}"}

@app.get("/healing/status")
async def get_healing_status():
    """Get self-healing system status."""
    return healing.get_healing_status()

@app.post("/healing/backup")
async def create_backup(filepath: str):
    """Create a backup of a file."""
    backup_path = healing.backup_file(filepath)
    if not backup_path:
        raise HTTPException(status_code=500, detail="Failed to create backup")
    return {"status": "success", "backup_path": backup_path}

@app.post("/healing/restore")
async def restore_backup(original_path: str, backup_path: str):
    """Restore a file from backup."""
    success = healing.restore_file(original_path, backup_path)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to restore backup")
    return {"status": "success", "message": "Backup restored successfully"}

@app.post("/threat/analyze")
async def analyze_threat(data: Dict):
    """Analyze a potential threat using LLM."""
    analysis = llm_analyzer.analyze_threat(data)
    if "error" in analysis:
        raise HTTPException(status_code=500, detail=analysis["error"])
    return analysis

@app.post("/threat/handle")
async def handle_threat(data: Dict):
    """Handle a detected threat."""
    # Get LLM analysis
    analysis = llm_analyzer.analyze_threat(data)
    
    # Update threat data with analysis
    threat_data = {**data, **analysis}
    
    # Handle with firewall
    firewall_response = firewall.handle_threat(threat_data)
    
    # Handle with healing system
    healing_response = healing.handle_threat(threat_data)
    
    return {
        "analysis": analysis,
        "firewall_response": firewall_response,
        "healing_response": healing_response
    }

@app.get("/api/system/status")
async def get_system_status():
    """Get complete system status."""
    try:
        return {
            "network": network_monitor.get_current_stats(),
            "anomalies": network_monitor.detect_anomalies(),
            "firewall": firewall.get_status(),
            "healing": healing.get_healing_status(),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting system status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) 