"""Main entry point for AGIS Defence System."""

from flask import Flask
from agis_defence.app import app
from agis_defence.services.realtime_monitor import RealtimeMonitor
import logging
import sys
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('agis.log')
    ]
)
logger = logging.getLogger(__name__)

def check_requirements():
    """Check if running with required privileges."""
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:  # Unix/Linux
        return os.geteuid() == 0

def main():
    """Main function to run the AGIS Defence System."""
    try:
        # Check privileges
        if not check_requirements():
            logger.warning("Running without administrator privileges. Some features may be limited.")
        
        # Initialize real-time monitor
        monitor = RealtimeMonitor()
        monitor.start_monitoring()
        
        logger.info("Starting AGIS Defence System...")
        # Run the Flask app
        app.run(host='0.0.0.0', port=5000, debug=False)
        
    except Exception as e:
        logger.error(f"Error starting AGIS Defence System: {e}")
        sys.exit(1)
    finally:
        if 'monitor' in locals():
            monitor.stop_monitoring()

if __name__ == '__main__':
    main() 