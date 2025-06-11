from waitress import serve
from server import app
import logging
import os

# Ensure we're in the website directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('website.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

if __name__ == '__main__':
    HOST = '192.168.29.116'  # Your specific IP address
    PORT = 80  # Standard HTTP port
    
    logger.info(f'Starting AGIS Website on http://{HOST}:{PORT}')
    print(f'AGIS Website is running on http://{HOST}:{PORT}')
    
    # Run the app using Waitress
    serve(app, host=HOST, port=PORT, threads=4) 