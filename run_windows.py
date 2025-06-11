from waitress import serve
from app import app
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/agis.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

if __name__ == '__main__':
    HOST = '192.168.29.116'  # Your specific IP address
    PORT = 8000
    
    logger.info(f'Starting AGIS Defence System on http://{HOST}:{PORT}')
    print(f'AGIS Defence System is running on http://{HOST}:{PORT}')
    
    # Run the app using Waitress
    serve(app, host=HOST, port=PORT, threads=4) 