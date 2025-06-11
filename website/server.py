from flask import Flask, send_from_directory, send_file, after_this_request, make_response, redirect, url_for
import os
import mimetypes
import logging
from werkzeug.utils import secure_filename

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('website_debug.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Add MIME type for .exe files
mimetypes.add_type('application/x-msdownload', '.exe')

app = Flask(__name__)

# Get the absolute path to the website directory
WEBSITE_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOADS_DIR = os.path.join(WEBSITE_DIR, 'downloads')

def add_no_cache_headers(response):
    """Add headers to prevent caching"""
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, post-check=0, pre-check=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
def index():
    response = make_response(send_from_directory(WEBSITE_DIR, 'index.html'))
    return add_no_cache_headers(response)

@app.route('/assets/<path:path>')
def serve_assets(path):
    return send_from_directory(os.path.join(WEBSITE_DIR, 'assets'), path)

# New download endpoint
@app.route('/get-installer/windows')
def download_windows_installer():
    try:
        filename = 'AGIS-Defence-Setup-Win64.zip'
        file_path = os.path.join(DOWNLOADS_DIR, filename)
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {filename}")
            return "Installation package not found. Please try again later.", 404

        file_size = os.path.getsize(file_path)
        logger.info(f"Serving Windows installer: {filename} (Size: {file_size} bytes)")

        response = make_response(send_file(
            file_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/zip'
        ))

        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        response.headers['Content-Type'] = 'application/zip'
        response.headers['Content-Length'] = file_size
        return add_no_cache_headers(response)

    except Exception as e:
        logger.exception("Error serving Windows installer")
        return "Error preparing download. Please try again.", 500

# Redirect old download URLs to new endpoint
@app.route('/downloads/<path:filename>')
def legacy_download(filename):
    if filename.startswith('AGIS-Defence-Setup-Win64'):
        return redirect(url_for('download_windows_installer'))
    return f"File not found: {filename}", 404

@app.route('/<path:path>')
def serve_file(path):
    return send_from_directory(WEBSITE_DIR, path)

if __name__ == '__main__':
    # Ensure downloads directory exists
    os.makedirs(DOWNLOADS_DIR, exist_ok=True)
    
    # Log initial configuration
    logger.info(f"Website directory: {WEBSITE_DIR}")
    logger.info(f"Downloads directory: {DOWNLOADS_DIR}")
    
    # Check downloads directory contents
    logger.info("Checking downloads directory contents:")
    try:
        files = os.listdir(DOWNLOADS_DIR)
        if not files:
            logger.warning("Downloads directory is empty!")
        for file in files:
            file_path = os.path.join(DOWNLOADS_DIR, file)
            logger.info(f"- {file} ({os.path.getsize(file_path)} bytes)")
    except Exception as e:
        logger.error(f"Error checking downloads directory: {str(e)}")
    
    # Start the server
    app.run(host='0.0.0.0', port=80) 