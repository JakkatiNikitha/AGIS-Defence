import os

# Production configuration
DEBUG = False
TESTING = False
SECRET_KEY = os.environ.get('AGIS_SECRET_KEY', 'generate-a-secure-key-here')

# Server settings
HOST = '0.0.0.0'
PORT = 8000

# Security settings
SESSION_COOKIE_SECURE = True
REMEMBER_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
REMEMBER_COOKIE_HTTPONLY = True

# SSL/TLS settings (if using HTTPS directly through Flask)
SSL_CERT_PATH = os.environ.get('SSL_CERT_PATH')
SSL_KEY_PATH = os.environ.get('SSL_KEY_PATH') 