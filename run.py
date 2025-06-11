"""Run script for AGIS Defence System."""

from agis_defence.app import app

if __name__ == '__main__':
    print("Starting AGIS Defence System...")
    print("Dashboard will be available at http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True) 