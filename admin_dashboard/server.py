from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, send_from_directory
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
import jwt
from datetime import datetime, timedelta
import os
import json
import logging
import psutil
from threat_detection import ThreatDetector
import platform
import socket

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///admin.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Specify the login view
login_manager.init_app(app)

# Initialize threat detector
threat_detector = ThreatDetector()

# Configure logging
logging.basicConfig(
    filename='admin.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Database Models
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False, default='admin')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    license_type = db.Column(db.String(20), nullable=False)
    license_expiry = db.Column(db.DateTime, nullable=False)
    active = db.Column(db.Boolean, default=True)
    last_active = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class SoftwareUpdate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    release_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')

# Add new model for detailed system metrics
class SystemMetrics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cpu_usage = db.Column(db.Float)
    memory_usage = db.Column(db.Float)
    disk_usage = db.Column(db.Float)
    network_in = db.Column(db.Float)
    network_out = db.Column(db.Float)
    active_connections = db.Column(db.Integer)

# Routes
@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/admin/users')
@login_required
def get_users():
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'licenseType': user.license_type,
        'licenseExpiry': user.license_expiry.isoformat(),
        'active': user.active,
        'lastActive': user.last_active.isoformat() if user.last_active else None,
        'createdAt': user.created_at.isoformat()
    } for user in users])

@app.route('/api/admin/logs')
@login_required
def get_logs():
    logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).limit(100).all()
    return jsonify([{
        'id': log.id,
        'type': log.type,
        'severity': log.severity,
        'message': log.message,
        'details': log.details,
        'timestamp': log.timestamp.isoformat()
    } for log in logs])

@app.route('/api/admin/updates')
@login_required
def get_updates():
    updates = SoftwareUpdate.query.order_by(SoftwareUpdate.release_date.desc()).all()
    return jsonify([{
        'id': update.id,
        'version': update.version,
        'description': update.description,
        'date': update.release_date.isoformat(),
        'status': update.status
    } for update in updates])

@app.route('/api/admin/statistics')
@login_required
def get_statistics():
    active_users = User.query.filter_by(active=True).count()
    threats_blocked = SystemLog.query.filter_by(
        type='threat',
        timestamp=datetime.utcnow() - timedelta(hours=24)
    ).count()
    
    return jsonify({
        'activeUsers': active_users,
        'threatsBlocked': threats_blocked
    })

@app.route('/api/admin/users/<int:user_id>/deactivate', methods=['POST'])
@login_required
def deactivate_user(user_id):
    user = User.query.get_or_404(user_id)
    user.active = False
    db.session.commit()
    
    # Log the action
    log = SystemLog(
        type='user_management',
        severity='info',
        message=f'User {user.email} deactivated',
        user_id=user_id
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'success': True})

# WebSocket events
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        emit('connected', {'data': 'Connected to admin server'})
        socketio.start_background_task(background_metrics)
        
        # Check for threats on connection
        threats = threat_detector.check_system_resources()
        for threat in threats:
            emit('new_threat', threat)

@socketio.on('user_activity')
def handle_user_activity(data):
    # Update user's last active timestamp
    user = User.query.get(data['user_id'])
    if user:
        user.last_active = datetime.utcnow()
        db.session.commit()
        
        # Broadcast to all admin clients
        emit('user_activity_update', {
            'user_id': user.id,
            'last_active': user.last_active.isoformat()
        }, broadcast=True)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

# CLI commands
@app.cli.command("create-admin")
def create_admin():
    """Create a new admin user."""
    admin = Admin(
        username='admin',
        password='admin',  # In production, use proper password hashing
        email='admin@agis.com',
        role='superadmin'
    )
    db.session.add(admin)
    db.session.commit()
    print('Admin user created successfully')

# Add this after login_manager initialization
@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

# Add login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = Admin.query.filter_by(username=username, password=password).first()
        
        # Get client IP
        ip_address = request.remote_addr
        
        if user:
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            # Record failed login attempt
            threat_detector.record_failed_login(ip_address)
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Add system metrics endpoint
@app.route('/api/admin/metrics')
@login_required
def get_metrics():
    cpu_percent = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    
    return jsonify({
        'cpu': cpu_percent,
        'memory': memory.percent,
        'disk': psutil.disk_usage('/').percent
    })

# Background task for system metrics
def background_metrics():
    while True:
        with app.app_context():
            try:
                # Get current metrics
                cpu = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                network = psutil.net_io_counters()
                
                # Emit to connected clients
                socketio.emit('metrics_update', {
                    'cpu': cpu,
                    'memory': memory.percent,
                    'disk': disk.percent,
                    'network': {
                        'in': network.bytes_recv,
                        'out': network.bytes_sent
                    }
                })
                
            except Exception as e:
                logging.error(f"Error in background metrics: {str(e)}")
            
            socketio.sleep(5)  # Update every 5 seconds

# Serve static files
@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

# User Management Routes
@app.route('/api/admin/users/create', methods=['POST'])
@login_required
def create_user():
    try:
        data = request.json
        # Validate required fields
        required_fields = ['name', 'email', 'license_type']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400

        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'User with this email already exists'}), 409

        # Calculate license expiry based on type
        license_duration = {
            'trial': timedelta(days=30),
            'basic': timedelta(days=365),
            'premium': timedelta(days=365),
            'enterprise': timedelta(days=365*2)
        }
        
        expiry_date = datetime.utcnow() + license_duration.get(data['license_type'], timedelta(days=30))

        # Create new user
        new_user = User(
            name=data['name'],
            email=data['email'],
            license_type=data['license_type'],
            license_expiry=expiry_date,
            active=True,
            last_active=datetime.utcnow()
        )
        
        db.session.add(new_user)
        db.session.commit()

        # Log user creation
        log = SystemLog(
            type='user_management',
            severity='info',
            message=f'New user created: {data["email"]}',
            details=f'License type: {data["license_type"]}'
        )
        db.session.add(log)
        db.session.commit()

        return jsonify({
            'success': True,
            'user': {
                'id': new_user.id,
                'name': new_user.name,
                'email': new_user.email,
                'license_type': new_user.license_type,
                'license_expiry': new_user.license_expiry.isoformat(),
                'active': new_user.active
            }
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        data = request.json

        # Update user fields
        if 'name' in data:
            user.name = data['name']
        if 'email' in data and data['email'] != user.email:
            # Check if new email already exists
            if User.query.filter_by(email=data['email']).first():
                return jsonify({'error': 'Email already in use'}), 409
            user.email = data['email']
        if 'license_type' in data:
            user.license_type = data['license_type']
            # Update license expiry based on new type
            license_duration = {
                'trial': timedelta(days=30),
                'basic': timedelta(days=365),
                'premium': timedelta(days=365),
                'enterprise': timedelta(days=365*2)
            }
            user.license_expiry = datetime.utcnow() + license_duration.get(data['license_type'], timedelta(days=30))

        db.session.commit()

        # Log user update
        log = SystemLog(
            type='user_management',
            severity='info',
            message=f'User updated: {user.email}',
            details=f'Updated fields: {", ".join(data.keys())}'
        )
        db.session.add(log)
        db.session.commit()

        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'license_type': user.license_type,
                'license_expiry': user.license_expiry.isoformat(),
                'active': user.active
            }
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users/<int:user_id>/extend-license', methods=['POST'])
@login_required
def extend_user_license(user_id):
    try:
        user = User.query.get_or_404(user_id)
        data = request.json
        duration_days = data.get('duration_days', 365)  # Default to 1 year

        # Extend license from current expiry or now, whichever is later
        current_expiry = max(user.license_expiry, datetime.utcnow())
        user.license_expiry = current_expiry + timedelta(days=duration_days)
        
        db.session.commit()

        # Log license extension
        log = SystemLog(
            type='user_management',
            severity='info',
            message=f'License extended for user: {user.email}',
            details=f'Extended by {duration_days} days. New expiry: {user.license_expiry}'
        )
        db.session.add(log)
        db.session.commit()

        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'license_type': user.license_type,
                'license_expiry': user.license_expiry.isoformat(),
                'active': user.active
            }
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Threat callback function
def handle_threat(threat):
    socketio.emit('new_threat', threat)
    
    # Log the threat
    log = SystemLog(
        type='security_threat',
        severity=threat['severity'],
        message=threat['type'],
        details=threat['details']
    )
    with app.app_context():
        db.session.add(log)
        db.session.commit()

# Start threat monitoring
threat_detector.start_monitoring(callback=handle_threat)

# Add new routes for system monitoring
@app.route('/api/admin/system/metrics')
@login_required
def get_system_metrics():
    try:
        # Get current metrics
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_io_counters()
        connections = len(psutil.net_connections())
        
        # Save metrics to database
        metrics = SystemMetrics(
            cpu_usage=cpu,
            memory_usage=memory.percent,
            disk_usage=disk.percent,
            network_in=network.bytes_recv,
            network_out=network.bytes_sent,
            active_connections=connections
        )
        db.session.add(metrics)
        db.session.commit()
        
        return jsonify({
            'cpu': cpu,
            'memory': memory.percent,
            'disk': disk.percent,
            'network': {
                'in': network.bytes_recv,
                'out': network.bytes_sent
            },
            'connections': connections
        })
    except Exception as e:
        logging.error(f"Error getting system metrics: {str(e)}")
        return jsonify({'error': 'Failed to get system metrics'}), 500

@app.route('/api/admin/system-info')
@login_required
def get_system_info():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        
        system_info = {
            'platform': platform.system(),
            'processor': platform.processor(),
            'architecture': platform.machine(),
            'hostname': hostname,
            'ip_address': ip_address,
            'python_version': platform.python_version(),
            'os_version': platform.version()
        }
        
        # Log successful info retrieval
        logging.info('System information retrieved successfully')
        return jsonify(system_info)
        
    except socket.gaierror as e:
        logging.error(f"Network error getting system info: {str(e)}")
        return jsonify({'error': 'Failed to get network information'}), 500
    except Exception as e:
        logging.error(f"Error getting system info: {str(e)}")
        return jsonify({'error': 'Failed to get system information'}), 500

@app.route('/api/admin/threats')
@login_required
def get_threats():
    try:
        return jsonify(threat_detector.threat_log)
    except Exception as e:
        logging.error(f"Error getting threats: {str(e)}")
        return jsonify({'error': 'Failed to get threats'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create default admin if it doesn't exist
        admin = Admin.query.filter_by(username='admin').first()
        if not admin:
            admin = Admin(
                username='admin',
                password='admin',  # In production, use proper password hashing
                email='admin@agis.com',
                role='superadmin'
            )
            db.session.add(admin)
            db.session.commit()
            print('Default admin user created successfully')
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000) 