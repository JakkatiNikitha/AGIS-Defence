import psutil
import platform
import socket
import json
import os
from datetime import datetime
import threading
import time
import logging
from collections import defaultdict

class ThreatDetector:
    def __init__(self):
        self.threat_log = []
        self.suspicious_ips = defaultdict(int)
        self.failed_logins = defaultdict(int)
        self.port_scan_attempts = defaultdict(int)
        
        # Configure logging
        logging.basicConfig(
            filename='threats.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def check_system_resources(self):
        """Monitor system resources for suspicious activity"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Check for resource abuse
            threats = []
            if cpu_percent > 90:  # CPU usage above 90%
                threats.append({
                    'type': 'resource_abuse',
                    'severity': 'high',
                    'details': f'High CPU usage detected: {cpu_percent}%'
                })
            
            if memory.percent > 90:  # Memory usage above 90%
                threats.append({
                    'type': 'resource_abuse',
                    'severity': 'high',
                    'details': f'High memory usage detected: {memory.percent}%'
                })
            
            if disk.percent > 90:  # Disk usage above 90%
                threats.append({
                    'type': 'resource_abuse',
                    'severity': 'medium',
                    'details': f'High disk usage detected: {disk.percent}%'
                })
            
            return threats
        except Exception as e:
            logging.error(f"Error in system resource check: {str(e)}")
            return []

    def check_network_activity(self, ip_address, port):
        """Monitor network activity for suspicious behavior"""
        try:
            # Track connection attempts per IP
            self.suspicious_ips[ip_address] += 1
            
            threats = []
            # Check for potential port scanning
            if self.port_scan_attempts[ip_address] > 10:
                threats.append({
                    'type': 'port_scan',
                    'severity': 'high',
                    'details': f'Potential port scanning detected from IP: {ip_address}'
                })
            
            # Check for multiple failed login attempts
            if self.failed_logins[ip_address] > 5:
                threats.append({
                    'type': 'brute_force',
                    'severity': 'high',
                    'details': f'Multiple failed login attempts from IP: {ip_address}'
                })
            
            # Check for suspicious ports
            suspicious_ports = [22, 23, 3389, 445]  # SSH, Telnet, RDP, SMB
            if port in suspicious_ports:
                threats.append({
                    'type': 'suspicious_port',
                    'severity': 'medium',
                    'details': f'Connection attempt to suspicious port {port} from {ip_address}'
                })
            
            return threats
        except Exception as e:
            logging.error(f"Error in network activity check: {str(e)}")
            return []

    def check_file_system(self):
        """Monitor file system for suspicious changes"""
        try:
            threats = []
            # Add file system monitoring logic here
            # Example: Monitor sensitive directories
            sensitive_dirs = ['/etc', '/var/log', '/usr/bin']
            for dir_path in sensitive_dirs:
                try:
                    # Check for write permissions in sensitive directories
                    if os.access(dir_path, os.W_OK):
                        threats.append({
                            'type': 'file_system',
                            'severity': 'medium',
                            'details': f'Writable permissions detected in sensitive directory: {dir_path}'
                        })
                except Exception as e:
                    logging.warning(f"Error checking directory {dir_path}: {str(e)}")
            
            return threats
        except Exception as e:
            logging.error(f"Error in file system check: {str(e)}")
            return []

    def record_failed_login(self, ip_address):
        """Record failed login attempts"""
        self.failed_logins[ip_address] += 1
        if self.failed_logins[ip_address] > 5:
            logging.warning(f"Multiple failed login attempts from IP: {ip_address}")

    def record_port_scan(self, ip_address, port):
        """Record potential port scan attempts"""
        self.port_scan_attempts[ip_address] += 1
        logging.info(f"Port scan attempt recorded - IP: {ip_address}, Port: {port}")

    def get_system_info(self):
        """Get detailed system information"""
        try:
            info = {
                'platform': platform.platform(),
                'processor': platform.processor(),
                'architecture': platform.machine(),
                'hostname': socket.gethostname(),
                'ip_address': socket.gethostbyname(socket.gethostname()),
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_total': psutil.disk_usage('/').total
            }
            return info
        except Exception as e:
            logging.error(f"Error getting system info: {str(e)}")
            return {}

    def monitor_system(self, callback=None):
        """Continuous system monitoring"""
        while True:
            try:
                # Check all potential threats
                threats = []
                threats.extend(self.check_system_resources())
                threats.extend(self.check_file_system())
                
                # Log threats and notify if callback is provided
                for threat in threats:
                    logging.warning(f"Threat detected: {json.dumps(threat)}")
                    self.threat_log.append({
                        'timestamp': datetime.utcnow().isoformat(),
                        **threat
                    })
                    if callback:
                        callback(threat)
                
                # Clean up old records
                self._cleanup_old_records()
                
                # Wait before next check
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logging.error(f"Error in system monitoring: {str(e)}")
                time.sleep(60)  # Wait before retrying

    def _cleanup_old_records(self):
        """Clean up old records to prevent memory bloat"""
        try:
            # Keep only last 1000 threats in memory
            if len(self.threat_log) > 1000:
                self.threat_log = self.threat_log[-1000:]
            
            # Reset counters periodically
            current_time = time.time()
            for ip in list(self.suspicious_ips.keys()):
                if current_time - self.suspicious_ips[ip] > 3600:  # 1 hour
                    del self.suspicious_ips[ip]
            
            for ip in list(self.failed_logins.keys()):
                if current_time - self.failed_logins[ip] > 3600:  # 1 hour
                    del self.failed_logins[ip]
            
            for ip in list(self.port_scan_attempts.keys()):
                if current_time - self.port_scan_attempts[ip] > 3600:  # 1 hour
                    del self.port_scan_attempts[ip]
                    
        except Exception as e:
            logging.error(f"Error in cleanup: {str(e)}")

    def start_monitoring(self, callback=None):
        """Start the monitoring thread"""
        monitor_thread = threading.Thread(
            target=self.monitor_system,
            args=(callback,),
            daemon=True
        )
        monitor_thread.start()
        logging.info("Threat monitoring started") 