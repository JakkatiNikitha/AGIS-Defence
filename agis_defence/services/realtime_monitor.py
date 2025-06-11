import scapy.all as scapy
from scapy.layers import http
import psutil
import threading
import time
from datetime import datetime
import logging
from typing import Dict, List, Optional
from ..models.threat_detection import ThreatDetector
from ..collectors.log_collector import LogCollector
from agis_defence.config.threat_detection import (
    SYSTEM_THRESHOLDS,
    NETWORK_THRESHOLDS,
    AUTH_THRESHOLDS,
    FILESYSTEM_THRESHOLDS,
    WEB_ATTACK_THRESHOLDS,
    RESPONSE_THRESHOLDS,
    AI_THRESHOLDS,
    SEVERITY_WEIGHTS
)

logger = logging.getLogger(__name__)

class RealtimeMonitor:
    def __init__(self):
        self.is_running = False
        self.monitor_thread = None
        self.packet_thread = None
        self.threat_detector = ThreatDetector()
        self.log_collector = LogCollector()
        self.suspicious_ips = set()
        self.connection_attempts = {}
        self.last_cleanup = time.time()
        self.blocked_ips = set()
        self.monitoring_ips = {}
        
    def start_monitoring(self):
        """Start real-time monitoring threads"""
        if not self.is_running:
            self.is_running = True
            
            # Start system monitoring thread
            self.monitor_thread = threading.Thread(target=self._monitor_system)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            
            # Start packet capture thread
            self.packet_thread = threading.Thread(target=self._capture_packets)
            self.packet_thread.daemon = True
            self.packet_thread.start()
            
            logger.info("Real-time monitoring started")
            
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.is_running = False
        if self.monitor_thread:
            self.monitor_thread.join()
        if self.packet_thread:
            self.packet_thread.join()
        logger.info("Real-time monitoring stopped")
            
    def _monitor_system(self):
        """Monitor system metrics and logs in real-time"""
        while self.is_running:
            try:
                current_time = time.time()
                
                # Cleanup old data periodically
                if current_time - self.last_cleanup > 300:  # Every 5 minutes
                    self._cleanup_old_data()
                    self.last_cleanup = current_time
                
                # Monitor CPU spikes
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > SYSTEM_THRESHOLDS['cpu_usage']:
                    self.threat_detector._create_threat(
                        "high_cpu_usage",
                        "system",
                        "local",
                        severity="medium" if cpu_percent < 95 else "high",
                        details=f"CPU usage at {cpu_percent}%"
                    )
                
                # Monitor memory usage
                memory = psutil.virtual_memory()
                if memory.percent > SYSTEM_THRESHOLDS['memory_usage']:
                    self.threat_detector._create_threat(
                        "high_memory_usage",
                        "system",
                        "local",
                        severity="medium" if memory.percent < 95 else "high",
                        details=f"Memory usage at {memory.percent}%"
                    )
                
                # Monitor process count
                process_count = len(psutil.pids())
                if process_count > SYSTEM_THRESHOLDS['process_count']:
                    self.threat_detector._create_threat(
                        "high_process_count",
                        "system",
                        "local",
                        severity="medium",
                        details=f"High process count: {process_count}"
                    )
                
                # Monitor network connections
                connections = psutil.net_connections()
                self._analyze_connections(connections, current_time)
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                logger.error(f"Error in system monitoring: {e}")
                time.sleep(5)  # Wait before retrying
                
    def _analyze_connections(self, connections, current_time):
        """Analyze network connections for potential threats"""
        connection_counts = {}
        
        for conn in connections:
            if conn.raddr and conn.raddr.ip:
                remote_ip = conn.raddr.ip
                
                # Skip if IP is already blocked
                if remote_ip in self.blocked_ips:
                    continue
                
                # Initialize tracking for new IP
                if remote_ip not in self.connection_attempts:
                    self.connection_attempts[remote_ip] = []
                if remote_ip not in connection_counts:
                    connection_counts[remote_ip] = 0
                
                # Track connection
                connection_counts[remote_ip] += 1
                self.connection_attempts[remote_ip].append(current_time)
                
                # Remove old attempts (older than 1 minute)
                self.connection_attempts[remote_ip] = [
                    t for t in self.connection_attempts[remote_ip]
                    if current_time - t <= 60
                ]
                
                # Check for potential brute force
                if len(self.connection_attempts[remote_ip]) > NETWORK_THRESHOLDS['connection_rate']:
                    self._handle_threat(
                        "brute_force_attempt",
                        remote_ip,
                        "high",
                        f"High connection rate from {remote_ip}: {len(self.connection_attempts[remote_ip])} attempts/min"
                    )
                
                # Check for potential DDoS
                if connection_counts[remote_ip] > NETWORK_THRESHOLDS['connections_per_second']:
                    self._handle_threat(
                        "ddos_attempt",
                        remote_ip,
                        "critical",
                        f"Possible DDoS from {remote_ip}: {connection_counts[remote_ip]} connections/sec"
                    )
                
    def _capture_packets(self):
        """Capture and analyze network packets in real-time"""
        try:
            # Start packet capture
            scapy.sniff(
                prn=self._packet_callback,
                store=False,  # Don't store packets in memory
                filter="tcp or udp"  # Only capture TCP and UDP
            )
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            
    def _packet_callback(self, packet):
        """Analyze captured packets for potential threats"""
        try:
            if not self.is_running:
                return
                
            if packet.haslayer(http.HTTPRequest):
                # Get source IP
                src_ip = packet[scapy.IP].src
                
                # Skip if IP is already blocked
                if src_ip in self.blocked_ips:
                    return
                
                # Check for SQL injection attempts
                if self._check_sql_injection(packet):
                    self._handle_threat(
                        "sql_injection_attempt",
                        src_ip,
                        "high",
                        "SQL injection pattern detected in HTTP request"
                    )
                
                # Check for XSS attempts
                if self._check_xss(packet):
                    self._handle_threat(
                        "xss_attempt",
                        src_ip,
                        "high",
                        "XSS pattern detected in HTTP request"
                    )
                    
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            
    def _check_sql_injection(self, packet) -> bool:
        """Check for SQL injection patterns in HTTP requests"""
        try:
            if packet.haslayer(http.HTTPRequest):
                # Get the URL and parameters
                url = packet[http.HTTPRequest].Path.decode('utf-8')
                
                # Check against SQL injection patterns
                return any(
                    pattern.lower() in url.lower()
                    for pattern in WEB_ATTACK_THRESHOLDS['sql_injection_patterns']
                )
        except:
            return False
            
    def _check_xss(self, packet) -> bool:
        """Check for XSS attempts in HTTP requests"""
        try:
            if packet.haslayer(http.HTTPRequest):
                # Get the URL and parameters
                url = packet[http.HTTPRequest].Path.decode('utf-8')
                
                # Check against XSS patterns
                return any(
                    pattern.lower() in url.lower()
                    for pattern in WEB_ATTACK_THRESHOLDS['xss_patterns']
                )
        except:
            return False
            
    def _handle_threat(self, threat_type: str, source: str, severity: str, details: str):
        """Handle detected threats"""
        # Create threat
        self.threat_detector._create_threat(
            threat_type,
            "network" if "attempt" in threat_type else "system",
            source,
            severity=severity,
            details=details
        )
        
        # Track suspicious IP
        if source != "local":
            self.suspicious_ips.add(source)
            
            # Check if IP should be blocked
            ip_threats = sum(1 for t in self.threat_detector.active_threats
                           if t.get('source') == source)
            
            if ip_threats >= RESPONSE_THRESHOLDS['block_ip_threshold']:
                self.blocked_ips.add(source)
                logger.warning(f"Blocked IP {source} due to multiple threats")
                
    def _cleanup_old_data(self):
        """Clean up old monitoring data"""
        current_time = time.time()
        
        # Clean up old connection attempts
        for ip in list(self.connection_attempts.keys()):
            self.connection_attempts[ip] = [
                t for t in self.connection_attempts[ip]
                if current_time - t <= 60
            ]
            if not self.connection_attempts[ip]:
                del self.connection_attempts[ip]
        
        # Clean up old blocked IPs
        for ip in list(self.blocked_ips):
            if ip in self.monitoring_ips:
                if current_time - self.monitoring_ips[ip] > RESPONSE_THRESHOLDS['block_duration']:
                    self.blocked_ips.remove(ip)
                    del self.monitoring_ips[ip]
                    logger.info(f"Unblocked IP {ip} after block duration") 