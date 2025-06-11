from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import threading
import time
import logging
from typing import Dict, List, Optional
from datetime import datetime
import json
from pathlib import Path
import psutil  # For fallback network monitoring

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkMonitor:
    """Monitor network traffic and detect anomalies."""

    def __init__(self, storage_dir: str = "data/network"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.packet_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'ports': defaultdict(int),
            'protocols': defaultdict(int)
        })
        self.lock = threading.Lock()
        self._stop_flag = threading.Event()
        self.use_fallback = False

    def start_monitoring(self, interface: Optional[str] = None):
        """Start network monitoring on specified interface."""
        logger.info(f"Starting network monitoring on interface: {interface or 'default'}")
        
        try:
            # Try to start packet capture
            self.capture_thread = threading.Thread(
                target=self._capture_packets,
                args=(interface,)
            )
            self.capture_thread.start()
        except Exception as e:
            logger.warning(f"Packet capture not available: {str(e)}")
            logger.info("Falling back to basic network statistics monitoring")
            self.use_fallback = True
            self.capture_thread = threading.Thread(
                target=self._fallback_monitoring
            )
            self.capture_thread.start()

        # Start stats saving in another thread
        self.stats_thread = threading.Thread(
            target=self._save_stats_periodically
        )
        self.stats_thread.start()

    def stop_monitoring(self):
        """Stop network monitoring."""
        logger.info("Stopping network monitoring...")
        self._stop_flag.set()
        self.capture_thread.join()
        self.stats_thread.join()

    def _fallback_monitoring(self):
        """Monitor network using psutil when packet capture is not available."""
        while not self._stop_flag.is_set():
            try:
                # Get network counters
                net_io = psutil.net_io_counters()
                with self.lock:
                    stats = self.packet_stats['system']
                    stats['byte_count'] = net_io.bytes_sent + net_io.bytes_recv
                    stats['packet_count'] = net_io.packets_sent + net_io.packets_recv
                    stats['protocols']['total'] = 1
                    
                    # Get network connections
                    connections = psutil.net_connections()
                    for conn in connections:
                        if conn.laddr and conn.laddr.port:
                            stats['ports'][str(conn.laddr.port)] += 1
                
                time.sleep(1)  # Update every second
                
            except Exception as e:
                logger.error(f"Error in fallback monitoring: {str(e)}")
                time.sleep(5)

    def _capture_packets(self, interface: Optional[str]):
        """Capture and process network packets."""
        try:
            sniff(
                iface=interface,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda _: self._stop_flag.is_set()
            )
        except Exception as e:
            logger.error(f"Error in packet capture: {str(e)}")
            # Switch to fallback mode
            self.use_fallback = True
            self._fallback_monitoring()

    def _process_packet(self, packet):
        """Process a single packet and update statistics."""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            length = len(packet)

            with self.lock:
                # Update source IP stats
                self._update_ip_stats(src_ip, length, packet, 'source')
                # Update destination IP stats
                self._update_ip_stats(dst_ip, length, packet, 'destination')

    def _update_ip_stats(self, ip: str, length: int, packet, direction: str):
        """Update statistics for an IP address."""
        stats = self.packet_stats[ip]
        stats['packet_count'] += 1
        stats['byte_count'] += length
        
        # Track ports
        if TCP in packet:
            port = packet[TCP].sport if direction == 'source' else packet[TCP].dport
            stats['ports'][port] += 1
            stats['protocols']['TCP'] += 1
        elif UDP in packet:
            port = packet[UDP].sport if direction == 'source' else packet[UDP].dport
            stats['ports'][port] += 1
            stats['protocols']['UDP'] += 1

    def _save_stats_periodically(self, interval: int = 300):
        """Save network statistics periodically."""
        while not self._stop_flag.is_set():
            self._save_current_stats()
            time.sleep(interval)

    def _save_current_stats(self):
        """Save current network statistics to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.storage_dir / f"network_stats_{timestamp}.json"

        with self.lock:
            # Convert defaultdict to regular dict for JSON serialization
            stats_dict = {
                ip: {
                    'packet_count': data['packet_count'],
                    'byte_count': data['byte_count'],
                    'ports': dict(data['ports']),
                    'protocols': dict(data['protocols'])
                }
                for ip, data in self.packet_stats.items()
            }

        with open(filename, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'stats': stats_dict
            }, f, indent=2)

    def get_current_stats(self) -> Dict:
        """Get current network statistics."""
        with self.lock:
            return dict(self.packet_stats)

    def detect_anomalies(self) -> List[Dict]:
        """Detect network anomalies based on current statistics."""
        anomalies = []
        with self.lock:
            for ip, stats in self.packet_stats.items():
                # Check for high packet counts
                if stats['packet_count'] > 10000:  # Threshold can be adjusted
                    anomalies.append({
                        'type': 'high_traffic',
                        'ip': ip,
                        'packet_count': stats['packet_count'],
                        'timestamp': datetime.now().isoformat()
                    })
                
                # Check for port scanning
                if len(stats['ports']) > 100:  # Threshold can be adjusted
                    anomalies.append({
                        'type': 'port_scan',
                        'ip': ip,
                        'ports_accessed': len(stats['ports']),
                        'timestamp': datetime.now().isoformat()
                    })

        return anomalies


if __name__ == "__main__":
    monitor = NetworkMonitor()
    try:
        monitor.start_monitoring()
        # Keep the main thread running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop_monitoring() 