import os
import psutil
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LogCollector:
    """Collects and processes system logs and metrics."""
    
    def __init__(self, log_dir: str = "logs", storage_dir: str = "data"):
        self.log_dir = Path(log_dir)
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.observer = Observer()
        self.setup_log_monitoring()

    def setup_log_monitoring(self):
        """Set up log file monitoring."""
        if os.name == 'nt':  # Windows
            self.log_paths = [
                os.path.expandvars(r"%SystemRoot%\System32\Winevt\Logs")
            ]
        else:  # Linux/Unix
            self.log_paths = [
                "/var/log/syslog",
                "/var/log/auth.log",
                "/var/log/secure"
            ]

        for log_path in self.log_paths:
            if os.path.exists(log_path):
                event_handler = LogFileHandler()
                self.observer.schedule(event_handler, log_path, recursive=False)
        
        self.observer.start()

    def collect_system_metrics(self) -> Dict:
        """Collect current system metrics."""
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network': self._get_network_stats(),
            'processes': self._get_process_info()
        }
        return metrics

    def _get_network_stats(self) -> Dict:
        """Collect network statistics."""
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv
        }

    def _get_process_info(self) -> List[Dict]:
        """Collect information about running processes."""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes

    def save_metrics(self, metrics: Dict):
        """Save collected metrics to storage."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.storage_dir / f"metrics_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(metrics, f, indent=2)

    def start_collection(self, interval: int = 60):
        """Start continuous metric collection."""
        logger.info("Starting system metric collection...")
        try:
            while True:
                metrics = self.collect_system_metrics()
                self.save_metrics(metrics)
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Stopping metric collection...")
            self.observer.stop()
        self.observer.join()


class LogFileHandler(FileSystemEventHandler):
    """Handles log file events."""
    
    def on_modified(self, event):
        if event.is_directory:
            return
        logger.info(f"Log file modified: {event.src_path}")
        # Here you would implement log parsing and processing
        self._process_log_file(event.src_path)

    def _process_log_file(self, filepath: str):
        """Process modified log file."""
        try:
            with open(filepath, 'r') as f:
                # Read last few lines for processing
                last_lines = self._tail(f, 10)
                for line in last_lines:
                    self._analyze_log_line(line)
        except Exception as e:
            logger.error(f"Error processing log file {filepath}: {str(e)}")

    def _analyze_log_line(self, line: str):
        """Analyze a single log line for potential threats."""
        # TODO: Implement log analysis logic
        pass

    @staticmethod
    def _tail(file, n: int) -> List[str]:
        """Return the last n lines of a file."""
        try:
            with open(file.name, 'r') as f:
                return list(f)[-n:]
        except Exception:
            return []


if __name__ == "__main__":
    collector = LogCollector()
    collector.start_collection() 