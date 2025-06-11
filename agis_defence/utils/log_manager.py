import csv
import os
from datetime import datetime
from typing import Dict, List, Optional

class LogManager:
    def __init__(self, log_file: str = "data/system_logs.csv"):
        """Initialize the log manager with the path to the log file."""
        self.log_file = log_file
        self._ensure_log_file_exists()

    def _ensure_log_file_exists(self):
        """Create the log file and headers if it doesn't exist."""
        if not os.path.exists(os.path.dirname(self.log_file)):
            os.makedirs(os.path.dirname(self.log_file))
        
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'event_type', 'severity', 'description', 
                               'source', 'action_taken', 'status'])

    def add_log(self, event_type: str, severity: str, description: str,
                source: str, action_taken: str, status: str):
        """Add a new log entry to the CSV file."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(self.log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, event_type, severity, description,
                           source, action_taken, status])

    def get_logs(self, filters: Optional[Dict] = None) -> List[Dict]:
        """
        Retrieve logs with optional filtering.
        
        Args:
            filters (dict): Optional dictionary of column:value pairs to filter by
        
        Returns:
            List of dictionaries containing log entries
        """
        logs = []
        with open(self.log_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if filters is None:
                    logs.append(row)
                else:
                    if all(row.get(k) == v for k, v in filters.items()):
                        logs.append(row)
        return logs

    def get_recent_logs(self, limit: int = 10) -> List[Dict]:
        """Get the most recent log entries."""
        all_logs = self.get_logs()
        return all_logs[-limit:]

    def get_logs_by_severity(self, severity: str) -> List[Dict]:
        """Get all logs of a specific severity level."""
        return self.get_logs({'severity': severity})

    def get_logs_by_event_type(self, event_type: str) -> List[Dict]:
        """Get all logs of a specific event type."""
        return self.get_logs({'event_type': event_type})

# Example usage:
if __name__ == "__main__":
    logger = LogManager()
    
    # Add a test log entry
    logger.add_log(
        event_type="TEST",
        severity="INFO",
        description="Test log entry",
        source="LogManager",
        action_taken="Test logging",
        status="COMPLETED"
    )
    
    # Retrieve recent logs
    recent_logs = logger.get_recent_logs(5)
    print("Recent logs:", recent_logs) 