import subprocess
import logging
import json
from typing import Dict, List, Optional, Union
from datetime import datetime
import os
from pathlib import Path
import psutil
import time
import shutil

from ..config import HEALING_CONFIG

logger = logging.getLogger(__name__)

class SelfHealing:
    """Self-healing system for automated recovery from threats."""

    def __init__(self):
        self.config = HEALING_CONFIG
        self.history_file = Path("healing_history.json")
        self.healing_history = self._load_history()
        self.backup_dir = Path("backups")
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def _load_history(self) -> Dict:
        """Load healing action history."""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading healing history: {str(e)}")
        return {'actions': [], 'last_updated': None}

    def _save_history(self):
        """Save healing action history."""
        try:
            self.healing_history['last_updated'] = datetime.now().isoformat()
            with open(self.history_file, 'w') as f:
                json.dump(self.healing_history, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving healing history: {str(e)}")

    def _can_attempt_action(self, action_type: str) -> bool:
        """Check if an action can be attempted based on history."""
        if not self.config['actions'].get(action_type, False):
            return False

        recent_actions = [
            a for a in self.healing_history['actions']
            if a['action_type'] == action_type and
            (datetime.now() - datetime.fromisoformat(a['timestamp'])).total_seconds() < self.config['cooldown_period']
        ]

        return len(recent_actions) < self.config['max_attempts']

    def _record_action(self, action_type: str, details: Dict, success: bool):
        """Record a healing action in history."""
        action = {
            'action_type': action_type,
            'timestamp': datetime.now().isoformat(),
            'details': details,
            'success': success
        }
        self.healing_history['actions'].append(action)
        self._save_history()

    def restart_service(self, service_name: str) -> bool:
        """Restart a system service."""
        if not self._can_attempt_action('restart_service'):
            logger.warning(f"Cannot attempt to restart {service_name} - cooldown or max attempts reached")
            return False

        try:
            if os.name == 'nt':  # Windows
                cmd = f'net stop {service_name} && net start {service_name}'
            else:  # Linux
                cmd = f'systemctl restart {service_name}'

            subprocess.run(cmd, shell=True, check=True)
            
            self._record_action('restart_service', 
                              {'service': service_name}, 
                              success=True)
            logger.info(f"Successfully restarted service: {service_name}")
            return True

        except subprocess.CalledProcessError as e:
            self._record_action('restart_service', 
                              {'service': service_name, 'error': str(e)}, 
                              success=False)
            logger.error(f"Error restarting service {service_name}: {str(e)}")
            return False

    def kill_process(self, pid: int, force: bool = False) -> bool:
        """Kill a process by PID."""
        try:
            process = psutil.Process(pid)
            process_info = {
                'pid': pid,
                'name': process.name(),
                'cmdline': ' '.join(process.cmdline())
            }

            if force:
                process.kill()
            else:
                process.terminate()
                
            self._record_action('kill_process', process_info, success=True)
            logger.info(f"Successfully terminated process: {process_info}")
            return True

        except psutil.NoSuchProcess:
            logger.warning(f"Process {pid} not found")
            return False
        except Exception as e:
            self._record_action('kill_process', 
                              {'pid': pid, 'error': str(e)}, 
                              success=False)
            logger.error(f"Error killing process {pid}: {str(e)}")
            return False

    def backup_file(self, filepath: str) -> Optional[str]:
        """Create a backup of a file."""
        try:
            src_path = Path(filepath)
            if not src_path.exists():
                logger.warning(f"File not found: {filepath}")
                return None

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.backup_dir / f"{src_path.name}_{timestamp}"
            
            shutil.copy2(src_path, backup_path)
            
            self._record_action('backup_file', 
                              {'source': str(src_path), 
                               'backup': str(backup_path)}, 
                              success=True)
            logger.info(f"Created backup: {backup_path}")
            return str(backup_path)

        except Exception as e:
            self._record_action('backup_file', 
                              {'source': filepath, 'error': str(e)}, 
                              success=False)
            logger.error(f"Error backing up file {filepath}: {str(e)}")
            return None

    def restore_file(self, original_path: str, backup_path: str) -> bool:
        """Restore a file from backup."""
        try:
            if not Path(backup_path).exists():
                logger.warning(f"Backup not found: {backup_path}")
                return False

            shutil.copy2(backup_path, original_path)
            
            self._record_action('restore_file', 
                              {'source': backup_path, 
                               'destination': original_path}, 
                              success=True)
            logger.info(f"Restored file from backup: {original_path}")
            return True

        except Exception as e:
            self._record_action('restore_file', 
                              {'source': backup_path, 
                               'destination': original_path, 
                               'error': str(e)}, 
                              success=False)
            logger.error(f"Error restoring file: {str(e)}")
            return False

    def isolate_system(self) -> bool:
        """Isolate the system by restricting network access."""
        if not self._can_attempt_action('isolate_system'):
            logger.warning("Cannot attempt system isolation - cooldown or max attempts reached")
            return False

        try:
            if os.name == 'nt':  # Windows
                # Enable Windows Firewall and block all incoming/outgoing traffic
                cmds = [
                    'netsh advfirewall set allprofiles state on',
                    'netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound'
                ]
            else:  # Linux
                # Drop all incoming/outgoing traffic except established connections
                cmds = [
                    'iptables -P INPUT DROP',
                    'iptables -P OUTPUT DROP',
                    'iptables -P FORWARD DROP',
                    'iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT',
                    'iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT'
                ]

            for cmd in cmds:
                subprocess.run(cmd, shell=True, check=True)

            self._record_action('isolate_system', 
                              {'timestamp': datetime.now().isoformat()}, 
                              success=True)
            logger.warning("System has been isolated from network")
            return True

        except subprocess.CalledProcessError as e:
            self._record_action('isolate_system', 
                              {'error': str(e)}, 
                              success=False)
            logger.error(f"Error isolating system: {str(e)}")
            return False

    def handle_threat(self, threat_data: Dict) -> Dict:
        """Handle a detected threat with appropriate healing actions."""
        response = {
            'actions_taken': [],
            'success': True
        }

        try:
            # Extract threat information
            severity = threat_data.get('severity', 'LOW')
            affected_service = threat_data.get('affected_service')
            affected_process = threat_data.get('affected_process')
            affected_file = threat_data.get('affected_file')

            # Apply healing actions based on severity and affected components
            if severity in ['CRITICAL', 'HIGH']:
                if affected_service and self.restart_service(affected_service):
                    response['actions_taken'].append(f"Restarted service: {affected_service}")

                if affected_process and self.kill_process(affected_process, force=True):
                    response['actions_taken'].append(f"Terminated process: {affected_process}")

                if affected_file:
                    backup_path = self.backup_file(affected_file)
                    if backup_path:
                        response['actions_taken'].append(f"Created backup: {backup_path}")

                if severity == 'CRITICAL' and self.config['actions']['isolate_system']:
                    if self.isolate_system():
                        response['actions_taken'].append("Isolated system from network")

            elif severity == 'MEDIUM':
                if affected_service and self.restart_service(affected_service):
                    response['actions_taken'].append(f"Restarted service: {affected_service}")

                if affected_file:
                    backup_path = self.backup_file(affected_file)
                    if backup_path:
                        response['actions_taken'].append(f"Created backup: {backup_path}")

            # For LOW severity, just create backups if files are affected
            elif affected_file:
                backup_path = self.backup_file(affected_file)
                if backup_path:
                    response['actions_taken'].append(f"Created backup: {backup_path}")

            return response

        except Exception as e:
            logger.error(f"Error in threat healing: {str(e)}")
            return {'success': False, 'error': str(e)}

    def get_healing_status(self) -> Dict:
        """Get current healing system status."""
        return {
            'config': self.config,
            'history': self.healing_history,
            'last_updated': datetime.now().isoformat()
        }


if __name__ == "__main__":
    # Example usage
    healer = SelfHealing()
    
    # Example threat
    threat = {
        'severity': 'HIGH',
        'affected_service': 'httpd',
        'affected_process': 1234,
        'affected_file': '/etc/passwd'
    }
    
    # Handle threat
    result = healer.handle_threat(threat)
    print("Healing result:", json.dumps(result, indent=2))
    
    # Check status
    status = healer.get_healing_status()
    print("\nHealing status:", json.dumps(status, indent=2)) 