"""System Healer Module for AGIS Defence System."""

import logging
import psutil
import subprocess
from typing import Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class SystemHealer:
    def __init__(self):
        self.healing_history = {}
        self.last_heal_time = datetime.now()
        
    def heal_system(self, threat: Dict) -> Dict:
        """Attempt to heal the system from a detected threat."""
        try:
            threat_type = threat.get('type', 'unknown')
            source = threat.get('source', 'unknown')
            
            logger.info(f"Attempting to heal system from {threat_type} threat from {source}")
            
            # Record healing attempt
            if threat_type not in self.healing_history:
                self.healing_history[threat_type] = []
            
            healing_action = {
                'timestamp': datetime.now().isoformat(),
                'threat_type': threat_type,
                'source': source,
                'action_taken': None,
                'success': False
            }
            
            # Apply healing strategy based on threat type
            if threat_type == 'brute_force':
                success = self._heal_brute_force(source)
                healing_action['action_taken'] = 'reset_connection'
                healing_action['success'] = success
                
            elif threat_type == 'high_cpu_usage':
                success = self._heal_high_cpu()
                healing_action['action_taken'] = 'optimize_processes'
                healing_action['success'] = success
                
            elif threat_type == 'high_memory_usage':
                success = self._heal_high_memory()
                healing_action['action_taken'] = 'free_memory'
                healing_action['success'] = success
                
            elif threat_type == 'suspicious_connection':
                success = self._heal_suspicious_connection(source)
                healing_action['action_taken'] = 'terminate_connection'
                healing_action['success'] = success
                
            else:
                logger.warning(f"No specific healing strategy for threat type: {threat_type}")
                healing_action['action_taken'] = 'general_protection'
                healing_action['success'] = True
            
            # Record healing action
            self.healing_history[threat_type].append(healing_action)
            self.last_heal_time = datetime.now()
            
            return {
                'success': healing_action['success'],
                'action': healing_action['action_taken'],
                'message': f"Healing attempt completed for {threat_type} threat"
            }
            
        except Exception as e:
            logger.error(f"Error in heal_system: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _heal_brute_force(self, source: str) -> bool:
        """Handle brute force attack healing."""
        try:
            # Reset connection from source
            if source != 'unknown':
                # In simulation mode, just log the action
                logger.info(f"Simulated: Resetting connections from {source}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error healing brute force attack: {str(e)}")
            return False
    
    def _heal_high_cpu(self) -> bool:
        """Handle high CPU usage healing."""
        try:
            # Find and optimize high CPU processes
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    if proc.info['cpu_percent'] > 80:
                        # In simulation mode, just log the action
                        logger.info(f"Simulated: Optimizing high CPU process: {proc.info['name']}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return True
        except Exception as e:
            logger.error(f"Error healing high CPU usage: {str(e)}")
            return False
    
    def _heal_high_memory(self) -> bool:
        """Handle high memory usage healing."""
        try:
            # Clear system cache
            if psutil.WINDOWS:
                # In simulation mode, just log the action
                logger.info("Simulated: Clearing Windows memory cache")
            else:
                # In simulation mode, just log the action
                logger.info("Simulated: Clearing Linux memory cache")
            return True
        except Exception as e:
            logger.error(f"Error healing high memory usage: {str(e)}")
            return False
    
    def _heal_suspicious_connection(self, source: str) -> bool:
        """Handle suspicious connection healing."""
        try:
            if source != 'unknown':
                # In simulation mode, just log the action
                logger.info(f"Simulated: Terminating suspicious connection from {source}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error healing suspicious connection: {str(e)}")
            return False
    
    def get_healing_stats(self) -> Dict:
        """Get statistics about healing actions."""
        stats = {
            'total_healings': sum(len(actions) for actions in self.healing_history.values()),
            'success_rate': 0,
            'last_heal_time': self.last_heal_time.isoformat(),
            'by_threat_type': {}
        }
        
        total_success = 0
        total_attempts = 0
        
        for threat_type, actions in self.healing_history.items():
            successful = len([a for a in actions if a['success']])
            total = len(actions)
            
            stats['by_threat_type'][threat_type] = {
                'total_attempts': total,
                'successful': successful,
                'success_rate': (successful / total * 100) if total > 0 else 0
            }
            
            total_success += successful
            total_attempts += total
        
        if total_attempts > 0:
            stats['success_rate'] = (total_success / total_attempts * 100)
        
        return stats 