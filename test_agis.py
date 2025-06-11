import requests
import time
import random
import json
from datetime import datetime
import logging
import threading
import queue
import signal
import sys
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# API Configuration
API_BASE_URL = 'http://localhost:5000'
ATTACK_TYPES = [
    {
        'type': 'sql_injection',
        'severity': 'critical',
        'description': 'SQL injection attempt detected',
        'source': '192.168.1.100'
    },
    {
        'type': 'xss',
        'severity': 'high',
        'description': 'Cross-site scripting attack detected',
        'source': '192.168.1.101'
    },
    {
        'type': 'ddos',
        'severity': 'critical',
        'description': 'DDoS attack detected',
        'source': '192.168.1.102'
    },
    {
        'type': 'brute_force',
        'severity': 'high',
        'description': 'Brute force login attempt detected',
        'source': '192.168.1.103'
    },
    {
        'type': 'ransomware',
        'severity': 'critical',
        'description': 'Ransomware activity detected',
        'source': '192.168.1.104'
    }
]

class AGISTester:
    def __init__(self):
        self.stop_event = threading.Event()
        self.attack_queue = queue.Queue()
        self.attack_history = {}
        self.test_results = {
            'escalation_tests': [],
            'learning_tests': [],
            'pattern_tests': [],
            'response_tests': []
        }
        
    def send_attack(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send simulated attack to the system."""
        try:
            url = f"{API_BASE_URL}/api/threat/analyze"
            attack_data['timestamp'] = datetime.now().isoformat()
            
            # Add to attack history
            attack_key = f"{attack_data['type']}:{attack_data['source']}"
            if attack_key not in self.attack_history:
                self.attack_history[attack_key] = []
            self.attack_history[attack_key].append(attack_data)
            
            response = requests.post(url, json={'threats': [attack_data]})
            if response.status_code == 200:
                logger.info(f"Attack sent: {attack_data['type']} from {attack_data['source']}")
                return response.json()
            else:
                logger.error(f"Failed to send attack: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error sending attack: {str(e)}")
            return None

    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status."""
        try:
            response = requests.get(f"{API_BASE_URL}/api/system/status")
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Error getting system status: {str(e)}")
            return None

    def test_attack_escalation(self):
        """Test AI response to escalating attacks"""
        logger.info("Starting attack escalation test...")
        
        # Send sequence of increasingly severe attacks
        attacks = [
            {
                'type': 'port_scan',
                'severity': 'low',
                'description': 'Port scan detected',
                'source': '192.168.1.100'
            },
            {
                'type': 'brute_force',
                'severity': 'medium',
                'description': 'Brute force attempt detected',
                'source': '192.168.1.100'
            },
            {
                'type': 'sql_injection',
                'severity': 'critical',
                'description': 'SQL injection attempt detected',
                'source': '192.168.1.100'
            }
        ]
        
        results = []
        for attack in attacks:
            response = self.send_attack(attack)
            if response:
                status = self.get_system_status()
                results.append({
                    'attack': attack,
                    'ai_response': response,
                    'system_status': status
                })
            time.sleep(2)
        
        self.test_results['escalation_tests'].append(results)
        logger.info("Attack escalation test completed")

    def test_repeated_attacks(self):
        """Test AI learning from repeated attacks"""
        logger.info("Starting AI learning test...")
        
        attack = {
            'type': 'brute_force',
            'severity': 'high',
            'description': 'Brute force login attempt detected',
            'source': '192.168.1.103'
        }
        
        results = []
        for i in range(3):
            response = self.send_attack(attack)
            if response:
                status = self.get_system_status()
                results.append({
                    'iteration': i + 1,
                    'ai_response': response,
                    'system_status': status
                })
            time.sleep(2)
        
        self.test_results['learning_tests'].append(results)
        logger.info("AI learning test completed")

    def test_attack_patterns(self):
        """Test AI detection of attack patterns"""
        logger.info("Starting attack pattern detection test...")
        
        # Simulate distributed attack
        sources = ['192.168.1.101', '192.168.1.102', '192.168.1.103']
        results = []
        
        for source in sources:
            attack = {
                'type': 'ddos',
                'severity': 'high',
                'description': 'DDoS attack detected',
                'source': source
            }
            response = self.send_attack(attack)
            if response:
                status = self.get_system_status()
                results.append({
                    'source': source,
                    'ai_response': response,
                    'system_status': status
                })
            time.sleep(1)
        
        self.test_results['pattern_tests'].append(results)
        logger.info("Attack pattern detection test completed")

    def validate_ai_response(self, response: Dict[str, Any]) -> bool:
        """Validate AI response structure and content"""
        try:
            # Basic structure validation
            required_fields = ['confidence', 'recommendations', 'timestamp']
            for field in required_fields:
                if field not in response:
                    logger.error(f"Missing required field: {field}")
                    return False

            # Validate confidence
            if not isinstance(response['confidence'], (int, float)):
                logger.error("Invalid confidence value type")
                return False
            if not 0 <= response['confidence'] <= 100:
                logger.error("Confidence value out of range")
                return False

            # Validate recommendations
            if not isinstance(response['recommendations'], list):
                logger.error("Invalid recommendations format")
                return False
            if len(response['recommendations']) == 0:
                logger.error("Empty recommendations")
                return False

            return True
        except Exception as e:
            logger.error(f"Error validating AI response: {str(e)}")
            return False

    def test_system_response(self):
        """Test system-wide response to AI decisions"""
        logger.info("Starting system response test...")
        
        # Send critical attack
        attack = {
            'type': 'ransomware',
            'severity': 'critical',
            'description': 'Ransomware activity detected',
            'source': '192.168.1.104'
        }
        
        initial_status = self.get_system_status()
        response = self.send_attack(attack)
        time.sleep(2)
        final_status = self.get_system_status()
        
        if response and initial_status and final_status:
            result = {
                'attack': attack,
                'ai_response': response,
                'initial_status': initial_status,
                'final_status': final_status,
                'validation': self.validate_ai_response(response)
            }
            self.test_results['response_tests'].append(result)
        
        logger.info("System response test completed")

    def run_all_tests(self):
        """Run all AI agent tests"""
        try:
            logger.info("Starting comprehensive AI agent testing...")
            
            # Run all test scenarios
            self.test_attack_escalation()
            time.sleep(3)
            
            self.test_repeated_attacks()
            time.sleep(3)
            
            self.test_attack_patterns()
            time.sleep(3)
            
            self.test_system_response()
            
            # Log test summary
            logger.info("AI Agent Test Summary:")
            for test_type, results in self.test_results.items():
                logger.info(f"{test_type}: {len(results)} test(s) completed")
            
            return self.test_results
            
        except Exception as e:
            logger.error(f"Error during AI agent testing: {str(e)}")
            return None

    def simulate_attacks(self):
        """Continuously simulate random attacks."""
        while not self.stop_event.is_set():
            try:
                # Select random attack
                attack = random.choice(ATTACK_TYPES).copy()
                
                # Send attack
                if self.send_attack(attack):
                    # Add to queue for verification
                    self.attack_queue.put(attack)
                
                # Random delay between attacks
                time.sleep(random.uniform(2, 5))
            except Exception as e:
                logger.error(f"Error in attack simulation: {str(e)}")
                time.sleep(1)
    
    def verify_system_response(self):
        """Verify system's response to attacks."""
        while not self.stop_event.is_set():
            try:
                # Get system status
                status = self.get_system_status()
                if status:
                    # Log current state
                    logger.info("Current System State:")
                    logger.info(f"- Active Threats: {status['threats']['active_threats']}")
                    logger.info(f"- Blocked Attacks: {status['threats']['blocked_attacks']}")
                    logger.info(f"- Threat Level: {status['threats']['threat_level']}")
                    logger.info(f"- System Status: {status['system']['status']}")
                    logger.info(f"- Network Status: {status['network']['status']}")
                    logger.info(f"- Active Connections: {status['network']['active_connections']}")
                
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error verifying system response: {str(e)}")
                time.sleep(1)
    
    def monitor_system_health(self):
        """Monitor overall system health."""
        while not self.stop_event.is_set():
            try:
                status = self.get_system_status()
                if status:
                    logger.info(f"System Health - CPU: {status['system']['cpu_usage']}%, Memory: {status['system']['memory_usage']}%, Disk: {status['system']['disk_usage']}%")
                time.sleep(3)
            except Exception as e:
                logger.error(f"Error monitoring system health: {str(e)}")
                time.sleep(1)
    
    def run(self):
        """Run the test suite."""
        try:
            # First run comprehensive AI agent tests
            test_results = self.run_all_tests()
            
            # Then start continuous monitoring
            attack_thread = threading.Thread(target=self.simulate_attacks)
            attack_thread.daemon = True
            attack_thread.start()
            
            verify_thread = threading.Thread(target=self.verify_system_response)
            verify_thread.daemon = True
            verify_thread.start()
            
            health_thread = threading.Thread(target=self.monitor_system_health)
            health_thread.daemon = True
            health_thread.start()
            
            # Wait for interrupt
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Stopping test suite...")
            self.stop_event.set()
            time.sleep(2)  # Allow threads to clean up
            sys.exit(0)

if __name__ == '__main__':
    # Check if API is available
    try:
        response = requests.get(f"{API_BASE_URL}/api/system/status")
        if response.status_code != 200:
            logger.error("AGIS Defence System is not running")
            sys.exit(1)
        logger.info("AGIS Defence System is running")
        tester = AGISTester()
        tester.run()
    except Exception as e:
        logger.error(f"Failed to connect to AGIS Defence System: {str(e)}")
        sys.exit(1) 