"""Tests for AI Security Agent."""

import unittest
from datetime import datetime
from agis_defence.agents.ai_agent import AISecurityAgent

class TestAISecurityAgent(unittest.TestCase):
    def setUp(self):
        """Set up test environment."""
        self.agent = AISecurityAgent()

    def test_threat_response_sequence(self):
        """Test that agent heals on first attack and blocks on subsequent attacks."""
        # Simulate a threat
        test_threat = {
            'type': 'brute_force',
            'source': '192.168.1.100',
            'severity': 'high',
            'timestamp': datetime.now().isoformat(),
            'details': 'Suspicious login attempts detected'
        }
        
        # First attack should trigger heal
        response1 = self.agent.handle_threat(test_threat)
        self.assertTrue(response1['success'])
        self.assertEqual(response1['action'], 'heal')
        
        # Second attack should trigger block
        response2 = self.agent.handle_threat(test_threat)
        self.assertTrue(response2['success'])
        self.assertEqual(response2['action'], 'block')
        
        # Verify attack history
        threat_key = f"{test_threat['type']}:{test_threat['source']}"
        history = self.agent.attack_history[threat_key]
        self.assertEqual(history['count'], 2)
        self.assertEqual(len(history['actions_taken']), 2)
        self.assertEqual(history['actions_taken'][0]['action'], 'heal')
        self.assertEqual(history['actions_taken'][1]['action'], 'block')

    def test_system_analysis_updates(self):
        """Test that system analysis updates correctly with threats."""
        # Initial state
        initial_analysis = self.agent.analyze_system_state()
        self.assertEqual(initial_analysis['threat_level'], 'low')
        
        # Add threat to threat detector
        test_threat = {
            'type': 'malware',
            'source': '192.168.1.101',
            'severity': 'critical',
            'timestamp': datetime.now().isoformat(),
            'details': 'Malware detected'
        }
        self.agent.threat_detector.add_threat(test_threat)
        
        # Handle threat and check analysis updates
        response = self.agent.handle_threat(test_threat)
        self.assertTrue(response['success'])
        
        # Get updated analysis
        updated_analysis = self.agent.analyze_system_state()
        
        # Verify analysis updates
        self.assertEqual(len(updated_analysis['recent_actions']), 1)
        self.assertEqual(updated_analysis['recent_actions'][0]['threat_type'], 'malware')
        self.assertIn('malware', updated_analysis['threat_distribution'])

    def test_real_time_updates(self):
        """Test that dashboard data updates in real-time."""
        # Initial state
        initial_state = self.agent.analyze_system_state()
        
        # Simulate multiple threats
        threats = [
            {
                'type': 'sql_injection',
                'source': '192.168.1.102',
                'severity': 'high',
                'timestamp': datetime.now().isoformat(),
                'details': 'SQL injection attempt'
            },
            {
                'type': 'sql_injection',
                'source': '192.168.1.102',
                'severity': 'high',
                'timestamp': datetime.now().isoformat(),
                'details': 'SQL injection attempt'
            }
        ]
        
        # Add threats to threat detector
        for threat in threats:
            self.agent.threat_detector.add_threat(threat)
        
        # Process threats
        for threat in threats:
            response = self.agent.handle_threat(threat)
            self.assertTrue(response['success'])
        
        # Get final state
        final_state = self.agent.analyze_system_state()
        
        # Verify real-time updates
        self.assertEqual(len(final_state['recent_actions']), 2)
        self.assertEqual(final_state['blocked_attacks'], 1)  # Second attack should be blocked
        self.assertIn('sql_injection', final_state['threat_distribution'])

if __name__ == '__main__':
    unittest.main() 