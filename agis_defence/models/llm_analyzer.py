import openai
import os
import json
import logging
from typing import Dict, List, Optional, Union
from datetime import datetime
from pathlib import Path

from ..config import LLM_CONFIG

logger = logging.getLogger(__name__)

class LLMAnalyzer:
    """LLM-based threat analysis and explanation system."""

    def __init__(self):
        self.api_key = os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            logger.warning("OpenAI API key not found. LLM features will be disabled.")
        else:
            openai.api_key = self.api_key

        self.model = LLM_CONFIG['model_name']
        self.temperature = LLM_CONFIG['temperature']
        self.max_tokens = LLM_CONFIG['max_tokens']

    def analyze_threat(self, data: Dict) -> Dict:
        """Analyze threat data using LLM."""
        if not self.api_key:
            return {"error": "OpenAI API key not configured"}

        try:
            # Prepare the prompt
            prompt = self._create_threat_analysis_prompt(data)
            
            # Get LLM response
            response = self._get_completion(prompt)
            
            # Parse and structure the response
            analysis = self._parse_threat_analysis(response)
            
            return analysis

        except Exception as e:
            logger.error(f"Error in threat analysis: {str(e)}")
            return {"error": str(e)}

    def explain_anomaly(self, anomaly_data: Dict) -> str:
        """Generate human-readable explanation for an anomaly."""
        if not self.api_key:
            return "LLM explanation not available (API key not configured)"

        try:
            prompt = self._create_anomaly_explanation_prompt(anomaly_data)
            explanation = self._get_completion(prompt)
            return explanation.strip()

        except Exception as e:
            logger.error(f"Error generating anomaly explanation: {str(e)}")
            return f"Error generating explanation: {str(e)}"

    def suggest_mitigation(self, threat_data: Dict) -> List[str]:
        """Suggest mitigation steps for a detected threat."""
        if not self.api_key:
            return ["LLM mitigation suggestions not available (API key not configured)"]

        try:
            prompt = self._create_mitigation_prompt(threat_data)
            response = self._get_completion(prompt)
            
            # Parse the response into a list of steps
            steps = [step.strip() for step in response.split('\n') if step.strip()]
            return steps

        except Exception as e:
            logger.error(f"Error generating mitigation suggestions: {str(e)}")
            return [f"Error generating suggestions: {str(e)}"]

    def _get_completion(self, prompt: str) -> str:
        """Get completion from OpenAI API."""
        try:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing system logs and network traffic for potential threats."},
                    {"role": "user", "content": prompt}
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                timeout=LLM_CONFIG['request_timeout']
            )
            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"Error in OpenAI API call: {str(e)}")
            raise

    def _create_threat_analysis_prompt(self, data: Dict) -> str:
        """Create a prompt for threat analysis."""
        return f"""
Analyze the following security event data for potential threats:

Event Data:
{json.dumps(data, indent=2)}

Please provide a detailed analysis including:
1. Threat Classification
2. Severity Level (Low/Medium/High/Critical)
3. Potential Impact
4. Confidence Score
5. Recommended Actions

Format your response as a structured analysis.
"""

    def _create_anomaly_explanation_prompt(self, data: Dict) -> str:
        """Create a prompt for anomaly explanation."""
        return f"""
Explain the following anomaly in simple, human-readable terms:

Anomaly Data:
{json.dumps(data, indent=2)}

Provide a clear, concise explanation of:
1. What is unusual about this behavior
2. Why it might be concerning
3. What it could indicate
"""

    def _create_mitigation_prompt(self, data: Dict) -> str:
        """Create a prompt for mitigation suggestions."""
        return f"""
Suggest specific mitigation steps for the following security threat:

Threat Data:
{json.dumps(data, indent=2)}

Provide a numbered list of concrete actions to:
1. Contain the threat
2. Prevent further damage
3. Strengthen defenses
"""

    def _parse_threat_analysis(self, response: str) -> Dict:
        """Parse the LLM response into a structured format."""
        try:
            # Basic structure for the analysis
            analysis = {
                'timestamp': datetime.now().isoformat(),
                'classification': None,
                'severity': None,
                'impact': None,
                'confidence': None,
                'recommendations': [],
                'raw_analysis': response
            }

            # Extract information from the response
            # This is a simple implementation - could be made more robust
            lines = response.split('\n')
            for line in lines:
                line = line.strip().lower()
                if 'severity' in line:
                    for level in ['low', 'medium', 'high', 'critical']:
                        if level in line:
                            analysis['severity'] = level.upper()
                elif 'confidence' in line and '%' in line:
                    analysis['confidence'] = float(line.split('%')[0].split()[-1])
                elif 'recommend' in line or 'action' in line:
                    analysis['recommendations'].append(line)

            return analysis

        except Exception as e:
            logger.error(f"Error parsing threat analysis: {str(e)}")
            return {
                'error': str(e),
                'raw_analysis': response
            }


if __name__ == "__main__":
    # Example usage
    analyzer = LLMAnalyzer()
    
    # Example threat data
    sample_data = {
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.5',
        'port': 22,
        'protocol': 'TCP',
        'packet_count': 1000,
        'timestamp': '2024-01-20T15:30:00',
        'event_type': 'repeated_login_attempts'
    }
    
    # Get analysis
    analysis = analyzer.analyze_threat(sample_data)
    print("Threat Analysis:")
    print(json.dumps(analysis, indent=2))
    
    # Get explanation
    explanation = analyzer.explain_anomaly(sample_data)
    print("\nAnomaly Explanation:")
    print(explanation)
    
    # Get mitigation steps
    steps = analyzer.suggest_mitigation(sample_data)
    print("\nMitigation Steps:")
    for i, step in enumerate(steps, 1):
        print(f"{i}. {step}") 