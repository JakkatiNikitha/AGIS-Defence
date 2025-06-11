from typing import Dict, List, Any
from datetime import datetime
import collections

class HistoricalData:
    def __init__(self):
        """Initialize historical data storage."""
        self.data = {
            'threats': collections.deque(maxlen=1000),  # Store last 1000 threats
            'actions': collections.deque(maxlen=100),   # Store last 100 actions
            'recommendations': collections.deque(maxlen=50),  # Store last 50 recommendations
            'vulnerabilities': collections.deque(maxlen=50),  # Store last 50 vulnerabilities
            'system_metrics': collections.deque(maxlen=1440),  # Store 24 hours of metrics (1 per minute)
            'network_stats': collections.deque(maxlen=1440),   # Store 24 hours of network stats
            'ai_analysis': collections.deque(maxlen=100)       # Store last 100 AI analyses
        }
        
    def add_threat(self, threat: Dict[str, Any]) -> None:
        """Add a threat to historical data."""
        if not isinstance(threat, dict):
            return
            
        threat_data = {
            'timestamp': datetime.now().isoformat(),
            'data': threat
        }
        self.data['threats'].append(threat_data)
        
    def add_action(self, action: Dict[str, Any]) -> None:
        """Add an action to historical data."""
        if not isinstance(action, dict):
            return
            
        action_data = {
            'timestamp': datetime.now().isoformat(),
            'data': action
        }
        self.data['actions'].append(action_data)
        
    def add_recommendation(self, recommendation: Dict[str, Any]) -> None:
        """Add a recommendation to historical data."""
        if not isinstance(recommendation, dict):
            return
            
        rec_data = {
            'timestamp': datetime.now().isoformat(),
            'data': recommendation
        }
        self.data['recommendations'].append(rec_data)
        
    def add_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """Add a vulnerability to historical data."""
        if not isinstance(vulnerability, dict):
            return
            
        vuln_data = {
            'timestamp': datetime.now().isoformat(),
            'data': vulnerability
        }
        self.data['vulnerabilities'].append(vuln_data)
        
    def add_system_metrics(self, metrics: Dict[str, Any]) -> None:
        """Add system metrics to historical data."""
        if not isinstance(metrics, dict):
            return
            
        metrics_data = {
            'timestamp': datetime.now().isoformat(),
            'data': metrics
        }
        self.data['system_metrics'].append(metrics_data)
        
    def add_network_stats(self, stats: Dict[str, Any]) -> None:
        """Add network stats to historical data."""
        if not isinstance(stats, dict):
            return
            
        stats_data = {
            'timestamp': datetime.now().isoformat(),
            'data': stats
        }
        self.data['network_stats'].append(stats_data)
        
    def add_ai_analysis(self, analysis: Dict[str, Any]) -> None:
        """Add AI analysis to historical data."""
        if not isinstance(analysis, dict):
            return
            
        analysis_data = {
            'timestamp': datetime.now().isoformat(),
            'data': analysis
        }
        self.data['ai_analysis'].append(analysis_data)
        
    def get_recent_threats(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most recent threats."""
        threats = list(self.data['threats'])[-limit:]
        return [t['data'] for t in threats]
        
    def get_recent_actions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most recent actions."""
        actions = list(self.data['actions'])[-limit:]
        return [a['data'] for a in actions]
        
    def get_recent_recommendations(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most recent recommendations."""
        recs = list(self.data['recommendations'])[-limit:]
        return [r['data'] for r in recs]
        
    def get_recent_vulnerabilities(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most recent vulnerabilities."""
        vulns = list(self.data['vulnerabilities'])[-limit:]
        return [v['data'] for v in vulns]
        
    def get_recent_metrics(self, limit: int = 60) -> List[Dict[str, Any]]:
        """Get recent system metrics (default last hour)."""
        metrics = list(self.data['system_metrics'])[-limit:]
        return [m['data'] for m in metrics]
        
    def get_recent_network_stats(self, limit: int = 60) -> List[Dict[str, Any]]:
        """Get recent network stats (default last hour)."""
        stats = list(self.data['network_stats'])[-limit:]
        return [s['data'] for s in stats]
        
    def get_recent_ai_analysis(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent AI analysis results."""
        analysis = list(self.data['ai_analysis'])[-limit:]
        return [a['data'] for a in analysis] 