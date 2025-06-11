import os
from pathlib import Path
from typing import Dict, Any

# Base directory for all data storage
BASE_DIR = Path(os.getenv('AGIS_BASE_DIR', 'data'))

# Network monitoring settings
NETWORK_CONFIG = {
    'packet_capture_interval': 0.1,  # seconds
    'stats_save_interval': 300,  # 5 minutes
    'anomaly_thresholds': {
        'high_traffic_packets': 10000,
        'port_scan_threshold': 100,
        'connection_rate': 1000,  # connections per minute
        'bandwidth_threshold': 1000000,  # bytes per second
    }
}

# Log collection settings
LOG_CONFIG = {
    'collection_interval': 60,  # seconds
    'max_log_size': 1024 * 1024 * 100,  # 100MB
    'rotation_count': 5,
    'log_patterns': {
        'ssh_failure': r'Failed password for .* from .* port \d+',
        'sudo_attempt': r'sudo:.* USER=.* COMMAND=.*',
        'file_change': r'(CREATED|MODIFIED|DELETED) .*',
    }
}

# Machine Learning settings
ML_CONFIG = {
    'model_update_interval': 3600,  # 1 hour
    'training_data_limit': 1000000,  # number of samples
    'anomaly_detection': {
        'isolation_forest': {
            'n_estimators': 100,
            'contamination': 'auto',
            'max_samples': 'auto',
        },
        'one_class_svm': {
            'kernel': 'rbf',
            'nu': 0.1,
        }
    }
}

# LLM settings
LLM_CONFIG = {
    'model_name': 'gpt-3.5-turbo',
    'temperature': 0.3,
    'max_tokens': 500,
    'request_timeout': 30,
}

# Firewall settings
FIREWALL_CONFIG = {
    'default_policy': 'DROP',
    'allowed_ports': [80, 443, 22],  # HTTP, HTTPS, SSH
    'rate_limits': {
        'ssh': 5,  # connections per minute
        'http': 1000,  # requests per minute
        'default': 100,  # default rate limit
    }
}

# Alert settings
ALERT_CONFIG = {
    'email': {
        'enabled': True,
        'smtp_server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
        'smtp_port': int(os.getenv('SMTP_PORT', '587')),
        'sender_email': os.getenv('ALERT_EMAIL'),
        'recipient_email': os.getenv('ADMIN_EMAIL'),
    },
    'webhook': {
        'enabled': False,
        'url': os.getenv('WEBHOOK_URL'),
        'headers': {},
    }
}

# Self-healing settings
HEALING_CONFIG = {
    'max_attempts': 3,
    'cooldown_period': 300,  # 5 minutes
    'actions': {
        'restart_service': True,
        'block_ip': True,
        'rollback_changes': True,
        'isolate_system': False,  # requires admin approval
    }
}

ATTACK_TYPES = {
    'NETWORK': {
        'category': 'Network Attacks',
        'types': [
            {'id': 'ddos', 'name': 'DDoS Attack', 'description': 'Distributed Denial of Service attacks'},
            {'id': 'syn_flood', 'name': 'SYN Flood', 'description': 'TCP SYN flooding attack'},
            {'id': 'port_scan', 'name': 'Port Scan', 'description': 'Port scanning attempts'},
            {'id': 'arp_spoof', 'name': 'ARP Spoofing', 'description': 'Address Resolution Protocol spoofing'}
        ]
    },
    'INTRUSION': {
        'category': 'Intrusion Attempts',
        'types': [
            {'id': 'brute_force', 'name': 'Brute Force', 'description': 'Password brute force attempts'},
            {'id': 'ssh_attack', 'name': 'SSH Attack', 'description': 'SSH-based attacks'},
            {'id': 'rdp_attack', 'name': 'RDP Attack', 'description': 'Remote Desktop Protocol attacks'},
            {'id': 'credential_stuff', 'name': 'Credential Stuffing', 'description': 'Automated credential testing'}
        ]
    },
    'MALWARE': {
        'category': 'Malware Threats',
        'types': [
            {'id': 'ransomware', 'name': 'Ransomware', 'description': 'Ransomware activity detection'},
            {'id': 'trojan', 'name': 'Trojan', 'description': 'Trojan horse malware'},
            {'id': 'fileless_malware', 'name': 'Fileless Malware', 'description': 'Memory-based malware'},
            {'id': 'cryptominer', 'name': 'Cryptominer', 'description': 'Cryptocurrency mining malware'}
        ]
    },
    'WEB': {
        'category': 'Web Attacks',
        'types': [
            {'id': 'sql_injection', 'name': 'SQL Injection', 'description': 'SQL injection attempts'},
            {'id': 'xss', 'name': 'XSS', 'description': 'Cross-site scripting attacks'},
            {'id': 'csrf', 'name': 'CSRF', 'description': 'Cross-site request forgery'},
            {'id': 'rce', 'name': 'RCE', 'description': 'Remote code execution attempts'}
        ]
    },
    'INSIDER': {
        'category': 'Insider Threats',
        'types': [
            {'id': 'data_exfil', 'name': 'Data Exfiltration', 'description': 'Unauthorized data transfer'},
            {'id': 'priv_escalation', 'name': 'Privilege Escalation', 'description': 'Unauthorized privilege increase'},
            {'id': 'policy_violation', 'name': 'Policy Violation', 'description': 'Security policy violations'}
        ]
    },
    'ADVANCED': {
        'category': 'Advanced Threats',
        'types': [
            {'id': 'apt', 'name': 'APT', 'description': 'Advanced Persistent Threat activity'},
            {'id': 'zero_day', 'name': 'Zero-day Exploit', 'description': 'Unknown vulnerability exploitation'},
            {'id': 'supply_chain', 'name': 'Supply Chain', 'description': 'Supply chain attack attempts'}
        ]
    }
}

def get_config() -> Dict[str, Any]:
    """Get the complete configuration dictionary."""
    return {
        'base_dir': BASE_DIR,
        'network': NETWORK_CONFIG,
        'logs': LOG_CONFIG,
        'ml': ML_CONFIG,
        'llm': LLM_CONFIG,
        'firewall': FIREWALL_CONFIG,
        'alerts': ALERT_CONFIG,
        'healing': HEALING_CONFIG,
    }

def update_config(new_config: Dict[str, Any]) -> None:
    """Update configuration with new values."""
    config = get_config()
    
    def deep_update(d: Dict[str, Any], u: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                d[k] = deep_update(d[k], v)
            else:
                d[k] = v
        return d
    
    deep_update(config, new_config)
    
    # Update global variables
    globals().update(config)

# Environment-specific configurations
if os.getenv('AGIS_ENV') == 'production':
    update_config({
        'network': {
            'stats_save_interval': 600,  # 10 minutes in production
        },
        'healing': {
            'max_attempts': 5,  # More attempts in production
        }
    }) 