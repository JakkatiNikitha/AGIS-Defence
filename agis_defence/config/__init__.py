"""Configuration package for AGIS Defence System."""

# Attack type definitions
ATTACK_TYPES = {
    'network': {
        'name': 'Network Attacks',
        'types': [
            {'id': 'ddos', 'name': 'DDoS Attack'},
            {'id': 'port_scan', 'name': 'Port Scan'},
            {'id': 'brute_force', 'name': 'Brute Force'}
        ]
    },
    'web': {
        'name': 'Web Attacks',
        'types': [
            {'id': 'sql_injection', 'name': 'SQL Injection'},
            {'id': 'xss', 'name': 'Cross-Site Scripting'},
            {'id': 'csrf', 'name': 'CSRF Attack'}
        ]
    },
    'system': {
        'name': 'System Attacks',
        'types': [
            {'id': 'privilege_escalation', 'name': 'Privilege Escalation'},
            {'id': 'malware', 'name': 'Malware Detection'},
            {'id': 'rootkit', 'name': 'Rootkit Detection'}
        ]
    }
} 