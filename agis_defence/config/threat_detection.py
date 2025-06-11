"""Configuration for threat detection thresholds."""

# System monitoring thresholds
SYSTEM_THRESHOLDS = {
    'cpu_usage': 90,  # CPU usage percentage threshold
    'memory_usage': 85,  # Memory usage percentage threshold
    'disk_usage': 90,  # Disk usage percentage threshold
    'process_count': 200,  # Maximum number of processes
    'file_changes': 100  # Maximum file changes per minute
}

# Network-based attack patterns
NETWORK_THRESHOLDS = {
    'connection_rate': 100,  # Connections per minute from single IP
    'connections_per_second': 20,  # Max connections per second per IP
    'packet_rate': 1000,  # Maximum packets per second
    'bandwidth_usage': 80,  # Percentage of bandwidth usage
    'suspicious_ports': [22, 23, 3389, 445, 135, 137, 138, 139],  # Common attack ports
    'max_failed_logins': 5  # Maximum failed login attempts
}

# Authentication and access patterns
AUTH_THRESHOLDS = {
    'failed_login_attempts': 5,  # Max failed logins before blocking
    'password_attempts': 3,  # Max password attempts per account
    'session_duration': 3600,  # Maximum session duration in seconds
    'concurrent_sessions': 3,  # Maximum concurrent sessions per user
    'privilege_changes': 5  # Maximum privilege changes per hour
}

# File system monitoring
FILESYSTEM_THRESHOLDS = {
    'file_changes': 50,  # Maximum file changes per minute
    'sensitive_access': 10,  # Maximum sensitive file accesses per minute
    'executable_created': 5,  # Maximum new executables per hour
    'permission_changes': 10,  # Maximum permission changes per hour
    'monitored_extensions': ['.exe', '.dll', '.sys', '.bat', '.ps1', '.vbs']
}

# Web attack patterns
WEB_ATTACK_THRESHOLDS = {
    # SQL Injection patterns
    'sql_injection_patterns': [
        "UNION SELECT",
        "OR 1=1",
        "AND 1=1",
        "DROP TABLE",
        "DELETE FROM",
        "INSERT INTO",
        "EXEC xp_",
        "EXEC sp_",
        "'; exec",
        "/**/",
        "-- ",
        "#"
    ],
    
    # XSS patterns
    'xss_patterns': [
        "<script>",
        "javascript:",
        "onerror=",
        "onload=",
        "eval(",
        "alert(",
        "document.cookie",
        "document.location",
        "<img src=",
        "<iframe"
    ],
    
    # Directory traversal
    'path_traversal_patterns': [
        "../",
        "..\\",
        "%2e%2e/",
        "..;/",
        "/etc/passwd",
        "c:\\windows",
        "../../../../"
    ],
    
    # Command injection
    'command_injection_patterns': [
        "; ls",
        "& dir",
        "| whoami",
        "> /dev/null",
        "`command`",
        "$(command)",
        "%0a",
        "ping -i"
    ],
    
    # File inclusion
    'file_inclusion_patterns': [
        "php://",
        "zip://",
        "data://",
        "expect://",
        "input://",
        "filter://",
        "phar://"
    ]
}

# Malware and ransomware patterns
MALWARE_PATTERNS = {
    'ransomware_extensions': ['.encrypted', '.locked', '.crypto', '.crypt', '.xxx'],
    'suspicious_processes': ['cryptor', 'ransom', 'wcry', 'wncry'],
    'malware_behaviors': [
        'mass_file_encryption',
        'registry_persistence',
        'disable_recovery',
        'delete_backups',
        'disable_defender'
    ]
}

# Response thresholds
RESPONSE_THRESHOLDS = {
    'block_ip_threshold': 3,  # Number of threats before blocking IP
    'block_duration': 3600,  # Duration to block IP (seconds)
    'alert_threshold': 5,  # Number of events before alerting
    'scan_frequency': 300,  # Time between full system scans (seconds)
    'log_retention': 30  # Days to retain logs
}

# AI-based detection thresholds
AI_THRESHOLDS = {
    'anomaly_score': 0.8,  # Minimum anomaly score to trigger alert
    'confidence_threshold': 0.7,  # Minimum AI confidence for automated actions
    'learning_rate': 0.01,  # AI model learning rate
    'false_positive_rate': 0.01,  # Maximum acceptable false positive rate
    'detection_sensitivity': 0.85  # Overall detection sensitivity
}

# Severity weights for different types of threats
SEVERITY_WEIGHTS = {
    'critical': 1.0,
    'high': 0.8,
    'medium': 0.6,
    'low': 0.4,
    'info': 0.2
}

# Data exfiltration patterns
DATA_EXFILTRATION_PATTERNS = {
    'sensitive_data_patterns': [
        r'\b\d{16}\b',  # Credit card numbers
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email addresses
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
        r'password[s]?\s*[=:]\s*\w+',  # Passwords in clear text
    ],
    'unusual_traffic_patterns': [
        'large_file_uploads',
        'unusual_protocols',
        'encrypted_tunnels',
        'dns_tunneling'
    ],
    'max_data_transfer': 100  # MB per minute
}

# Zero-day attack detection
ZERO_DAY_PATTERNS = {
    'behavior_patterns': [
        'unknown_process_creation',
        'unusual_system_calls',
        'unexpected_network_behavior',
        'abnormal_file_operations'
    ],
    'anomaly_threshold': 0.9,
    'detection_confidence': 0.8
}

# Botnet and C&C detection
BOTNET_PATTERNS = {
    'command_patterns': [
        'periodic_beaconing',
        'synchronized_requests',
        'encoded_commands',
        'unusual_dns_queries'
    ],
    'connection_patterns': [
        'multiple_failed_connections',
        'regular_intervals',
        'known_c2_ports'
    ]
}

# Advanced Persistent Threat (APT) patterns
APT_PATTERNS = {
    'indicators': [
        'lateral_movement',
        'data_staging',
        'privilege_escalation',
        'persistence_mechanisms',
        'stealth_techniques'
    ],
    'detection_threshold': 0.85,
    'minimum_dwell_time': 3600  # seconds
} 