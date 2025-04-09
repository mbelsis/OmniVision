from os import getenv

# API Configuration
# Default API keys are provided for testing but should be replaced in production
SHODAN_API_KEY = getenv('SHODAN_API_KEY', 'Your_API_Key')
ABUSEIPDB_API_KEY = getenv('ABUSEIPDB_API_KEY', 'Your_API_Key')
OTX_API_KEY = getenv('OTX_API_KEY', 'Your_API_Key

# Censys API Configuration - Set to empty strings by default
# The script will handle missing credentials gracefully
CENSYS_API_ID = getenv('CENSYS_API_ID', '')
CENSYS_API_SECRET = getenv('CENSYS_API_SECRET', '')

# Scan Configuration
# Modified NMAP args to be less aggressive and faster
NMAP_SCAN_ARGS = ['-Pn', '-sV', '--script=ssl-enum-ciphers']
REQUEST_TIMEOUT = 15  # Reduced timeout
RETRY_ATTEMPTS = 2    # Reduced retry attempts
RETRY_DELAY = 3       # Reduced retry delay

# Risk Scoring
RISK_WEIGHTS = {
    # SSL and Certificate Issues
    'ssl_expired': 25,
    'weak_ciphers': 15,
    
    # Service and Vulnerability Issues
    'exposed_services': 20,
    'known_vulnerabilities': 25,
    'abuse_reports': 15,
    
    # DNS Security Issues
    'dns_security': {
        'no_spf': 20,
        'no_dmarc': 20,
        'weak_spf': 15,
        'weak_dmarc': 15,
        'single_nameserver': 10
    },
    
    # Cloud Exposure Issues
    'cloud_exposure': {
        'public_storage': 25,
        'public_repos': 15
    },
    
    # Certificate Issues
    'certificate_issues': {
        'suspicious_cert': 20,
        'multiple_recent_certs': 15,
        'non_production_cert': 10
    },
    
    # Censys Findings
    'censys': {
        'outdated_software': 20,
        'insecure_protocols': 15,
        'weak_tls': 15,
        'exposed_critical_ports': 25
    }
}

# Service Definitions
CRITICAL_SERVICES = {
    22: 'SSH',
    3389: 'RDP',
    445: 'SMB',
    3306: 'MySQL',
    1433: 'MSSQL',
    27017: 'MongoDB'
}
