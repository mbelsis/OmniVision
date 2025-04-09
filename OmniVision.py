# ╔═══════════════════════════════════════════════════════════╗
# ║                 OmniVision Recon Tool                   ║
# ║                                                        ║
# ║         __             ____                            ║
# ║        /  \__         /    \  Bee-like Multi-Eye       ║
# ║   (   ( \  /  \       ) ()  (  Network Reconnaissance  ║
# ║    \   \  \   \      (  ()  )  Tool                    ║
# ║     \___\  \___\      \____/                           ║
# ║      \___/  \___/                                      ║
# ║                                                        ║
# ╚═══════════════════════════════════════════════════════════╝

"""
OmniVision: A comprehensive network reconnaissance tool 
inspired by the multi-faceted vision of a bee.

Key Features:
- Multi-perspective network scanning
- Comprehensive vulnerability assessment
- Intelligent risk scoring
"""

#!/usr/bin/env python3
import asyncio
import logging
import socket
import subprocess
import json
import os
import sys
import csv
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union, Any, Callable
import aiohttp
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Check if SSL module is available
SSL_AVAILABLE = False
try:
    import ssl
    SSL_AVAILABLE = True
    logger.info("SSL module is available and will be used for certificate checks")
except ImportError:
    logger.warning("SSL module is not available. Certificate checks will be limited")

# Try to import optional modules with fallbacks
try:
    import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    logger.info("tqdm module not found. Basic progress reporting will be used")

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False
    logger.info("Shodan module not found. Shodan lookups will be skipped")

try:
    from OTXv2 import OTXv2, IndicatorTypes
    OTX_AVAILABLE = True
except ImportError:
    OTX_AVAILABLE = False
    logger.info("OTXv2 module not found. OTX lookups will be skipped")

# Import custom modules
try:
    from dns_checks import check_dns_security
    DNS_CHECKS_AVAILABLE = True
except ImportError:
    DNS_CHECKS_AVAILABLE = False
    logger.warning("dns_checks module not found. DNS security checks will be skipped")

try:
    from cloud_checks import check_cloud_exposure
    CLOUD_CHECKS_AVAILABLE = True
except ImportError:
    CLOUD_CHECKS_AVAILABLE = False
    logger.warning("cloud_checks module not found. Cloud exposure checks will be skipped")

try:
    from cert_checks import check_certificate_logs
    CERT_CHECKS_AVAILABLE = True
except ImportError:
    CERT_CHECKS_AVAILABLE = False
    logger.warning("cert_checks module not found. Certificate transparency checks will be skipped")

try:
    import typosquatting_fixed as typosquatting
    TYPOSQUATTING_AVAILABLE = True
except ImportError:
    try:
        import typosquatting
        TYPOSQUATTING_AVAILABLE = True
    except ImportError:
        TYPOSQUATTING_AVAILABLE = False
        logger.warning("typosquatting module not found. Typosquatting checks will be skipped")

# Default configuration values
DEFAULT_CONFIG = {
    "SHODAN_API_KEY": "",
    "ABUSEIPDB_API_KEY": "",
    "OTX_API_KEY": "",
    "CENSYS_API_ID": "",
    "CENSYS_API_SECRET": "",
    "NMAP_SCAN_ARGS": ['-Pn', '-sV', '--script=ssl-enum-ciphers'],
    "REQUEST_TIMEOUT": 15,
    "RETRY_ATTEMPTS": 2,
    "RETRY_DELAY": 3,
    "RISK_WEIGHTS": {
        "ssl_expired": 25,
        "weak_ciphers": 15,
        "exposed_services": 20,
        "known_vulnerabilities": 25,
        "abuse_reports": 15,
        "dns_security": {
            "no_spf": 20,
            "no_dmarc": 20,
            "weak_spf": 15,
            "weak_dmarc": 15,
            "single_nameserver": 10
        },
        "cloud_exposure": {
            "public_storage": 25,
            "public_repos": 15
        },
        "certificate_issues": {
            "suspicious_cert": 20,
            "multiple_recent_certs": 15,
            "non_production_cert": 10
        },
        "censys": {
            "outdated_software": 20,
            "insecure_protocols": 15,
            "weak_tls": 15,
            "exposed_critical_ports": 25
        }
    },
    "CRITICAL_SERVICES": {
        22: 'SSH',
        3389: 'RDP',
        445: 'SMB',
        3306: 'MySQL',
        1433: 'MSSQL',
        27017: 'MongoDB'
    }
}

# Try to import config from file, use defaults for missing values
try:
    # First try config_fixed.py
    try:
        from config_fixed import *
        logger.info("Using configuration from config_fixed.py")
    except ImportError:
        # Then try config.py
        try:
            from config import *
            logger.info("Using configuration from config.py")
        except ImportError:
            logger.warning("No configuration file found. Using default values")
            # Use the default config values defined above
            SHODAN_API_KEY = DEFAULT_CONFIG["SHODAN_API_KEY"]
            ABUSEIPDB_API_KEY = DEFAULT_CONFIG["ABUSEIPDB_API_KEY"]
            OTX_API_KEY = DEFAULT_CONFIG["OTX_API_KEY"]
            CENSYS_API_ID = DEFAULT_CONFIG["CENSYS_API_ID"]
            CENSYS_API_SECRET = DEFAULT_CONFIG["CENSYS_API_SECRET"]
            NMAP_SCAN_ARGS = DEFAULT_CONFIG["NMAP_SCAN_ARGS"]
            REQUEST_TIMEOUT = DEFAULT_CONFIG["REQUEST_TIMEOUT"]
            RETRY_ATTEMPTS = DEFAULT_CONFIG["RETRY_ATTEMPTS"]
            RETRY_DELAY = DEFAULT_CONFIG["RETRY_DELAY"]
            RISK_WEIGHTS = DEFAULT_CONFIG["RISK_WEIGHTS"]
            CRITICAL_SERVICES = DEFAULT_CONFIG["CRITICAL_SERVICES"]
except Exception as e:
    logger.error(f"Error loading configuration: {e}")
    logger.warning("Using default configuration values")
    # Use the default config values defined above
    SHODAN_API_KEY = DEFAULT_CONFIG["SHODAN_API_KEY"]
    ABUSEIPDB_API_KEY = DEFAULT_CONFIG["ABUSEIPDB_API_KEY"]
    OTX_API_KEY = DEFAULT_CONFIG["OTX_API_KEY"]
    CENSYS_API_ID = DEFAULT_CONFIG["CENSYS_API_ID"]
    CENSYS_API_SECRET = DEFAULT_CONFIG["CENSYS_API_SECRET"]
    NMAP_SCAN_ARGS = DEFAULT_CONFIG["NMAP_SCAN_ARGS"]
    REQUEST_TIMEOUT = DEFAULT_CONFIG["REQUEST_TIMEOUT"]
    RETRY_ATTEMPTS = DEFAULT_CONFIG["RETRY_ATTEMPTS"]
    RETRY_DELAY = DEFAULT_CONFIG["RETRY_DELAY"]
    RISK_WEIGHTS = DEFAULT_CONFIG["RISK_WEIGHTS"]
    CRITICAL_SERVICES = DEFAULT_CONFIG["CRITICAL_SERVICES"]

# Progress tracking class
class ProgressTracker:
    def __init__(self, total_steps: int, description: str = "Progress", disable: bool = False):
        self.total_steps = total_steps
        self.current_step = 0
        self.description = description
        self.start_time = time.time()
        self.disable = disable
        self.pbar = None
        
        if not self.disable:
            if TQDM_AVAILABLE:
                self.pbar = tqdm.tqdm(total=total_steps, desc=description, unit="step")
            else:
                print(f"{description}: 0/{total_steps} (0%)")
    
    def update(self, steps: int = 1, message: str = None):
        self.current_step += steps
        if not self.disable:
            if self.pbar:
                self.pbar.update(steps)
                if message:
                    self.pbar.set_description(f"{self.description}: {message}")
            else:
                percent = int((self.current_step / self.total_steps) * 100)
                print(f"{self.description}: {self.current_step}/{self.total_steps} ({percent}%){' - ' + message if message else ''}")
    
    def close(self):
        if not self.disable and self.pbar:
            self.pbar.close()
    
    def get_progress(self) -> float:
        return (self.current_step / self.total_steps) * 100 if self.total_steps > 0 else 0
    
    def get_elapsed_time(self) -> float:
        return time.time() - self.start_time
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

async def resolve_domain(domain: str) -> Optional[str]:
    try:
        # Using asyncio to run blocking DNS lookup in thread pool with timeout
        loop = asyncio.get_event_loop()
        ip = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, domain),
            timeout=5.0
        )
        logger.info(f"Resolved {domain} to {ip}")
        return ip
    except asyncio.TimeoutError:
        logger.error(f"DNS resolution timed out for {domain}")
        return None
    except socket.gaierror as e:
        logger.error(f"DNS resolution failed for {domain}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error resolving {domain}: {e}")
        return None

def is_valid_ip_or_cidr(ip_input: str) -> bool:
    """Check if the input is a valid IP address or CIDR notation."""
    try:
        ipaddress.ip_network(ip_input, strict=False)
        return True
    except ValueError:
        return False

def get_ips_from_subnet(subnet: str, max_hosts: int = 100) -> List[str]:
    """Convert a subnet in CIDR notation to a list of IP addresses."""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        # Limit the number of IPs to avoid excessive scanning
        return [str(ip) for ip in list(network.hosts())[:max_hosts]]
    except ValueError as e:
        logger.error(f"Invalid subnet format: {e}")
        return []

async def check_ssl_cert(domain: str, progress: ProgressTracker = None) -> Dict[str, Union[str, datetime, List[str]]]:
    """Check SSL certificate for a domain. Falls back to limited info if SSL module is not available."""
    if progress:
        progress.update(message=f"Checking SSL for {domain}")
    
    # If SSL is not available, return limited info
    if not SSL_AVAILABLE:
        logger.warning(f"SSL module not available. Cannot perform direct certificate checks for {domain}")
        return {'error': "SSL module not available", 'limited_check': True}
    
    try:
        context = ssl.create_default_context()
        
        # Use asyncio to handle SSL connection with timeout
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    domain, 443,
                    ssl=context,
                    server_hostname=domain
                ),
                timeout=10.0
            )
        except asyncio.TimeoutError:
            return {'error': "SSL connection timed out"}
            
        # Get the SSL object to extract certificate info
        ssl_obj = writer.get_extra_info('ssl_object')
        cert = ssl_obj.getpeercert()
        cipher = ssl_obj.cipher()
        
        # Clean up the connection
        writer.close()
        await writer.wait_closed()
        
        expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        
        return {
            'expiry_date': expiry_date,
            'issuer': dict(x[0] for x in cert['issuer']),
            'subject': dict(x[0] for x in cert['subject']),
            'version': cert['version'],
            'cipher_suite': cipher[0],
            'cipher_bits': cipher[1],
            'protocol': ssl_obj.version()
        }
    except ssl.SSLError as e:
        logger.error(f"SSL error for {domain}: {e}")
        return {'error': f"SSL error: {str(e)}"}
    except Exception as e:
        logger.error(f"Error checking SSL for {domain}: {e}")
        return {'error': f"Unexpected error: {str(e)}"}

async def run_nmap(ip: str, progress: ProgressTracker = None) -> Dict[str, Union[str, List[Dict[str, str]]]]:
    if progress:
        progress.update(message=f"Running nmap scan on {ip}")
        
    try:
        # First check if nmap is installed
        if os.name == 'nt':  # Windows
            check_cmd = 'where nmap.exe'
            nmap_executable = 'nmap.exe'
        else:  # Linux/Unix
            check_cmd = 'which nmap'
            nmap_executable = 'nmap'

        check_proc = await asyncio.create_subprocess_shell(
            check_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, _ = await check_proc.communicate()
        
        if check_proc.returncode != 0:
            logger.warning("Nmap is not installed. Skipping port scan.")
            return {
                'error': 'Nmap not installed',
                'services': [],
                'raw_output': 'Nmap scan skipped - tool not installed'
            }
        
        # If nmap is installed, proceed with scan but with timeout
        cmd = [nmap_executable] + NMAP_SCAN_ARGS + [ip]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60.0)
        except asyncio.TimeoutError:
            # Kill the process if it takes too long
            proc.kill()
            logger.warning(f"Nmap scan timed out for {ip}")
            return {
                'error': 'Nmap scan timed out',
                'services': [],
                'raw_output': 'Scan timed out after 60 seconds'
            }
            
        output = stdout.decode()
        
        # Parse nmap output to extract services
        services = []
        for line in output.splitlines():
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0]
                    state = parts[1]
                    service = ' '.join(parts[2:])
                    port = port_proto.split('/')[0]
                    protocol = port_proto.split('/')[1]
                    
                    services.append({
                        'port': port,
                        'protocol': protocol,
                        'state': state,
                        'service': service
                    })
        
        return {
            'services': services,
            'raw_output': output
        }
    except Exception as e:
        logger.error(f"Error running nmap scan: {e}")
        return {
            'error': f"Error: {str(e)}",
            'services': [],
            'raw_output': ''
        }

async def shodan_lookup(ip: str, api_key: str, progress: ProgressTracker = None) -> Dict[str, Union[str, List[str], Dict]]:
    """Look up an IP address in Shodan."""
    if progress:
        progress.update(message=f"Querying Shodan for {ip}")
    
    if not api_key:
        logger.warning("Shodan API key not provided. Skipping Shodan lookup.")
        return {"error": "Shodan API key not configured"}
    
    if not SHODAN_AVAILABLE:
        logger.warning("Shodan module not available. Skipping Shodan lookup.")
        return {"error": "Shodan module not installed"}
        
    for attempt in range(RETRY_ATTEMPTS):
        try:
            api = shodan.Shodan(api_key)
            host = await asyncio.get_event_loop().run_in_executor(None, api.host, ip)
            
            result = {
                "ip": ip,
                "os": host.get("os", "Unknown"),
                "organization": host.get("org", "Unknown"),
                "country": host.get("country_name", "Unknown"),
                "city": host.get("city", "Unknown"),
                "ports": host.get("ports", []),
                "hostnames": host.get("hostnames", []),
                "domains": host.get("domains", []),
                "vulns": host.get("vulns", []),
                "last_update": host.get("last_update", "N/A"),
                "asn": host.get("asn", "N/A"),
                "isp": host.get("isp", "N/A")
            }
            
            # Extract SSL information if available
            if "ssl" in host:
                result["ssl"] = {
                    "cert_issuer": host["ssl"].get("cert", {}).get("issuer", {}),
                    "cert_expires": host["ssl"].get("cert", {}).get("expires", "N/A"),
                    "cipher": host["ssl"].get("cipher", {}),
                    "versions": host["ssl"].get("versions", [])
                }
            
            logger.info(f"Successfully retrieved Shodan data for {ip}")
            return result
            
        except shodan.APIError as e:
            if attempt < RETRY_ATTEMPTS - 1:
                logger.warning(f"Shodan API error for {ip}, attempt {attempt + 1}: {e}")
                await asyncio.sleep(RETRY_DELAY)
                continue
            logger.error(f"Shodan API error for {ip} after {RETRY_ATTEMPTS} attempts: {e}")
            return {"error": f"Shodan API error: {str(e)}"}
        except Exception as e:
            logger.error(f"Unexpected error in Shodan lookup for {ip}: {e}")
            return {"error": f"Unexpected error: {str(e)}"}

async def abuseipdb_lookup(ip: str, api_key: str, progress: ProgressTracker = None) -> Dict[str, Union[str, int, List[Dict]]]:
    if progress:
        progress.update(message=f"Checking AbuseIPDB for {ip}")
    
    if not api_key:
        logger.warning("AbuseIPDB API key not provided. Skipping AbuseIPDB lookup.")
        return {"error": "AbuseIPDB API key not configured"}
        
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    
    for attempt in range(RETRY_ATTEMPTS):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers=headers,
                    params=params,
                    timeout=REQUEST_TIMEOUT
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.info(f"Successfully retrieved AbuseIPDB data for {ip}")
                        return data.get('data', {})
                    else:
                        error_text = await response.text()
                        logger.warning(f"AbuseIPDB API error for {ip}, attempt {attempt + 1}: {error_text}")
                        if attempt < RETRY_ATTEMPTS - 1:
                            await asyncio.sleep(RETRY_DELAY)
                            continue
                        return {"error": f"AbuseIPDB API error: {error_text}"}
        except asyncio.TimeoutError:
            logger.warning(f"AbuseIPDB request timed out for {ip}, attempt {attempt + 1}")
            if attempt < RETRY_ATTEMPTS - 1:
                await asyncio.sleep(RETRY_DELAY)
                continue
            return {"error": "Request timed out"}
        except Exception as e:
            logger.error(f"Unexpected error in AbuseIPDB lookup for {ip}: {e}")
            return {"error": f"Unexpected error: {str(e)}"}
    
    return {"error": "Maximum retry attempts reached"}

async def censys_lookup(ip: str, api_id: str, api_secret: str, progress: ProgressTracker = None) -> Dict[str, Union[str, List[Dict]]]:
    """Look up an IP address in Censys."""
    if progress:
        progress.update(message=f"Querying Censys for {ip}")
        
    # Skip if credentials are not configured
    if not api_id or not api_secret:
        logger.warning("Censys API credentials not configured. Skipping Censys lookup.")
        return {"error": "Censys API credentials not configured"}
    
    try:
        # Import here to avoid errors if not installed
        try:
            from censys.search import CensysHosts
            from censys.common.exceptions import CensysNotFoundException, CensysRateLimitExceededException
        except ImportError:
            logger.warning("Censys module not installed. Skipping Censys lookup.")
            return {"error": "Censys module not installed"}
        
        # Initialize Censys client
        c = CensysHosts(api_id=api_id, api_secret=api_secret)
        
        # Query Censys for the IP
        host_data = await asyncio.get_event_loop().run_in_executor(None, c.view, ip)
        
        # Extract relevant information
        result = {
            "ip": ip,
            "last_updated": host_data.get("last_updated", "Unknown"),
            "services": [],
            "location": host_data.get("location", {}),
            "autonomous_system": host_data.get("autonomous_system", {})
        }
        
        # Extract services information
        if "services" in host_data:
            for service in host_data["services"]:
                service_info = {
                    "port": service.get("port"),
                    "service_name": service.get("service_name"),
                    "transport_protocol": service.get("transport_protocol")
                }
                
                # Extract TLS information if available
                if "tls" in service:
                    service_info["tls"] = {
                        "version": service["tls"].get("version"),
                        "cipher": service["tls"].get("cipher"),
                        "certificate": {
                            "issuer": service["tls"].get("certificate", {}).get("issuer", {}),
                            "subject": service["tls"].get("certificate", {}).get("subject", {}),
                            "validity": service["tls"].get("certificate", {}).get("validity", {})
                        }
                    }
                
                result["services"].append(service_info)
        
        logger.info(f"Successfully retrieved Censys data for {ip}")
        return result
        
    except Exception as e:
        logger.error(f"Error in Censys lookup for {ip}: {e}")
        return {"error": f"Censys lookup error: {str(e)}"}

async def otx_lookup(domain: str, api_key: str, progress: ProgressTracker = None) -> Dict[str, Union[str, List[Dict]]]:
    """Look up a domain in AlienVault OTX."""
    if progress:
        progress.update(message=f"Querying OTX for {domain}")
    
    if not api_key:
        logger.warning("OTX API key not provided. Skipping OTX lookup.")
        return {"error": "OTX API key not configured"}
    
    if not OTX_AVAILABLE:
        logger.warning("OTXv2 module not available. Skipping OTX lookup.")
        return {"error": "OTXv2 module not installed"}
        
    try:
        otx = OTXv2(api_key)
        
        # Get general information
        general = await asyncio.get_event_loop().run_in_executor(
            None, 
            lambda: otx.get_indicator_details_by_section(
                IndicatorTypes.DOMAIN, 
                domain, 
                'general'
            )
        )
        
        # Get geo information
        geo = await asyncio.get_event_loop().run_in_executor(
            None, 
            lambda: otx.get_indicator_details_by_section(
                IndicatorTypes.DOMAIN, 
                domain, 
                'geo'
            )
        )
        
        # Get malware information
        malware = await asyncio.get_event_loop().run_in_executor(
            None, 
            lambda: otx.get_indicator_details_by_section(
                IndicatorTypes.DOMAIN, 
                domain, 
                'malware'
            )
        )
        
        # Get URL information
        url_list = await asyncio.get_event_loop().run_in_executor(
            None, 
            lambda: otx.get_indicator_details_by_section(
                IndicatorTypes.DOMAIN, 
                domain, 
                'url_list'
            )
        )
        
        # Get passive DNS information
        passive_dns = await asyncio.get_event_loop().run_in_executor(
            None, 
            lambda: otx.get_indicator_details_by_section(
                IndicatorTypes.DOMAIN, 
                domain, 
                'passive_dns'
            )
        )
        
        # Combine all data
        result = {
            "general": general,
            "geo": geo,
            "malware": malware,
            "url_list": url_list,
            "passive_dns": passive_dns
        }
        
        logger.debug(f"OTX Domain Response: {json.dumps(result, default=str)}")
        
        # Extract relevant information
        findings = []
        
        # Check if domain is in any pulse (threat intelligence report)
        if general.get("pulse_info", {}).get("count", 0) > 0:
            findings.append({
                "severity": "HIGH",
                "category": "Threat Intelligence",
                "finding": f"Domain found in {general['pulse_info']['count']} threat intelligence reports"
            })
        
        # Check for malware samples
        if malware.get("count", 0) > 0:
            findings.append({
                "severity": "HIGH",
                "category": "Malware",
                "finding": f"Domain associated with {malware['count']} malware samples"
            })
        
        return {
            "data": result,
            "findings": findings
        }
        
    except Exception as e:
        logger.error(f"Error in OTX lookup for {domain}: {e}")
        return {"error": f"OTX lookup error: {str(e)}"}

async def analyze_target(target: str, max_hosts: int = 256, days: int = 30, 
                         verbose: bool = False, output_format: str = "text",
                         parallel_factor: int = 1, show_progress: bool = True,
                         shodan_api_key: str = None, abuseipdb_api_key: str = None,
                         otx_api_key: str = None, censys_api_id: str = None,
                         censys_api_secret: str = None) -> Dict:
    """Main analysis function for a target (domain, IP, or subnet)."""
    # Use provided API keys or fall back to config/environment variables
    shodan_key = shodan_api_key or SHODAN_API_KEY or os.getenv('SHODAN_API_KEY', '')
    abuseipdb_key = abuseipdb_api_key or ABUSEIPDB_API_KEY or os.getenv('ABUSEIPDB_API_KEY', '')
    otx_key = otx_api_key or OTX_API_KEY or os.getenv('OTX_API_KEY', '')
    censys_id = censys_api_id or CENSYS_API_ID or os.getenv('CENSYS_API_ID', '')
    censys_secret = censys_api_secret or CENSYS_API_SECRET or os.getenv('CENSYS_API_SECRET', '')
    
    # Determine total steps for progress tracking
    total_steps = 10  # Base steps
    
    # Create progress tracker
    progress = ProgressTracker(total_steps, "Analyzing target", disable=not show_progress)
    
    results = {
        "target": target,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "findings": [],
        "risk_score": 0
    }
    
    # Determine target type
    progress.update(message="Determining target type")
    if is_valid_ip_or_cidr(target):
        if '/' in target:  # CIDR notation
            results["target_type"] = "subnet"
            ips = get_ips_from_subnet(target, max_hosts)
            if len(ips) > max_hosts:
                logger.warning(f"Subnet contains {len(ips)} hosts, limiting to {max_hosts}")
                ips = ips[:max_hosts]
            results["ips"] = ips
            # Adjust total steps based on number of IPs
            progress.total_steps += len(ips) * 3  # 3 operations per IP
        else:  # Single IP
            results["target_type"] = "ip"
            results["ips"] = [target]
            progress.total_steps += 3  # 3 operations for single IP
    else:  # Domain
        results["target_type"] = "domain"
        progress.update(message=f"Resolving domain {target}")
        ip = await resolve_domain(target)
        if ip:
            results["ips"] = [ip]
            progress.total_steps += 8  # Additional domain-specific operations
        else:
            results["error"] = "Could not resolve domain"
            progress.close()
            return results
    
    progress.update()
    
    # Analyze each IP
    ip_results = {}
    
    # Create a semaphore to limit concurrent operations
    sem = asyncio.Semaphore(5 * parallel_factor)  # Adjust based on parallel_factor
    
    async def process_ip(ip):
        async with sem:
            ip_result = {}
            
            # Shodan lookup
            ip_result["shodan"] = await shodan_lookup(ip, shodan_key, progress)
            
            # AbuseIPDB lookup
            ip_result["abuseipdb"] = await abuseipdb_lookup(ip, abuseipdb_key, progress)
            
            # Nmap scan
            ip_result["nmap"] = await run_nmap(ip, progress)
            
            # Check if target is behind CDN
            if ip_result["shodan"].get("organization") and any(cdn in ip_result["shodan"]["organization"] for cdn in ["Cloudflare", "Akamai", "Fastly", "CloudFront", "CDN"]):
                logger.warning(f"Target appears to be behind a CDN ({ip_result['shodan']['organization']})")
                results["cdn_detected"] = ip_result["shodan"]["organization"]
            
            # Add Censys data if credentials are configured
            if censys_id and censys_secret:
                ip_result["censys"] = await censys_lookup(ip, censys_id, censys_secret, progress)
            
            return ip, ip_result
    
    # Process IPs in parallel
    progress.update(message=f"Analyzing {len(results['ips'])} IP addresses")
    ip_tasks = [process_ip(ip) for ip in results.get("ips", [])]
    ip_results_list = await asyncio.gather(*ip_tasks)
    
    # Convert list of results to dictionary
    for ip, result in ip_results_list:
        ip_results[ip] = result
    
    results["ip_results"] = ip_results
    progress.update()
    
    # Domain-specific checks
    if results["target_type"] == "domain":
        progress.update(message=f"Performing domain-specific checks for {target}")
        
        # OTX lookup
        results["otx"] = await otx_lookup(target, otx_key, progress)
        progress.update()
        
        # DNS security checks
        if DNS_CHECKS_AVAILABLE:
            progress.update(message=f"Checking DNS security for {target}")
            results["dns_security"] = await check_dns_security(target)
            progress.update()
        else:
            results["dns_security"] = {"error": "DNS checks module not available"}
            progress.update()
        
        # Certificate transparency logs
        if CERT_CHECKS_AVAILABLE:
            progress.update(message=f"Checking certificate logs for {target}")
            results["certificate_logs"] = await check_certificate_logs(target)
            progress.update()
        else:
            results["certificate_logs"] = {"error": "Certificate checks module not available"}
            progress.update()
        
        # Cloud exposure checks
        if CLOUD_CHECKS_AVAILABLE:
            progress.update(message=f"Checking cloud exposure for {target}")
            results["cloud_exposure"] = await check_cloud_exposure(target)
            progress.update()
        else:
            results["cloud_exposure"] = {"error": "Cloud checks module not available"}
            progress.update()
        
        # Typosquatting detection - with reduced scope and better error handling
        if TYPOSQUATTING_AVAILABLE:
            progress.update(message=f"Checking for typosquatting domains similar to {target}")
            try:
                similar_domains = await asyncio.wait_for(
                    typosquatting.find_similar_domains(target, max_age_days=days),
                    timeout=60.0
                )
                results["typosquatting"] = {
                    "similar_domains": similar_domains,
                    "report": typosquatting.format_typosquatting_report(similar_domains)
                }
            except asyncio.TimeoutError:
                logger.warning("Typosquatting check timed out")
                results["typosquatting"] = {
                    "error": "Typosquatting check timed out",
                    "similar_domains": [],
                    "report": "Typosquatting check timed out after 60 seconds"
                }
            except Exception as e:
                logger.error(f"Error in typosquatting check: {e}")
                results["typosquatting"] = {
                    "error": f"Error in typosquatting check: {str(e)}",
                    "similar_domains": [],
                    "report": f"Error in typosquatting check: {str(e)}"
                }
        else:
            results["typosquatting"] = {"error": "Typosquatting module not available"}
        progress.update()
        
        # SSL certificate check (if SSL is available)
        if SSL_AVAILABLE:
            progress.update(message=f"Checking SSL certificate for {target}")
            results["ssl_cert"] = await check_ssl_cert(target, progress)
            progress.update()
        else:
            results["ssl_cert"] = {"error": "SSL module not available"}
            progress.update()
    
    # Calculate risk score and compile findings
    progress.update(message="Calculating risk score and compiling findings")
    risk_score = 0
    findings = []
    
    # Process IP-specific findings
    for ip, ip_result in ip_results.items():
        # Check for vulnerabilities in Shodan data
        if "vulns" in ip_result["shodan"] and ip_result["shodan"]["vulns"]:
            vuln_count = len(ip_result["shodan"]["vulns"])
            severity = "HIGH" if vuln_count > 0 else "MEDIUM"
            findings.append({
                "severity": severity,
                "category": "Vulnerabilities",
                "finding": f"Found {vuln_count} known vulnerabilities for {ip}"
            })
            risk_score += RISK_WEIGHTS["known_vulnerabilities"]
        
        # Check for abuse reports
        if "abuseConfidenceScore" in ip_result["abuseipdb"] and ip_result["abuseipdb"]["abuseConfidenceScore"] > 0:
            score = ip_result["abuseipdb"]["abuseConfidenceScore"]
            severity = "HIGH" if score > 50 else "MEDIUM" if score > 20 else "LOW"
            findings.append({
                "severity": severity,
                "category": "Abuse Reports",
                "finding": f"AbuseIPDB confidence score: {score}% for {ip}"
            })
            risk_score += RISK_WEIGHTS["abuse_reports"]
        
        # Check for critical services
        if "services" in ip_result["nmap"]:
            for service in ip_result["nmap"]["services"]:
                try:
                    port = int(service["port"])
                    if port in CRITICAL_SERVICES:
                        findings.append({
                            "severity": "MEDIUM",
                            "category": "Exposed Services",
                            "finding": f"Critical service {CRITICAL_SERVICES[port]} exposed on port {port}"
                        })
                        risk_score += RISK_WEIGHTS["critical_services"]
                except (ValueError, KeyError):
                    pass
    
    # Add domain-specific findings
    if results["target_type"] == "domain":
        # Add DNS security findings
        if "findings" in results["dns_security"]:
            findings.extend(results["dns_security"]["findings"])
            for finding in results["dns_security"]["findings"]:
                category = finding["category"].lower().replace(" ", "_")
                if category in RISK_WEIGHTS.get("dns_security", {}):
                    risk_score += RISK_WEIGHTS["dns_security"][category]
        
        # Add certificate findings
        if "findings" in results["certificate_logs"]:
            findings.extend(results["certificate_logs"]["findings"])
            for finding in results["certificate_logs"]["findings"]:
                category = finding["category"].lower().replace(" ", "_")
                if category in RISK_WEIGHTS.get("certificate_issues", {}):
                    risk_score += RISK_WEIGHTS["certificate_issues"][category]
        
        # Add cloud exposure findings
        if "findings" in results["cloud_exposure"]:
            findings.extend(results["cloud_exposure"]["findings"])
            for finding in results["cloud_exposure"]["findings"]:
                category = finding["category"].lower().replace(" ", "_")
                if category in RISK_WEIGHTS.get("cloud_exposure", {}):
                    risk_score += RISK_WEIGHTS["cloud_exposure"][category]
        
        # Add OTX findings
        if "findings" in results["otx"]:
            findings.extend(results["otx"]["findings"])
            # No specific risk weights for OTX findings
        
        # Add typosquatting findings
        if "similar_domains" in results["typosquatting"] and results["typosquatting"]["similar_domains"]:
            count = len(results["typosquatting"]["similar_domains"])
            severity = "HIGH" if count > 5 else "MEDIUM" if count > 2 else "LOW"
            findings.append({
                "severity": severity,
                "category": "Typosquatting",
                "finding": f"Found {count} recently registered similar domains"
            })
            # No specific risk weight for typosquatting
        
        # Add SSL certificate findings
        if "error" not in results.get("ssl_cert", {}) and "expiry_date" in results.get("ssl_cert", {}):
            expiry_date = results["ssl_cert"]["expiry_date"]
            days_to_expiry = (expiry_date - datetime.now()).days
            if days_to_expiry < 0:
                findings.append({
                    "severity": "HIGH",
                    "category": "SSL Certificate",
                    "finding": f"SSL certificate expired {abs(days_to_expiry)} days ago"
                })
                risk_score += RISK_WEIGHTS["ssl_expired"]
            elif days_to_expiry < 30:
                findings.append({
                    "severity": "MEDIUM",
                    "category": "SSL Certificate",
                    "finding": f"SSL certificate expires in {days_to_expiry} days"
                })
                risk_score += RISK_WEIGHTS["ssl_expired"] / 2
    
    # Add findings and risk score to results
    results["findings"] = findings
    results["risk_score"] = risk_score
    
    # Calculate risk level
    if risk_score > 100:
        results["risk_level"] = "CRITICAL"
    elif risk_score > 70:
        results["risk_level"] = "HIGH"
    elif risk_score > 40:
        results["risk_level"] = "MEDIUM"
    elif risk_score > 10:
        results["risk_level"] = "LOW"
    else:
        results["risk_level"] = "INFO"
    
    progress.update(message="Analysis complete")
    progress.close()
    
    return results

def format_report_text(results: Dict) -> str:
    """Format analysis results into a readable text report."""
    report = []
    report.append("=" * 50)
    report.append(f"EXTERNAL RECONNAISSANCE REPORT FOR {results['target']}")
    report.append("=" * 50)
    report.append(f"Scan Time: {results['scan_time']}")
    report.append(f"Target Type: {results['target_type'].upper()}")
    report.append(f"Risk Level: {results['risk_level']}")
    report.append(f"Risk Score: {results['risk_score']}")
    report.append("")
    
    # Add CDN warning if detected
    if "cdn_detected" in results:
        report.append("⚠️ WARNING: Target appears to be behind a CDN")
        report.append(f"CDN Provider: {results['cdn_detected']}")
        report.append("This may affect the accuracy of IP-based reconnaissance.")
        report.append("")
    
    # Summary of findings
    report.append("FINDINGS SUMMARY")
    report.append("-" * 50)
    
    if not results["findings"]:
        report.append("No significant findings detected.")
    else:
        # Group findings by severity
        severity_groups = {"HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for finding in results["findings"]:
            severity = finding.get("severity", "INFO")
            severity_groups[severity].append(finding)
        
        # Report high severity findings first
        for severity in ["HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity_groups[severity]:
                report.append(f"{severity} Severity Findings:")
                for i, finding in enumerate(severity_groups[severity], 1):
                    report.append(f"  {i}. [{finding['category']}] {finding['finding']}")
                report.append("")
    
    # IP Details
    if "ip_results" in results:
        report.append("IP DETAILS")
        report.append("-" * 50)
        
        for ip, ip_result in results["ip_results"].items():
            report.append(f"IP: {ip}")
            
            # Shodan data
            if "shodan" in ip_result and "error" not in ip_result["shodan"]:
                shodan_data = ip_result["shodan"]
                report.append(f"  Organization: {shodan_data.get('organization', 'Unknown')}")
                report.append(f"  Country: {shodan_data.get('country', 'Unknown')}")
                report.append(f"  City: {shodan_data.get('city', 'Unknown')}")
                report.append(f"  Open Ports: {', '.join(map(str, shodan_data.get('ports', [])))}")
                if "vulns" in shodan_data and shodan_data["vulns"]:
                    report.append(f"  Vulnerabilities: {', '.join(shodan_data['vulns'])}")
            
            # AbuseIPDB data
            if "abuseipdb" in ip_result and "error" not in ip_result["abuseipdb"]:
                abuse_data = ip_result["abuseipdb"]
                report.append(f"  Abuse Confidence Score: {abuse_data.get('abuseConfidenceScore', 'N/A')}%")
                report.append(f"  Total Reports: {abuse_data.get('totalReports', 'N/A')}")
            
            # Nmap data
            if "nmap" in ip_result and "error" not in ip_result["nmap"]:
                nmap_data = ip_result["nmap"]
                if "services" in nmap_data and nmap_data["services"]:
                    report.append("  Services:")
                    for service in nmap_data["services"]:
                        report.append(f"    {service['port']}/{service['protocol']} - {service['service']}")
            
            report.append("")
    
    # Domain-specific details
    if results["target_type"] == "domain":
        # SSL Certificate
        if "ssl_cert" in results and "error" not in results["ssl_cert"]:
            report.append("SSL CERTIFICATE")
            report.append("-" * 50)
            ssl_data = results["ssl_cert"]
            
            if "expiry_date" in ssl_data:
                expiry_date = ssl_data["expiry_date"]
                days_to_expiry = (expiry_date - datetime.now()).days
                report.append(f"Expiry Date: {expiry_date.strftime('%Y-%m-%d')}")
                report.append(f"Days to Expiry: {days_to_expiry}")
            
            if "issuer" in ssl_data:
                issuer = ssl_data["issuer"]
                report.append(f"Issuer: {issuer.get('organizationName', 'Unknown')}")
            
            if "subject" in ssl_data:
                subject = ssl_data["subject"]
                report.append(f"Subject: {subject.get('commonName', 'Unknown')}")
            
            if "cipher_suite" in ssl_data:
                report.append(f"Cipher Suite: {ssl_data['cipher_suite']}")
            
            if "protocol" in ssl_data:
                report.append(f"Protocol: {ssl_data['protocol']}")
            
            report.append("")
        elif "ssl_cert" in results and "error" in results["ssl_cert"]:
            if "limited_check" not in results["ssl_cert"]:
                report.append("SSL CERTIFICATE")
                report.append("-" * 50)
                report.append(f"Error: {results['ssl_cert']['error']}")
                report.append("")
        
        # DNS Security
        if "dns_security" in results and "error" not in results["dns_security"]:
            report.append("DNS SECURITY")
            report.append("-" * 50)
            dns_data = results["dns_security"]
            
            report.append(f"SPF Record: {'Present' if dns_data.get('spf', {}).get('exists', False) else 'Missing'}")
            if dns_data.get('spf', {}).get('record'):
                report.append(f"  {dns_data['spf']['record']}")
            
            report.append(f"DMARC Record: {'Present' if dns_data.get('dmarc', {}).get('exists', False) else 'Missing'}")
            if dns_data.get('dmarc', {}).get('record'):
                report.append(f"  {dns_data['dmarc']['record']}")
            
            report.append(f"MX Records: {'Present' if dns_data.get('mx', {}).get('exists', False) else 'Missing'}")
            if dns_data.get('mx', {}).get('records'):
                for mx in dns_data['mx']['records']:
                    report.append(f"  {mx}")
            
            report.append(f"Nameservers: {', '.join(dns_data.get('ns', []))}")
            report.append("")
        
        # Certificate Transparency
        if "certificate_logs" in results and "error" not in results["certificate_logs"]:
            report.append("CERTIFICATE TRANSPARENCY")
            report.append("-" * 50)
            cert_data = results["certificate_logs"]
            
            if "certificates" in cert_data and cert_data["certificates"]:
                report.append(f"Found {len(cert_data['certificates'])} certificates in transparency logs")
                report.append("Recent certificates:")
                for i, cert in enumerate(cert_data["certificates"][:5], 1):
                    report.append(f"  {i}. Issuer: {cert.get('issuer', 'Unknown')}")
                    report.append(f"     Subject: {cert.get('name', 'Unknown')}")
                    report.append(f"     Date: {cert.get('date', 'Unknown')}")
            else:
                report.append("No certificates found in transparency logs")
            report.append("")
        
        # Cloud Exposure
        if "cloud_exposure" in results and "error" not in results["cloud_exposure"]:
            report.append("CLOUD EXPOSURE")
            report.append("-" * 50)
            cloud_data = results["cloud_exposure"]
            
            if "cloud_assets" in cloud_data:
                assets = cloud_data["cloud_assets"]
                
                if assets.get("github"):
                    report.append("GitHub Assets:")
                    for asset in assets["github"]:
                        report.append(f"  Organization: {asset.get('url', 'Unknown')}")
                        report.append(f"  Public Repos: {asset.get('public_repos', 0)}")
                
                if assets.get("s3_buckets"):
                    report.append("S3 Buckets:")
                    for bucket in assets["s3_buckets"]:
                        report.append(f"  {bucket}")
                
                if assets.get("azure_blobs"):
                    report.append("Azure Blob Storage:")
                    for blob in assets["azure_blobs"]:
                        report.append(f"  {blob}")
                
                if assets.get("gcp_storage"):
                    report.append("Google Cloud Storage:")
                    for storage in assets["gcp_storage"]:
                        report.append(f"  {storage}")
            
            if not any(cloud_data.get("cloud_assets", {}).values()):
                report.append("No exposed cloud assets detected")
            report.append("")
        
        # Typosquatting
        if "typosquatting" in results and "error" not in results["typosquatting"]:
            report.append("TYPOSQUATTING DETECTION")
            report.append("-" * 50)
            
            if "similar_domains" in results["typosquatting"] and results["typosquatting"]["similar_domains"]:
                domains = results["typosquatting"]["similar_domains"]
                report.append(f"Found {len(domains)} recently registered similar domains:")
                for i, domain in enumerate(domains, 1):
                    report.append(f"  {i}. {domain['domain']}")
                    report.append(f"     Registered: {domain['creation_date'].strftime('%Y-%m-%d')}")
                    report.append(f"     Registrar: {domain['registrar']}")
            else:
                report.append("No suspicious similar domains found")
            report.append("")
    
    # Recommendations
    report.append("RECOMMENDATIONS")
    report.append("-" * 50)
    
    # Generate recommendations based on findings
    recommendations = set()
    for finding in results["findings"]:
        category = finding["category"]
        
        if category == "Email Security":
            if "SPF" in finding["finding"]:
                recommendations.add("Implement a proper SPF record with a strict policy (-all)")
            if "DMARC" in finding["finding"]:
                recommendations.add("Implement a DMARC record with at least a quarantine policy")
        
        elif category == "DNS Configuration":
            if "nameserver" in finding["finding"].lower():
                recommendations.add("Use at least two nameservers for redundancy")
        
        elif category == "Certificate Monitoring":
            if "non-production" in finding["finding"].lower():
                recommendations.add("Review and revoke any non-production certificates for production domains")
        
        elif category == "Cloud Storage":
            recommendations.add("Review access controls for cloud storage assets")
            recommendations.add("Implement proper access policies for cloud resources")
        
        elif category == "Vulnerabilities":
            recommendations.add("Patch systems to address known vulnerabilities")
        
        elif category == "Exposed Services":
            recommendations.add("Restrict access to critical services using firewalls")
            recommendations.add("Implement network segmentation for sensitive services")
        
        elif category == "Typosquatting":
            recommendations.add("Monitor for typosquatting domains and consider defensive registrations")
        
        elif category == "SSL Certificate":
            if "expired" in finding["finding"].lower() or "expires" in finding["finding"].lower():
                recommendations.add("Renew SSL certificate before expiration")
    
    # Add general recommendations
    recommendations.add("Regularly monitor for new vulnerabilities and security issues")
    recommendations.add("Implement a vulnerability management program")
    
    # Output recommendations
    if recommendations:
        for i, rec in enumerate(sorted(recommendations), 1):
            report.append(f"{i}. {rec}")
    else:
        report.append("No specific recommendations at this time.")
    
    return "\n".join(report)

def format_report_html(results: Dict) -> str:
    """Format analysis results into an HTML report."""
    html = []
    html.append("<!DOCTYPE html>")
    html.append("<html lang='en'>")
    html.append("<head>")
    html.append("  <meta charset='UTF-8'>")
    html.append("  <meta name='viewport' content='width=device-width, initial-scale=1.0'>")
    html.append("  <title>External Reconnaissance Report</title>")
    html.append("  <style>")
    html.append("    body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }")
    html.append("    h1, h2, h3 { color: #2c3e50; }")
    html.append("    h1 { border-bottom: 2px solid #3498db; padding-bottom: 10px; }")
    html.append("    h2 { border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; margin-top: 30px; }")
    html.append("    .container { max-width: 1200px; margin: 0 auto; }")
    html.append("    .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }")
    html.append("    .warning { background-color: #fff3cd; color: #856404; padding: 15px; border-radius: 5px; margin-bottom: 20px; }")
    html.append("    .finding { margin-bottom: 10px; padding: 10px; border-radius: 5px; }")
    html.append("    .finding.high { background-color: #f8d7da; color: #721c24; }")
    html.append("    .finding.medium { background-color: #fff3cd; color: #856404; }")
    html.append("    .finding.low { background-color: #d1ecf1; color: #0c5460; }")
    html.append("    .finding.info { background-color: #d6d8d9; color: #1b1e21; }")
    html.append("    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }")
    html.append("    th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }")
    html.append("    th { background-color: #f2f2f2; }")
    html.append("    tr:hover { background-color: #f5f5f5; }")
    html.append("    .recommendation { background-color: #e8f4f8; padding: 10px; margin-bottom: 10px; border-radius: 5px; }")
    html.append("  </style>")
    html.append("</head>")
    html.append("<body>")
    html.append("  <div class='container'>")
    
    # Header
    html.append(f"    <h1>External Reconnaissance Report for {results['target']}</h1>")
    
    # Summary
    html.append("    <div class='summary'>")
    html.append(f"      <p><strong>Scan Time:</strong> {results['scan_time']}</p>")
    html.append(f"      <p><strong>Target Type:</strong> {results['target_type'].upper()}</p>")
    html.append(f"      <p><strong>Risk Level:</strong> {results['risk_level']}</p>")
    html.append(f"      <p><strong>Risk Score:</strong> {results['risk_score']}</p>")
    html.append("    </div>")
    
    # CDN Warning
    if "cdn_detected" in results:
        html.append("    <div class='warning'>")
        html.append("      <h3>⚠️ WARNING: Target appears to be behind a CDN</h3>")
        html.append(f"      <p><strong>CDN Provider:</strong> {results['cdn_detected']}</p>")
        html.append("      <p>This may affect the accuracy of IP-based reconnaissance.</p>")
        html.append("    </div>")
    
    # Findings Summary
    html.append("    <h2>Findings Summary</h2>")
    
    if not results["findings"]:
        html.append("    <p>No significant findings detected.</p>")
    else:
        # Group findings by severity
        severity_groups = {"HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for finding in results["findings"]:
            severity = finding.get("severity", "INFO")
            severity_groups[severity].append(finding)
        
        # Report high severity findings first
        for severity in ["HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity_groups[severity]:
                html.append(f"    <h3>{severity} Severity Findings</h3>")
                for finding in severity_groups[severity]:
                    html.append(f"    <div class='finding {severity.lower()}'>")
                    html.append(f"      <strong>[{finding['category']}]</strong> {finding['finding']}")
                    html.append("    </div>")
    
    # IP Details
    if "ip_results" in results:
        html.append("    <h2>IP Details</h2>")
        
        for ip, ip_result in results["ip_results"].items():
            html.append(f"    <h3>IP: {ip}</h3>")
            
            # Shodan data
            if "shodan" in ip_result and "error" not in ip_result["shodan"]:
                shodan_data = ip_result["shodan"]
                html.append("    <table>")
                html.append("      <tr><th colspan='2'>Shodan Information</th></tr>")
                html.append(f"      <tr><td>Organization</td><td>{shodan_data.get('organization', 'Unknown')}</td></tr>")
                html.append(f"      <tr><td>Country</td><td>{shodan_data.get('country', 'Unknown')}</td></tr>")
                html.append(f"      <tr><td>City</td><td>{shodan_data.get('city', 'Unknown')}</td></tr>")
                html.append(f"      <tr><td>Open Ports</td><td>{', '.join(map(str, shodan_data.get('ports', [])))}</td></tr>")
                if "vulns" in shodan_data and shodan_data["vulns"]:
                    html.append(f"      <tr><td>Vulnerabilities</td><td>{', '.join(shodan_data['vulns'])}</td></tr>")
                html.append("    </table>")
            
            # AbuseIPDB data
            if "abuseipdb" in ip_result and "error" not in ip_result["abuseipdb"]:
                abuse_data = ip_result["abuseipdb"]
                html.append("    <table>")
                html.append("      <tr><th colspan='2'>AbuseIPDB Information</th></tr>")
                html.append(f"      <tr><td>Abuse Confidence Score</td><td>{abuse_data.get('abuseConfidenceScore', 'N/A')}%</td></tr>")
                html.append(f"      <tr><td>Total Reports</td><td>{abuse_data.get('totalReports', 'N/A')}</td></tr>")
                html.append("    </table>")
            
            # Nmap data
            if "nmap" in ip_result and "error" not in ip_result["nmap"]:
                nmap_data = ip_result["nmap"]
                if "services" in nmap_data and nmap_data["services"]:
                    html.append("    <table>")
                    html.append("      <tr><th colspan='4'>Open Services (Nmap)</th></tr>")
                    html.append("      <tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th></tr>")
                    for service in nmap_data["services"]:
                        html.append(f"      <tr><td>{service['port']}</td><td>{service['protocol']}</td><td>{service['state']}</td><td>{service['service']}</td></tr>")
                    html.append("    </table>")
    
    # Domain-specific details
    if results["target_type"] == "domain":
        # SSL Certificate
        if "ssl_cert" in results and "error" not in results["ssl_cert"]:
            html.append("    <h2>SSL Certificate</h2>")
            ssl_data = results["ssl_cert"]
            
            html.append("    <table>")
            html.append("      <tr><th colspan='2'>Certificate Details</th></tr>")
            
            if "expiry_date" in ssl_data:
                expiry_date = ssl_data["expiry_date"]
                days_to_expiry = (expiry_date - datetime.now()).days
                html.append(f"      <tr><td>Expiry Date</td><td>{expiry_date.strftime('%Y-%m-%d')}</td></tr>")
                html.append(f"      <tr><td>Days to Expiry</td><td>{days_to_expiry}</td></tr>")
            
            if "issuer" in ssl_data:
                issuer = ssl_data["issuer"]
                html.append(f"      <tr><td>Issuer</td><td>{issuer.get('organizationName', 'Unknown')}</td></tr>")
            
            if "subject" in ssl_data:
                subject = ssl_data["subject"]
                html.append(f"      <tr><td>Subject</td><td>{subject.get('commonName', 'Unknown')}</td></tr>")
            
            if "cipher_suite" in ssl_data:
                html.append(f"      <tr><td>Cipher Suite</td><td>{ssl_data['cipher_suite']}</td></tr>")
            
            if "protocol" in ssl_data:
                html.append(f"      <tr><td>Protocol</td><td>{ssl_data['protocol']}</td></tr>")
            
            html.append("    </table>")
        
        # DNS Security
        if "dns_security" in results and "error" not in results["dns_security"]:
            html.append("    <h2>DNS Security</h2>")
            dns_data = results["dns_security"]
            
            html.append("    <table>")
            html.append("      <tr><th>Record Type</th><th>Status</th><th>Value</th></tr>")
            
            # SPF
            spf_exists = dns_data.get('spf', {}).get('exists', False)
            html.append(f"      <tr><td>SPF</td><td>{'Present' if spf_exists else 'Missing'}</td><td>{dns_data.get('spf', {}).get('record', 'N/A')}</td></tr>")
            
            # DMARC
            dmarc_exists = dns_data.get('dmarc', {}).get('exists', False)
            html.append(f"      <tr><td>DMARC</td><td>{'Present' if dmarc_exists else 'Missing'}</td><td>{dns_data.get('dmarc', {}).get('record', 'N/A')}</td></tr>")
            
            # MX
            mx_exists = dns_data.get('mx', {}).get('exists', False)
            mx_records = ', '.join(dns_data.get('mx', {}).get('records', []))
            html.append(f"      <tr><td>MX</td><td>{'Present' if mx_exists else 'Missing'}</td><td>{mx_records}</td></tr>")
            
            # NS
            ns_records = ', '.join(dns_data.get('ns', []))
            html.append(f"      <tr><td>Nameservers</td><td>{'Present' if ns_records else 'Missing'}</td><td>{ns_records}</td></tr>")
            
            html.append("    </table>")
        
        # Certificate Transparency
        if "certificate_logs" in results and "error" not in results["certificate_logs"]:
            html.append("    <h2>Certificate Transparency</h2>")
            cert_data = results["certificate_logs"]
            
            if "certificates" in cert_data and cert_data["certificates"]:
                html.append(f"    <p>Found {len(cert_data['certificates'])} certificates in transparency logs</p>")
                html.append("    <table>")
                html.append("      <tr><th>Issuer</th><th>Subject</th><th>Date</th></tr>")
                for cert in cert_data["certificates"][:5]:
                    html.append(f"      <tr><td>{cert.get('issuer', 'Unknown')}</td><td>{cert.get('name', 'Unknown')}</td><td>{cert.get('date', 'Unknown')}</td></tr>")
                html.append("    </table>")
            else:
                html.append("    <p>No certificates found in transparency logs</p>")
        
        # Cloud Exposure
        if "cloud_exposure" in results and "error" not in results["cloud_exposure"]:
            html.append("    <h2>Cloud Exposure</h2>")
            cloud_data = results["cloud_exposure"]
            
            if "cloud_assets" in cloud_data:
                assets = cloud_data["cloud_assets"]
                
                if assets.get("github"):
                    html.append("    <h3>GitHub Assets</h3>")
                    html.append("    <table>")
                    html.append("      <tr><th>Organization</th><th>Public Repos</th></tr>")
                    for asset in assets["github"]:
                        html.append(f"      <tr><td>{asset.get('url', 'Unknown')}</td><td>{asset.get('public_repos', 0)}</td></tr>")
                    html.append("    </table>")
                
                if assets.get("s3_buckets"):
                    html.append("    <h3>S3 Buckets</h3>")
                    html.append("    <ul>")
                    for bucket in assets["s3_buckets"]:
                        html.append(f"      <li>{bucket}</li>")
                    html.append("    </ul>")
                
                if assets.get("azure_blobs"):
                    html.append("    <h3>Azure Blob Storage</h3>")
                    html.append("    <ul>")
                    for blob in assets["azure_blobs"]:
                        html.append(f"      <li>{blob}</li>")
                    html.append("    </ul>")
                
                if assets.get("gcp_storage"):
                    html.append("    <h3>Google Cloud Storage</h3>")
                    html.append("    <ul>")
                    for storage in assets["gcp_storage"]:
                        html.append(f"      <li>{storage}</li>")
                    html.append("    </ul>")
            
            if not any(cloud_data.get("cloud_assets", {}).values()):
                html.append("    <p>No exposed cloud assets detected</p>")
        
        # Typosquatting
        if "typosquatting" in results and "error" not in results["typosquatting"]:
            html.append("    <h2>Typosquatting Detection</h2>")
            
            if "similar_domains" in results["typosquatting"] and results["typosquatting"]["similar_domains"]:
                domains = results["typosquatting"]["similar_domains"]
                html.append(f"    <p>Found {len(domains)} recently registered similar domains:</p>")
                html.append("    <table>")
                html.append("      <tr><th>Domain</th><th>Registration Date</th><th>Registrar</th></tr>")
                for domain in domains:
                    html.append(f"      <tr><td>{domain['domain']}</td><td>{domain['creation_date'].strftime('%Y-%m-%d')}</td><td>{domain['registrar']}</td></tr>")
                html.append("    </table>")
            else:
                html.append("    <p>No suspicious similar domains found</p>")
    
    # Recommendations
    html.append("    <h2>Recommendations</h2>")
    
    # Generate recommendations based on findings
    recommendations = set()
    for finding in results["findings"]:
        category = finding["category"]
        
        if category == "Email Security":
            if "SPF" in finding["finding"]:
                recommendations.add("Implement a proper SPF record with a strict policy (-all)")
            if "DMARC" in finding["finding"]:
                recommendations.add("Implement a DMARC record with at least a quarantine policy")
        
        elif category == "DNS Configuration":
            if "nameserver" in finding["finding"].lower():
                recommendations.add("Use at least two nameservers for redundancy")
        
        elif category == "Certificate Monitoring":
            if "non-production" in finding["finding"].lower():
                recommendations.add("Review and revoke any non-production certificates for production domains")
        
        elif category == "Cloud Storage":
            recommendations.add("Review access controls for cloud storage assets")
            recommendations.add("Implement proper access policies for cloud resources")
        
        elif category == "Vulnerabilities":
            recommendations.add("Patch systems to address known vulnerabilities")
        
        elif category == "Exposed Services":
            recommendations.add("Restrict access to critical services using firewalls")
            recommendations.add("Implement network segmentation for sensitive services")
        
        elif category == "Typosquatting":
            recommendations.add("Monitor for typosquatting domains and consider defensive registrations")
        
        elif category == "SSL Certificate":
            if "expired" in finding["finding"].lower() or "expires" in finding["finding"].lower():
                recommendations.add("Renew SSL certificate before expiration")
    
    # Add general recommendations
    recommendations.add("Regularly monitor for new vulnerabilities and security issues")
    recommendations.add("Implement a vulnerability management program")
    
    # Output recommendations
    if recommendations:
        html.append("    <ol>")
        for rec in sorted(recommendations):
            html.append(f"      <li class='recommendation'>{rec}</li>")
        html.append("    </ol>")
    else:
        html.append("    <p>No specific recommendations at this time.</p>")
    
    # Footer
    html.append("    <hr>")
    html.append(f"    <p><em>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</em></p>")
    html.append("  </div>")
    html.append("</body>")
    html.append("</html>")
    
    return "\n".join(html)

def export_csv(results: Dict, filename: str) -> None:
    """Export findings to CSV format."""
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['Severity', 'Category', 'Finding']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for finding in results["findings"]:
            writer.writerow({
                'Severity': finding.get('severity', 'INFO'),
                'Category': finding.get('category', 'Unknown'),
                'Finding': finding.get('finding', 'No details')
            })

def save_report(results: Dict, output_format: str = "text", base_filename: str = None) -> str:
    """Save report in the specified format."""
    if not base_filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"recon_{results['target'].replace('.', '_').replace('/', '_')}_{timestamp}"
    
    # Always save JSON results
    with open(f"{base_filename}.json", "w") as f:
        json.dump(results, f, default=str, indent=2)
    
    # Save in requested format
    if output_format == "text" or output_format == "all":
        report_text = format_report_text(results)
        with open(f"{base_filename}.txt", "w") as f:
            f.write(report_text)
    
    if output_format == "html" or output_format == "all":
        report_html = format_report_html(results)
        with open(f"{base_filename}.html", "w") as f:
            f.write(report_html)
    
    if output_format == "csv" or output_format == "all":
        export_csv(results, f"{base_filename}_findings.csv")
    
    return base_filename

def prompt_for_api_keys():
    """Prompt user for API keys if not provided in config or environment variables."""
    api_keys = {}
    
    # Check if Shodan API key is available
    if not SHODAN_API_KEY and not os.getenv('SHODAN_API_KEY'):
        print("\nShodan API key not found in config or environment variables.")
        api_keys['shodan'] = input("Enter Shodan API key (or press Enter to skip): ").strip()
    
    # Check if AbuseIPDB API key is available
    if not ABUSEIPDB_API_KEY and not os.getenv('ABUSEIPDB_API_KEY'):
        print("\nAbuseIPDB API key not found in config or environment variables.")
        api_keys['abuseipdb'] = input("Enter AbuseIPDB API key (or press Enter to skip): ").strip()
    
    # Check if OTX API key is available
    if not OTX_API_KEY and not os.getenv('OTX_API_KEY'):
        print("\nOTX API key not found in config or environment variables.")
        api_keys['otx'] = input("Enter OTX API key (or press Enter to skip): ").strip()
    
    # Check if Censys API credentials are available
    if (not CENSYS_API_ID and not os.getenv('CENSYS_API_ID')) or (not CENSYS_API_SECRET and not os.getenv('CENSYS_API_SECRET')):
        print("\nCensys API credentials not found in config or environment variables.")
        api_keys['censys_id'] = input("Enter Censys API ID (or press Enter to skip): ").strip()
        if api_keys.get('censys_id'):
            api_keys['censys_secret'] = input("Enter Censys API Secret: ").strip()
    
    return api_keys

async def main():
    parser = argparse.ArgumentParser(description='External Reconnaissance and Risk Assessment Tool')
    parser.add_argument('target', help='Target to analyze. Can be a domain (e.g., example.com), IP (e.g., 1.2.3.4), or subnet (e.g., 1.2.3.0/24)')
    parser.add_argument('--days', type=int, default=30, help='Number of days to look back for similar domains (default: 30)')
    parser.add_argument('--max-hosts', type=int, default=256, help='Maximum number of hosts to scan in a subnet (default: 256)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--output', '-o', choices=['text', 'html', 'csv', 'all'], default='text', 
                        help='Output format (default: text)')
    parser.add_argument('--parallel', '-p', type=int, default=1, 
                        help='Parallel processing factor (1-5, higher values use more resources but may be faster) (default: 1)')
    parser.add_argument('--no-progress', action='store_true', 
                        help='Disable progress bars')
    parser.add_argument('--prompt-api-keys', action='store_true',
                        help='Prompt for API keys during execution')
    parser.add_argument('--shodan-key', type=str, default="",
                        help='Shodan API key')
    parser.add_argument('--abuseipdb-key', type=str, default="",
                        help='AbuseIPDB API key')
    parser.add_argument('--otx-key', type=str, default="",
                        help='OTX API key')
    parser.add_argument('--censys-id', type=str, default="",
                        help='Censys API ID')
    parser.add_argument('--censys-secret', type=str, default="",
                        help='Censys API Secret')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
    
    # Validate parallel factor
    parallel_factor = max(1, min(5, args.parallel))
    if parallel_factor != args.parallel:
        logger.warning(f"Parallel factor adjusted to {parallel_factor} (valid range: 1-5)")
    
    # Print SSL availability status
    if SSL_AVAILABLE:
        logger.info("SSL module is available. Full certificate checks will be performed.")
    else:
        logger.warning("SSL module is not available. Certificate checks will be limited.")
        logger.info("To enable full SSL functionality, install OpenSSL libraries for your system.")
    
    # Prompt for API keys if requested
    api_keys = {}
    if args.prompt_api_keys:
        api_keys = prompt_for_api_keys()
    
    # Use API keys from command line args, prompt, or config (in that order)
    shodan_key = args.shodan_key or api_keys.get('shodan', '') or SHODAN_API_KEY or os.getenv('SHODAN_API_KEY', '')
    abuseipdb_key = args.abuseipdb_key or api_keys.get('abuseipdb', '') or ABUSEIPDB_API_KEY or os.getenv('ABUSEIPDB_API_KEY', '')
    otx_key = args.otx_key or api_keys.get('otx', '') or OTX_API_KEY or os.getenv('OTX_API_KEY', '')
    censys_id = args.censys_id or api_keys.get('censys_id', '') or CENSYS_API_ID or os.getenv('CENSYS_API_ID', '')
    censys_secret = args.censys_secret or api_keys.get('censys_secret', '') or CENSYS_API_SECRET or os.getenv('CENSYS_API_SECRET', '')
    
    try:
        print(f"Starting reconnaissance on {args.target}...")
        
        results = await analyze_target(
            args.target, 
            args.max_hosts, 
            args.days, 
            args.verbose,
            args.output,
            parallel_factor,
            not args.no_progress,
            shodan_key,
            abuseipdb_key,
            otx_key,
            censys_id,
            censys_secret
        )
        
        # Save report in requested format
        base_filename = save_report(results, args.output)
        
        # Print report to console if text format
        if args.output == "text":
            print("\n" + format_report_text(results))
        else:
            print(f"\nAnalysis complete. Risk level: {results['risk_level']}")
            print(f"Found {len(results['findings'])} findings.")
        
        print(f"\nResults saved to:")
        print(f"  - {base_filename}.json (raw data)")
        
        if args.output == "text" or args.output == "all":
            print(f"  - {base_filename}.txt (text report)")
        
        if args.output == "html" or args.output == "all":
            print(f"  - {base_filename}.html (HTML report)")
        
        if args.output == "csv" or args.output == "all":
            print(f"  - {base_filename}_findings.csv (CSV findings)")
        
    except Exception as e:
        logger.error(f"Error analyzing target: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    try:
        # Check for required packages and install if missing
        try:
            import tqdm
        except ImportError:
            print("Installing required package: tqdm")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "tqdm"])
            try:
                import tqdm
                print("Successfully installed tqdm")
            except ImportError:
                print("Note: tqdm package could not be installed. Basic progress reporting will be used.")
        
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
