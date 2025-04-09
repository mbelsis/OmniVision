import asyncio
import logging
import ssl
import socket
from typing import Dict, List, Optional
import dns.resolver
import requests

logger = logging.getLogger(__name__)

async def find_origin_ip(domain: str) -> Dict:
    """Attempt to find the origin IP behind Cloudflare."""
    results = {
        'origin_found': False,
        'methods_tried': [],
        'potential_ips': set(),
        'findings': []
    }
    
    # Method 1: Historical DNS records
    try:
        results['methods_tried'].append('historical_dns')
        historical_ips = await check_historical_dns(domain)
        if historical_ips:
            results['potential_ips'].update(historical_ips)
            results['findings'].append({
                'severity': 'MEDIUM',
                'category': 'CDN Bypass',
                'finding': f'Found {len(historical_ips)} historical IPs that might be origin servers'
            })
    except Exception as e:
        logger.error(f"Error checking historical DNS: {str(e)}")

    # Method 2: SSL/TLS certificate check
    try:
        results['methods_tried'].append('ssl_certificate')
        cert_ips = await check_ssl_certificate(domain)
        if cert_ips:
            results['potential_ips'].update(cert_ips)
            results['findings'].append({
                'severity': 'HIGH',
                'category': 'CDN Bypass',
                'finding': f'Found {len(cert_ips)} IPs in SSL certificates that might expose origin'
            })
    except Exception as e:
        logger.error(f"Error checking SSL certificates: {str(e)}")

    # Method 3: Check Cloudflare security headers
    try:
        results['methods_tried'].append('security_headers')
        header_findings = await check_cloudflare_headers(domain)
        results['findings'].extend(header_findings)
    except Exception as e:
        logger.error(f"Error checking Cloudflare headers: {str(e)}")

    # Convert potential_ips set to list for JSON serialization
    results['potential_ips'] = list(results['potential_ips'])
    results['origin_found'] = len(results['potential_ips']) > 0

    return results

async def check_historical_dns(domain: str) -> set:
    """Check historical DNS records for potential origin IPs."""
    potential_ips = set()
    
    # Try to get historical DNS records from various sources
    try:
        # Example: Query SecurityTrails API (you would need an API key)
        # This is a placeholder - implement actual API call
        pass
    except Exception:
        pass

    return potential_ips

async def check_ssl_certificate(domain: str) -> set:
    """Check SSL certificates for potential origin IPs."""
    potential_ips = set()
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert and 'subjectAltName' in cert:
                    for type_name, alt_name in cert['subjectAltName']:
                        if type_name == 'IP Address':
                            potential_ips.add(alt_name)
    except Exception as e:
        logger.error(f"Error checking SSL certificate: {str(e)}")

    return potential_ips

async def check_cloudflare_headers(domain: str) -> List[Dict]:
    """Check Cloudflare security headers and common misconfigurations."""
    findings = []
    
    try:
        response = requests.get(f'https://{domain}', headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
        headers = response.headers
        
        # Check for missing security headers
        if 'cf-ray' in headers:  # Confirm it's behind Cloudflare
            if 'X-Frame-Options' not in headers:
                findings.append({
                    'severity': 'MEDIUM',
                    'category': 'Cloudflare Security',
                    'finding': 'Missing X-Frame-Options header, potential clickjacking risk'
                })
            
            if 'Strict-Transport-Security' not in headers:
                findings.append({
                    'severity': 'HIGH',
                    'category': 'Cloudflare Security',
                    'finding': 'HSTS not enabled, potential SSL/TLS downgrade risk'
                })
            
            # Check Cloudflare security level
            if 'Server' in headers and 'cloudflare' in headers['Server'].lower():
                security_level = headers.get('CF-RAY', '').split('-')[-1]
                if security_level == '1':
                    findings.append({
                        'severity': 'HIGH',
                        'category': 'Cloudflare Security',
                        'finding': 'Cloudflare security level set to Low'
                    })
    
    except Exception as e:
        logger.error(f"Error checking Cloudflare headers: {str(e)}")
    
    return findings
