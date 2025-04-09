"""DNS and Email Security Checks Module"""
import dns.resolver
import dns.exception
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)

async def check_dns_security(domain: str) -> Dict:
    """Check DNS security configurations including SPF, DMARC, and DKIM."""
    results = {
        'spf': {'exists': False, 'record': None},
        'dmarc': {'exists': False, 'record': None},
        'mx': {'exists': False, 'records': []},
        'txt': [],
        'ns': [],
        'findings': []
    }
    
    try:
        # Check SPF
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for record in txt_records:
                txt = record.to_text()
                results['txt'].append(txt)
                if 'v=spf1' in txt:
                    results['spf']['exists'] = True
                    results['spf']['record'] = txt
                    if '-all' not in txt and '~all' not in txt:
                        results['findings'].append({
                            'severity': 'MEDIUM',
                            'category': 'Email Security',
                            'finding': 'SPF record exists but does not end with a strict or soft fail directive'
                        })
        except dns.exception.DNSException:
            results['findings'].append({
                'severity': 'HIGH',
                'category': 'Email Security',
                'finding': 'No SPF record found'
            })

        # Check DMARC
        try:
            dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for record in dmarc_records:
                txt = record.to_text()
                if 'v=DMARC1' in txt:
                    results['dmarc']['exists'] = True
                    results['dmarc']['record'] = txt
                    if 'p=none' in txt:
                        results['findings'].append({
                            'severity': 'MEDIUM',
                            'category': 'Email Security',
                            'finding': 'DMARC policy set to none - no enforcement'
                        })
        except dns.exception.DNSException:
            results['findings'].append({
                'severity': 'HIGH',
                'category': 'Email Security',
                'finding': 'No DMARC record found'
            })

        # Check MX Records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            results['mx']['exists'] = True
            results['mx']['records'] = [str(mx.exchange) for mx in mx_records]
        except dns.exception.DNSException:
            if not results['mx']['exists']:
                results['findings'].append({
                    'severity': 'INFO',
                    'category': 'Email Configuration',
                    'finding': 'No MX records found - domain might not handle email'
                })

        # Check NS Records
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            results['ns'] = [str(ns) for ns in ns_records]
            if len(results['ns']) < 2:
                results['findings'].append({
                    'severity': 'MEDIUM',
                    'category': 'DNS Configuration',
                    'finding': 'Less than 2 nameservers found - potential single point of failure'
                })
        except dns.exception.DNSException:
            results['findings'].append({
                'severity': 'HIGH',
                'category': 'DNS Configuration',
                'finding': 'Unable to retrieve nameserver information'
            })

    except Exception as e:
        logger.error(f"Error checking DNS security: {str(e)}")
        results['error'] = str(e)

    return results
