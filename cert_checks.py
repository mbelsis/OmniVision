"""Certificate Transparency Log Monitoring"""
import asyncio
import aiohttp
from typing import Dict, List
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

async def check_certificate_logs(domain: str) -> Dict:
    """Check Certificate Transparency logs for recently issued certificates."""
    results = {
        'certificates': [],
        'findings': []
    }
    
    # Use crt.sh API
    try:
        async with aiohttp.ClientSession() as session:
            url = f'https://crt.sh/?q=%.{domain}&output=json'
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Process certificates
                    seen_certs = set()
                    recent_certs = []
                    
                    for cert in data:
                        cert_id = cert.get('id')
                        if cert_id not in seen_certs:
                            seen_certs.add(cert_id)
                            
                            entry = {
                                'issuer': cert.get('issuer_name'),
                                'name': cert.get('name_value'),
                                'date': cert.get('entry_timestamp')
                            }
                            
                            # Check if certificate was issued recently (last 30 days)
                            try:
                                cert_date = datetime.strptime(cert['entry_timestamp'], '%Y-%m-%d %H:%M:%S.%f %Z')
                                if datetime.now() - cert_date <= timedelta(days=30):
                                    recent_certs.append(entry)
                            except:
                                pass
                            
                            results['certificates'].append(entry)
                    
                    # Add findings
                    if recent_certs:
                        results['findings'].append({
                            'severity': 'INFO',
                            'category': 'Certificate Monitoring',
                            'finding': f'Found {len(recent_certs)} certificates issued in the last 30 days'
                        })
                        
                        # Check for potentially suspicious certificates
                        for cert in recent_certs:
                            name = cert.get('name', '').lower()
                            if any(s in name for s in ['test', 'dev', 'stage', 'uat']):
                                results['findings'].append({
                                    'severity': 'MEDIUM',
                                    'category': 'Certificate Monitoring',
                                    'finding': f'Found potentially non-production certificate: {name}'
                                })
    
    except Exception as e:
        logger.error(f"Error checking certificate logs: {str(e)}")
        results['error'] = str(e)
    
    return results
