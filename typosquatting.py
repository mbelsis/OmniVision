#!/usr/bin/env python3
import asyncio
import whois
from datetime import datetime, timedelta
import logging
import socket
from typing import List, Dict, Optional
from itertools import product
import dns.resolver
import re
import time

logger = logging.getLogger(__name__)

def generate_variations(domain: str) -> List[str]:
    """Generate possible typosquatting variations of a domain."""
    try:
        name, tld = domain.split('.', 1)
    except ValueError:
        logger.error(f"Invalid domain format: {domain}")
        return []
        
    variations = set()

    # 1. Character substitution (common look-alikes)
    substitutions = {
        'a': ['4', '@'],
        'b': ['8', '6'],
        'c': ['('],
        'e': ['3'],
        'g': ['6', '9'],
        'i': ['1', '!'],
        'l': ['1', '|'],
        'm': ['nn'],
        'o': ['0'],
        's': ['5', '$'],
        't': ['7'],
        'u': ['v'],
        'v': ['u', 'w'],
        'w': ['vv'],
        'z': ['2', 's']
    }

    # 2. Common TLD variations - reduced list to avoid too many checks
    common_tlds = [
        'com', 'net', 'org', 'info'
    ]

    # Character substitutions - limit to first 3 characters to reduce load
    for i, char in enumerate(name[:3]):
        if char.lower() in substitutions:
            for sub in substitutions[char.lower()]:
                new_name = name[:i] + sub + name[i+1:]
                variations.add(f"{new_name}.{tld}")

    # 3. Keyboard proximity typos (QWERTY layout) - limit to first 3 characters
    keyboard_map = {
        'a': 'qwsz', 'b': 'vghn', 'c': 'xdfv', 'd': 'srfec', 'e': 'wrsdf',
        'f': 'drtgc', 'g': 'ftyhv', 'h': 'gyujb', 'i': 'ujko', 'j': 'huikn',
        'k': 'jiol', 'l': 'kop', 'm': 'njk', 'n': 'bhjm', 'o': 'iklp',
        'p': 'ol', 'q': 'wa', 'r': 'edft', 's': 'awdxz', 't': 'rfgy',
        'u': 'yhji', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc', 'y': 'tghu',
        'z': 'asx'
    }

    # Generate keyboard proximity variations - limit to first 3 characters
    for i, char in enumerate(name[:3].lower()):
        if char in keyboard_map:
            for adjacent in keyboard_map[char]:
                new_name = name[:i] + adjacent + name[i+1:]
                variations.add(f"{new_name}.{tld}")

    # 4. Common prefixes and suffixes - use only a few to reduce load
    prefixes = ['my', 'get']
    suffixes = ['app', 'site']

    for prefix in prefixes:
        variations.add(f"{prefix}{name}.{tld}")
    
    for suffix in suffixes:
        variations.add(f"{name}{suffix}.{tld}")

    # 5. Common TLD variations - limit to a few
    for new_tld in common_tlds[:2]:
        if new_tld != tld:
            variations.add(f"{name}.{new_tld}")

    # Limit the number of variations to avoid too many concurrent requests
    return list(variations)[:20]  # Limit to 20 variations

async def check_domain_age(domain: str) -> Optional[Dict]:
    """Check if a domain exists and when it was registered."""
    try:
        # Add timeout to DNS resolution
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.0
            await asyncio.get_event_loop().run_in_executor(
                None, 
                lambda: resolver.resolve(domain, 'A')
            )
        except (dns.exception.DNSException, asyncio.TimeoutError):
            return None

        # Add retry logic and timeout for WHOIS
        retries = 2
        for attempt in range(retries):
            try:
                # Use a timeout for the WHOIS query
                w = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(None, whois.whois, domain),
                    timeout=3.0
                )
                
                if w.creation_date is None:
                    return None

                # Handle both single creation date and list of dates
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                
                return {
                    'domain': domain,
                    'creation_date': creation_date,
                    'registrar': w.registrar,
                    'name_servers': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else []
                }
            except asyncio.TimeoutError:
                if attempt < retries - 1:
                    # Wait before retrying
                    await asyncio.sleep(1)
                    continue
                return None
            except Exception as e:
                logger.debug(f"Error checking domain {domain}: {str(e)}")
                return None
    except Exception as e:
        logger.debug(f"Error checking domain {domain}: {str(e)}")
        return None

async def find_similar_domains(domain: str, max_age_days: int = 30) -> List[Dict]:
    """Find recently registered domains that are similar to the target domain."""
    variations = generate_variations(domain)
    tasks = []
    
    # Create tasks for domain variations with rate limiting
    for i, var in enumerate(variations):
        # Add a small delay between task creation to avoid overwhelming connections
        if i > 0 and i % 5 == 0:
            await asyncio.sleep(1)
        tasks.append(check_domain_age(var))
    
    # Run checks with a semaphore to limit concurrency
    semaphore = asyncio.Semaphore(5)  # Limit to 5 concurrent requests
    
    async def check_with_semaphore(domain_var):
        async with semaphore:
            return await check_domain_age(domain_var)
    
    # Create tasks with semaphore
    limited_tasks = [check_with_semaphore(var) for var in variations]
    
    # Run all checks with timeout
    try:
        results = await asyncio.wait_for(asyncio.gather(*limited_tasks, return_exceptions=True), timeout=30)
    except asyncio.TimeoutError:
        logger.warning("Typosquatting check timed out after 30 seconds")
        results = []
    
    # Filter results
    recent_domains = []
    cutoff_date = datetime.now() - timedelta(days=max_age_days)
    
    for result in results:
        if isinstance(result, Exception):
            continue
        if result and isinstance(result.get('creation_date'), datetime):
            if result['creation_date'] > cutoff_date:
                recent_domains.append(result)
    
    return recent_domains

def format_typosquatting_report(findings: List[Dict]) -> str:
    """Format typosquatting findings into a readable report."""
    if not findings:
        return "No suspicious similar domains found in the specified timeframe."
    
    output = []
    output.append("\nTYPOSQUATTING DETECTION RESULTS")
    output.append("=" * 30)
    
    for finding in findings:
        output.append(f"\nDomain: {finding['domain']}")
        output.append(f"Registration Date: {finding['creation_date'].strftime('%Y-%m-%d')}")
        output.append(f"Registrar: {finding['registrar']}")
        if finding['name_servers']:
            output.append(f"Name Servers: {', '.join(finding['name_servers'])}")
        output.append("-" * 30)
    
    return "\n".join(output)
