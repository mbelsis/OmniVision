"""Cloud Asset Discovery Module"""
import asyncio
import aiohttp
from typing import Dict, List
import logging
import re

logger = logging.getLogger(__name__)

async def check_cloud_exposure(domain: str) -> Dict:
    """Check for exposed cloud assets and misconfigurations."""
    results = {
        'cloud_assets': {
            'github': [],
            's3_buckets': [],
            'azure_blobs': [],
            'gcp_storage': []
        },
        'findings': []
    }
    
    # Common cloud storage patterns
    patterns = {
        's3_buckets': [
            f'https://{domain}.s3.amazonaws.com',
            f'https://s3.amazonaws.com/{domain}',
        ],
        'azure_blobs': [
            f'https://{domain}.blob.core.windows.net',
        ],
        'gcp_storage': [
            f'https://storage.googleapis.com/{domain}',
        ]
    }
    
    async def check_url(url: str) -> tuple:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(url, allow_redirects=True) as response:
                    return url, response.status
        except:
            return url, None

    # Check GitHub organization
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f'https://api.github.com/orgs/{domain}') as response:
                if response.status == 200:
                    data = await response.json()
                    results['cloud_assets']['github'].append({
                        'type': 'organization',
                        'url': data.get('html_url'),
                        'public_repos': data.get('public_repos', 0)
                    })
                    if data.get('public_repos', 0) > 0:
                        results['findings'].append({
                            'severity': 'INFO',
                            'category': 'Source Code Exposure',
                            'finding': f'Found {data["public_repos"]} public repositories on GitHub'
                        })
    except Exception as e:
        logger.debug(f"Error checking GitHub: {str(e)}")

    # Check for exposed cloud storage
    tasks = []
    for storage_type, urls in patterns.items():
        for url in urls:
            tasks.append(check_url(url))
    
    responses = await asyncio.gather(*tasks)
    
    for url, status in responses:
        if status in [200, 403]:  # 403 often means the bucket exists but is not public
            storage_type = next((k for k, v in patterns.items() if any(url.startswith(p) for p in v)), None)
            if storage_type:
                results['cloud_assets'][storage_type].append(url)
                results['findings'].append({
                    'severity': 'MEDIUM',
                    'category': 'Cloud Storage',
                    'finding': f'Found potentially exposed {storage_type}: {url}'
                })

    return results
