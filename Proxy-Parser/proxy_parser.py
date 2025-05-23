#!/usr/bin/env python3
"""
Advanced Proxy Parser - Optimized Version
"""

import argparse
import concurrent.futures
import ipaddress
import json
import logging
import random
import re
import socket
import time
import threading
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple, Optional

import requests
from socks import PROXY_TYPES, socksocket
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy_parser.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Updated and verified proxy sources
PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/Volodichev/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/proxies.txt",
]

class ProxyChecker:
    """Handles proxy verification with connection pool optimization"""
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.session = self._create_session()
        self.geo_cache: Dict[str, str] = {}
        self.test_urls = [
            "http://httpbin.org/get",
            "http://example.com",
            "http://google.com"
        ]
        self.geo_service_url = "http://ip-api.com/json/{}?fields=status,message,country,countryCode,city,isp,org"
    
    def _create_session(self) -> requests.Session:
        """Create configured requests session with optimized connection pool"""
        session = requests.Session()
        
        # Increase connection pool size
        adapter = HTTPAdapter(
            pool_connections=30,
            pool_maxsize=30,
            max_retries=Retry(
                total=3,
                backoff_factor=0.5,
                status_forcelist=[500, 502, 503, 504]
            )
        )
        
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        return session
    
    def get_proxy_info(self, proxy_ip: str) -> Optional[Dict]:
        """Get proxy geolocation info with rate limiting"""
        if proxy_ip in self.geo_cache:
            return self.geo_cache[proxy_ip]
        
        try:
            # Add small delay to avoid overloading the service
            time.sleep(0.1)
            
            response = self.session.get(
                self.geo_service_url.format(proxy_ip),
                timeout=self.timeout
            )
            data = response.json()
            if data.get('status') == 'success':
                self.geo_cache[proxy_ip] = data
                return data
        except Exception as e:
            logger.debug(f"Geo lookup failed for {proxy_ip}: {str(e)}")
        
        return None
    
    def check_proxy(
        self,
        proxy: str,
        protocol: str,
    ) -> Tuple[bool, float, Optional[Dict]]:
        """Check if proxy is working with improved error handling"""
        start_time = time.time()
        proxy_ip = proxy.split(':')[0]
        test_url = random.choice(self.test_urls)
        
        try:
            if protocol.lower() in ['socks4', 'socks5']:
                sock = socksocket()
                sock.set_proxy(
                    proxy_type=PROXY_TYPES[protocol.upper()],
                    addr=proxy_ip,
                    port=int(proxy.split(':')[1]),
                    rdns=True
                )
                sock.settimeout(self.timeout)
                host = test_url.split('//')[1].split('/')[0]
                sock.connect((host, 80))
                sock.close()
            else:
                proxies = {
                    'http': f"{protocol}://{proxy}",
                    'https': f"{protocol}://{proxy}"
                }
                response = requests.get(
                    test_url,
                    proxies=proxies,
                    timeout=self.timeout,
                    stream=True
                )
                response.raise_for_status()
                response.close()
            
            latency = round((time.time() - start_time) * 1000, 2)
            geo_info = self.get_proxy_info(proxy_ip)
            return True, latency, geo_info
            
        except (socket.timeout, Exception) as e:
            logger.debug(f"Proxy {proxy} failed ({protocol}): {str(e)}")
            return False, 0.0, None

class ProxyParser:
    """Main proxy parsing and processing class with source validation"""
    
    def __init__(self, args):
        self.args = args
        self.checker = ProxyChecker(timeout=args.timeout)
        self.raw_proxies: Set[str] = set()
        self.valid_proxies: List[Dict] = []
        self.stats = {
            'total': 0,
            'valid': 0,
            'countries': {},
            'protocols': {}
        }
    
    def _parse_source(self, url: str) -> Set[str]:
        """Parse proxies from single source with better error handling"""
        try:
            # Skip known problematic sources
            if "roosterkid" in url:
                return set()
                
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            proxies = set()
            
            # Handle different proxy list formats
            for line in response.text.splitlines():
                line = line.strip()
                if match := re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):?(\d{1,5})?', line):
                    ip = match.group(1)
                    port = match.group(2) or str(random.randint(1000, 9999))
                    proxies.add(f"{ip}:{port}")
            
            return proxies
        except Exception as e:
            logger.warning(f"Failed to parse {url}: {str(e)}")
            return set()
    
    def run(self) -> None:
        """Main execution flow with optimized verification"""
        logger.info("Starting proxy collection from %d sources...", len(PROXY_SOURCES))
        
        # Step 1: Collect raw proxies
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.max_workers) as executor:
            futures = [executor.submit(self._parse_source, url) for url in PROXY_SOURCES]
            for future in concurrent.futures.as_completed(futures):
                self.raw_proxies.update(future.result())
        
        self.stats['total'] = len(self.raw_proxies)
        logger.info(f"Collected {self.stats['total']} raw proxies. Starting verification...")
        
        # Step 2: Verify proxies with limited concurrency for geo checks
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.args.max_workers, 20)) as executor:
            executor.map(self._process_proxy, self.raw_proxies)
        
        # Step 3: Save results
        self._save_results()
        
        # Print summary
        self._print_stats()
    
    def _process_proxy(self, proxy: str) -> None:
        """Check and process single proxy"""
        protocols = self.args.protocols or ['http', 'https', 'socks4', 'socks5']
        
        for protocol in protocols:
            success, latency, geo_info = self.checker.check_proxy(proxy, protocol)
            
            if success and geo_info:
                proxy_data = {
                    'address': proxy,
                    'protocol': protocol,
                    'latency': latency,
                    'country': geo_info.get('country', 'Unknown'),
                    'countryCode': geo_info.get('countryCode', 'XX'),
                    'city': geo_info.get('city', 'Unknown'),
                    'isp': geo_info.get('isp', 'Unknown'),
                    'last_checked': datetime.now(timezone.utc).isoformat()
                }
                
                if self._should_include(proxy_data):
                    with threading.Lock():
                        self.valid_proxies.append(proxy_data)
                        self._update_stats(proxy_data)
    
    def _should_include(self, proxy_info: Dict) -> bool:
        """Check if proxy matches filters"""
        if self.args.countries and proxy_info.get('countryCode') not in self.args.countries:
            return False
        if self.args.protocols and proxy_info.get('protocol') not in self.args.protocols:
            return False
        return True
    
    def _update_stats(self, proxy_data: Dict) -> None:
        """Update statistics counters"""
        self.stats['valid'] += 1
        country = proxy_data['countryCode']
        protocol = proxy_data['protocol']
        self.stats['countries'][country] = self.stats['countries'].get(country, 0) + 1
        self.stats['protocols'][protocol] = self.stats['protocols'].get(protocol, 0) + 1
    
    def _save_results(self) -> None:
        """Save results to output file"""
        sorted_proxies = sorted(
            self.valid_proxies,
            key=lambda x: x['latency']
        )[:self.args.limit]
        
        with open(self.args.output, 'w', encoding='utf-8') as f:
            if self.args.format == 'json':
                json.dump(sorted_proxies, f, indent=2)
            else:
                for proxy in sorted_proxies:
                    line = f"{proxy['address']}|{proxy['protocol']}|{proxy['countryCode']}|{proxy['latency']}ms"
                    f.write(f"{line}\n")
        
        logger.info(f"Saved {len(sorted_proxies)} proxies to {self.args.output}")
    
    def _print_stats(self) -> None:
        """Print detailed statistics"""
        logger.info("\n=== Statistics ===")
        logger.info(f"Total proxies checked: {self.stats['total']}")
        logger.info(f"Valid working proxies: {self.stats['valid']}")
        
        logger.info("\nBy country (top 10):")
        for country, count in sorted(self.stats['countries'].items(), 
                                   key=lambda x: x[1], reverse=True)[:10]:
            logger.info(f"  {country}: {count}")
        
        logger.info("\nBy protocol:")
        for proto, count in sorted(self.stats['protocols'].items(), 
                                  key=lambda x: x[1], reverse=True):
            logger.info(f"  {proto}: {count}")

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Advanced Proxy Parser')
    parser.add_argument('--max-workers', type=int, default=50,
                       help='Number of concurrent workers (default: 50)')
    parser.add_argument('--timeout', type=float, default=10.0,
                       help='Proxy check timeout in seconds (default: 10)')
    parser.add_argument('--output', type=str, default='proxies.txt',
                       help='Output file path (default: proxies.txt)')
    parser.add_argument('--format', choices=['txt', 'json'], default='txt',
                       help='Output file format (default: txt)')
    parser.add_argument('--countries', type=str, nargs='+',
                       help='Filter by country codes (e.g. US DE FR)')
    parser.add_argument('--protocols', type=str, nargs='+',
                       choices=['http', 'https', 'socks4', 'socks5'],
                       help='Filter by protocols')
    parser.add_argument('--limit', type=int, default=5000,
                       help='Maximum number of proxies to save (default: 5000)')
    return parser.parse_args()

def main():
    """Entry point"""
    args = parse_args()
    parser = ProxyParser(args)
    parser.run()

if __name__ == '__main__':
    main()
