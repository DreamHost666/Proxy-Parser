#!/usr/bin/env python3
"""
Advanced Proxy Parser - Professional Edition
"""

import argparse
import concurrent.futures
import ipaddress
import json
import logging
import os
import random
import re
import socket
import sys
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

PROXY_SOURCES = [
    # Основные источники
    "https://proxy-list.org/english/index.php",
    "https://www.free-proxy-list.net/",
    "https://www.us-proxy.org/",
    
    # GitHub источники
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt",
    
    # Дополнительные источники (20+)
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTP_RAW.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/Volodichev/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
]

class ProxyChecker:
    """Класс для проверки и геолокации прокси"""
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.session = self._create_session()
        self.geo_cache: Dict[str, str] = {}
        self.test_urls = [
            "http://httpbin.org/get",
            "http://example.com",
            "http://google.com"
        ]
    
    def _create_session(self) -> requests.Session:
        """Создает настроенную сессию requests"""
        session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        return session
    
    def get_proxy_info(self, proxy_ip: str) -> Optional[Dict]:
        """Получает информацию о геолокации прокси"""
        if proxy_ip in self.geo_cache:
            return self.geo_cache[proxy_ip]
        
        try:
            response = self.session.get(
                f"http://ip-api.com/json/{proxy_ip}?fields=status,message,country,countryCode,city,isp,org",
                timeout=self.timeout
            )
            data = response.json()
            if data.get('status') == 'success':
                self.geo_cache[proxy_ip] = data
                return data
        except Exception as e:
            logger.debug(f"Geo lookup failed for {proxy_ip}: {str(e)}")
        
        return None
    
    def check_proxy(self, proxy: str, protocol: str) -> Tuple[bool, float, Optional[Dict]]:
        """Проверяет работоспособность прокси"""
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
                proxies = {protocol: f"{protocol}://{proxy}"}
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
            
        except Exception as e:
            logger.debug(f"Proxy {proxy} failed ({protocol}): {str(e)}")
            return False, 0.0, None

class ProxyParser:
    """Основной класс парсера прокси"""
    
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
        """Парсит прокси из одного источника"""
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            proxies = set()
            
            for line in response.text.splitlines():
                if match := re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):?(\d{1,5})?', line.strip()):
                    ip, port = match.groups()
                    proxies.add(f"{ip}:{port or '8080'}")
            
            return proxies
        except Exception as e:
            logger.warning(f"Failed to parse {url}: {str(e)}")
            return set()
    
    def run(self):
        """Запускает процесс парсинга и проверки"""
        logger.info("Starting proxy collection...")
        
        # Сбор прокси
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.max_workers) as executor:
            futures = [executor.submit(self._parse_source, url) for url in PROXY_SOURCES]
            for future in concurrent.futures.as_completed(futures):
                self.raw_proxies.update(future.result())
        
        self.stats['total'] = len(self.raw_proxies)
        logger.info(f"Collected {self.stats['total']} proxies. Starting verification...")
        
        # Проверка прокси
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.max_workers) as executor:
            executor.map(self._process_proxy, self.raw_proxies)
        
        # Сохранение результатов
        self._save_results()
        
        # Вывод статистики
        self._print_stats()
    
    def _process_proxy(self, proxy: str):
        """Обрабатывает один прокси"""
        protocols = self.args.protocols or ['http', 'https', 'socks4', 'socks5']
        
        for protocol in protocols:
            success, latency, geo_info = self.checker.check_proxy(proxy, protocol)
            if success and geo_info:
                with threading.Lock():
                    self._add_valid_proxy(proxy, protocol, latency, geo_info)
    
    def _add_valid_proxy(self, proxy: str, protocol: str, latency: float, geo_info: Dict):
        """Добавляет валидный прокси в список"""
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
            self.valid_proxies.append(proxy_data)
            self._update_stats(proxy_data)
    
    def _should_include(self, proxy_info: Dict) -> bool:
        """Проверяет соответствие прокси фильтрам"""
        if self.args.countries and proxy_info.get('countryCode') not in self.args.countries:
            return False
        if self.args.protocols and proxy_info.get('protocol') not in self.args.protocols:
            return False
        return True
    
    def _update_stats(self, proxy_data: Dict):
        """Обновляет статистику"""
        self.stats['valid'] += 1
        country = proxy_data['countryCode']
        protocol = proxy_data['protocol']
        self.stats['countries'][country] = self.stats['countries'].get(country, 0) + 1
        self.stats['protocols'][protocol] = self.stats['protocols'].get(protocol, 0) + 1
    
    def _save_results(self):
        """Сохраняет результаты в файл"""
        sorted_proxies = sorted(self.valid_proxies, key=lambda x: x['latency'])[:self.args.limit]
        
        with open(self.args.output, 'w', encoding='utf-8') as f:
            if self.args.format == 'json':
                json.dump(sorted_proxies, f, indent=2)
            else:
                for proxy in sorted_proxies:
                    f.write(f"{proxy['address']}|{proxy['protocol']}|{proxy['countryCode']}|{proxy['latency']}ms\n")
        
        logger.info(f"Saved {len(sorted_proxies)} proxies to {self.args.output}")
    
    def _print_stats(self):
        """Выводит статистику"""
        logger.info("\n=== Statistics ===")
        logger.info(f"Total proxies checked: {self.stats['total']}")
        logger.info(f"Valid working proxies: {self.stats['valid']}")
        
        logger.info("\nBy country:")
        for country, count in sorted(self.stats['countries'].items(), key=lambda x: x[1], reverse=True):
            logger.info(f"  {country}: {count}")
        
        logger.info("\nBy protocol:")
        for proto, count in sorted(self.stats['protocols'].items(), key=lambda x: x[1], reverse=True):
            logger.info(f"  {proto}: {count}")

def parse_args():
    """Парсит аргументы командной строки"""
    parser = argparse.ArgumentParser(description='Advanced Proxy Parser')
    parser.add_argument('--max-workers', type=int, default=100,
                       help='Number of concurrent workers')
    parser.add_argument('--timeout', type=float, default=10.0,
                       help='Proxy check timeout in seconds')
    parser.add_argument('--output', type=str, default='proxies.txt',
                       help='Output file path')
    parser.add_argument('--format', choices=['txt', 'json'], default='txt',
                       help='Output file format')
    parser.add_argument('--countries', type=str, nargs='+',
                       help='Filter by country codes (e.g. US DE FR)')
    parser.add_argument('--protocols', type=str, nargs='+',
                       choices=['http', 'https', 'socks4', 'socks5'],
                       help='Filter by protocols')
    parser.add_argument('--limit', type=int, default=5000,
                       help='Maximum number of proxies to save')
    return parser.parse_args()

def main():
    """Точка входа"""
    args = parse_args()
    parser = ProxyParser(args)
    parser.run()

if __name__ == '__main__':
    main()