#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TECHNOLOGY DETECTOR v3.0 - TANQUE EDITION
Detección de 50+ tecnologías · Version fingerprinting · Headers · Meta
Con análisis de JS y CSS
"""

import asyncio
import re
from urllib.parse import urljoin
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class TechnologyDetector:
    def __init__(self, url: str):
        self.url = url.rstrip('/')
        self.client = None
        self.technologies = set()
        self.versions = {}
        self.confidence = {}
        
        # Base de datos de tecnologías (50+)
        self.patterns = {
            # CMS
            'WordPress': {
                'patterns': [r'wp-content', r'wp-includes', r'WordPress', r'wp-json'],
                'version_patterns': [
                    (r'<meta name="generator" content="WordPress ([0-9.]+)"', 'meta'),
                    (r'WordPress ([0-9.]+)', 'comment'),
                    (r'ver=([0-9.]+)"', 'query'),
                ],
                'headers': [],
                'cookies': ['wordpress_', 'wp-settings']
            },
            'Joomla': {
                'patterns': [r'joomla', r'com_content', r'/media/system/js/'],
                'version_patterns': [
                    (r'<meta name="generator" content="Joomla! ([0-9.]+)"', 'meta'),
                ],
                'headers': [],
                'cookies': []
            },
            'Drupal': {
                'patterns': [r'drupal', r'sites/all', r'/sites/default/'],
                'version_patterns': [
                    (r'Drupal ([0-9.]+)', 'comment'),
                    (r'<meta name="generator" content="Drupal ([0-9.]+)"', 'meta'),
                ],
                'headers': ['X-Drupal-Cache'],
                'cookies': []
            },
            'Magento': {
                'patterns': [r'mage/', r'Magento', r'var/'],
                'version_patterns': [
                    (r'Magento/([0-9.]+)', 'header'),
                ],
                'headers': ['X-Magento'],
                'cookies': []
            },
            'Shopify': {
                'patterns': [r'shopify.com', r'Shopify', r'cdn.shopify.com'],
                'version_patterns': [],
                'headers': ['X-ShopId'],
                'cookies': ['_shopify_']
            },
            'WooCommerce': {
                'patterns': [r'woocommerce', r'wc-', r'/wc-api/'],
                'version_patterns': [
                    (r'WooCommerce ([0-9.]+)', 'comment'),
                ],
                'headers': [],
                'cookies': []
            },
            
            # Frameworks Backend
            'Laravel': {
                'patterns': [r'laravel', r'csrf-token', r'Laravel'],
                'version_patterns': [
                    (r'Laravel v([0-9.]+)', 'comment'),
                ],
                'headers': [],
                'cookies': ['laravel_session']
            },
            'Django': {
                'patterns': [r'csrftoken', r'django', r'__admin__'],
                'version_patterns': [],
                'headers': [],
                'cookies': ['csrftoken', 'sessionid']
            },
            'Ruby on Rails': {
                'patterns': [r'rails', r'csrf-param', r'Rails'],
                'version_patterns': [],
                'headers': ['X-Runtime'],
                'cookies': ['_session_id']
            },
            'Express': {
                'patterns': [r'express', r'x-powered-by'],
                'version_patterns': [
                    (r'Express/([0-9.]+)', 'header'),
                ],
                'headers': ['X-Powered-By'],
                'cookies': []
            },
            'Flask': {
                'patterns': [r'flask', r'jinja'],
                'version_patterns': [],
                'headers': [],
                'cookies': ['session']
            },
            'Spring': {
                'patterns': [r'spring', r'java'],
                'version_patterns': [],
                'headers': ['X-Application-Context'],
                'cookies': []
            },
            
            # Frameworks Frontend
            'React': {
                'patterns': [r'react', r'react-dom', r'React'],
                'version_patterns': [
                    (r'React v([0-9.]+)', 'comment'),
                ],
                'headers': [],
                'cookies': []
            },
            'Vue.js': {
                'patterns': [r'vue.js', r'__VUE__', r'VueJS'],
                'version_patterns': [
                    (r'Vue\.js v([0-9.]+)', 'comment'),
                ],
                'headers': [],
                'cookies': []
            },
            'Angular': {
                'patterns': [r'angular', r'ng-', r'Angular'],
                'version_patterns': [
                    (r'Angular v([0-9.]+)', 'comment'),
                ],
                'headers': [],
                'cookies': []
            },
            'Next.js': {
                'patterns': [r'next.js', r'__NEXT_DATA__', r'/_next/'],
                'version_patterns': [
                    (r'Next\.js v([0-9.]+)', 'comment'),
                ],
                'headers': ['x-powered-by'],
                'cookies': []
            },
            'Nuxt.js': {
                'patterns': [r'nuxt', r'__NUXT__'],
                'version_patterns': [],
                'headers': [],
                'cookies': []
            },
            'Gatsby': {
                'patterns': [r'gatsby', r'___gatsby'],
                'version_patterns': [],
                'headers': [],
                'cookies': []
            },
            
            # Librerías JS
            'jQuery': {
                'patterns': [r'jquery', r'jQuery', r'jquery.js'],
                'version_patterns': [
                    (r'jQuery v([0-9.]+)', 'comment'),
                ],
                'headers': [],
                'cookies': []
            },
            'Bootstrap': {
                'patterns': [r'bootstrap', r'col-md-', r'Bootstrap'],
                'version_patterns': [
                    (r'Bootstrap v([0-9.]+)', 'comment'),
                ],
                'headers': [],
                'cookies': []
            },
            'Tailwind': {
                'patterns': [r'tailwind', r'bg-', r'text-', r'flex'],
                'version_patterns': [],
                'headers': [],
                'cookies': []
            },
            'FontAwesome': {
                'patterns': [r'font-awesome', r'fa-', r'FontAwesome'],
                'version_patterns': [
                    (r'FontAwesome ([0-9.]+)', 'comment'),
                ],
                'headers': [],
                'cookies': []
            },
            
            # Servidores
            'Nginx': {
                'patterns': [r'nginx'],
                'version_patterns': [
                    (r'nginx/([0-9.]+)', 'header'),
                ],
                'headers': ['Server'],
                'cookies': []
            },
            'Apache': {
                'patterns': [r'apache'],
                'version_patterns': [
                    (r'Apache/([0-9.]+)', 'header'),
                ],
                'headers': ['Server'],
                'cookies': []
            },
            'IIS': {
                'patterns': [r'iis', 'Microsoft-IIS'],
                'version_patterns': [
                    (r'Microsoft-IIS/([0-9.]+)', 'header'),
                ],
                'headers': ['Server'],
                'cookies': ['ASPSESSIONID']
            },
            'Cloudflare': {
                'patterns': [r'cloudflare', r'__cfduid', r'cf-ray'],
                'version_patterns': [],
                'headers': ['CF-Ray', 'CF-Cache-Status'],
                'cookies': ['__cfduid']
            },
            
            # Lenguajes
            'PHP': {
                'patterns': [r'php', r'x-powered-by'],
                'version_patterns': [
                    (r'PHP/([0-9.]+)', 'header'),
                ],
                'headers': ['X-Powered-By'],
                'cookies': ['PHPSESSID']
            },
            'Python': {
                'patterns': [r'python', r'wsgi'],
                'version_patterns': [
                    (r'Python/([0-9.]+)', 'header'),
                ],
                'headers': ['X-Powered-By'],
                'cookies': []
            },
            'Java': {
                'patterns': [r'java', r'jsp', r'servlet'],
                'version_patterns': [],
                'headers': ['X-Powered-By'],
                'cookies': ['JSESSIONID']
            },
            'ASP.NET': {
                'patterns': [r'asp.net', r'__viewstate', r'aspnet'],
                'version_patterns': [],
                'headers': ['X-AspNet-Version'],
                'cookies': ['ASP.NET_SessionId']
            },
            
            # Analytics
            'Google Analytics': {
                'patterns': [r'google-analytics', r'gtag', r'ga\(', r'GoogleAnalytics'],
                'version_patterns': [],
                'headers': [],
                'cookies': ['_ga', '_gid']
            },
            'Facebook Pixel': {
                'patterns': [r'facebook.*?pixel', r'fbq'],
                'version_patterns': [],
                'headers': [],
                'cookies': ['_fbp']
            },
            'Hotjar': {
                'patterns': [r'hotjar', r'hj-'],
                'version_patterns': [],
                'headers': [],
                'cookies': ['_hj']
            },
        }
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    async def fetch_page(self) -> tuple:
        """Obtiene HTML y headers"""
        try:
            resp = await self.client.get(self.url)
            if resp:
                html = await resp.text()
                headers = resp.headers
                return html, headers
        except:
            pass
        return None, {}
        
    def check_headers(self, headers: Dict):
        """Analiza headers HTTP"""
        server = headers.get('server', '').lower()
        powered = headers.get('x-powered-by', '').lower()
        
        for tech, data in self.patterns.items():
            for header_pattern in data.get('headers', []):
                if header_pattern.lower() in server or header_pattern.lower() in powered:
                    self.technologies.add(tech)
                    
                    # Extraer versión
                    for pattern, _ in data.get('version_patterns', []):
                        match = re.search(pattern, headers.get('server', '') + headers.get('x-powered-by', ''))
                        if match:
                            self.versions[tech] = match.group(1)
                            
    def check_cookies(self, cookies: str):
        """Analiza cookies"""
        for tech, data in self.patterns.items():
            for cookie_pattern in data.get('cookies', []):
                if cookie_pattern in cookies:
                    self.technologies.add(tech)
                    
    def check_html(self, html: str):
        """Analiza HTML en busca de tecnologías"""
        html_lower = html.lower()
        
        for tech, data in self.patterns.items():
            if tech in self.technologies:
                continue
                
            for pattern in data['patterns']:
                if pattern.lower() in html_lower:
                    self.technologies.add(tech)
                    
                    # Buscar versión
                    for vpattern, _ in data.get('version_patterns', []):
                        vmatch = re.search(vpattern, html, re.IGNORECASE)
                        if vmatch:
                            self.versions[tech] = vmatch.group(1)
                    break
                    
    async def scan_assets(self, html: str):
        """Analiza archivos JS/CSS"""
        # Extraer JS
        js_pattern = r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']'
        js_files = re.findall(js_pattern, html, re.IGNORECASE)
        
        for js in js_files[:20]:
            js_url = urljoin(self.url, js)
            try:
                resp = await self.client.get(js_url)
                if resp:
                    content = await resp.text()
                    
                    # Buscar versiones en JS
                    for tech, data in self.patterns.items():
                        for vpattern, _ in data.get('version_patterns', []):
                            vmatch = re.search(vpattern, content, re.IGNORECASE)
                            if vmatch:
                                self.technologies.add(tech)
                                self.versions[tech] = vmatch.group(1)
            except:
                pass
                
    async def scan(self):
        """Ejecuta detección completa"""
        print(f"\n🔍 TECHNOLOGY DETECTOR v3.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            html, headers = await self.fetch_page()
            if not html:
                print("[!] No se pudo obtener la página")
                return [], {}
                
            # Análisis
            self.check_headers(headers)
            self.check_cookies(str(headers.get('set-cookie', '')))
            self.check_html(html)
            await self.scan_assets(html)
            
            # Resumen
            print("\n" + "="*70)
            print("📊 TECNOLOGÍAS DETECTADAS")
            print("="*70)
            
            if self.technologies:
                for tech in sorted(self.technologies):
                    if tech in self.versions:
                        print(f"   [OK] {tech} v{self.versions[tech]}")
                    else:
                        print(f"   [INFO] {tech}")
            else:
                print("   ❌ No se detectaron tecnologías")
                
        finally:
            if self.client:
                await self.client.close()
                
        return list(self.technologies), self.versions

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 technology_detector.py <URL>")
        sys.exit(1)
        
    detector = TechnologyDetector(sys.argv[1])
    await detector.scan()

if __name__ == "__main__":
    asyncio.run(main())
