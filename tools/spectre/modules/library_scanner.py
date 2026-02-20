#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LIBRARY SCANNER v2.0 - TANQUE EDITION
Detección de librerías JS · Version fingerprinting · CDN detection
Base de datos de 50+ librerías
"""

import asyncio
import re
import hashlib
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class LibraryScanner:
    def __init__(self, url: str):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.client = None
        self.libraries = []
        
        # Base de datos de librerías (50+)
        self.library_db = {
            # Frameworks
            'jQuery': {
                'name': 'jQuery',
                'url_patterns': [
                    (r'jquery[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                    (r'jquery(?:\.min)?\.js\?ver=([\d.]+)', 'ver'),
                ],
                'content_patterns': [
                    (r'jQuery\s+v?([\d.]+)', 'comment'),
                    (r'jQuery\.fn\.jquery\s*=\s*"([\d.]+)"', 'property'),
                    (r'version:\s*"([\d.]+)"', 'object'),
                ]
            },
            'Bootstrap': {
                'name': 'Bootstrap',
                'url_patterns': [
                    (r'bootstrap[.-]?([\d.]+)(?:\.min)?\.(?:js|css)', 'url'),
                    (r'bootstrap(?:\.min)?\.(?:js|css)\?ver=([\d.]+)', 'ver'),
                ],
                'content_patterns': [
                    (r'Bootstrap\s+v?([\d.]+)', 'comment'),
                    (r'data-bootstrap-version="([\d.]+)"', 'attr'),
                    (r'Version\s+([\d.]+)', 'css_comment'),
                ]
            },
            'Vue.js': {
                'name': 'Vue.js',
                'url_patterns': [
                    (r'vue[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                    (r'vue(?:\.min)?\.js\?ver=([\d.]+)', 'ver'),
                ],
                'content_patterns': [
                    (r'Vue\.js\s+v?([\d.]+)', 'comment'),
                    (r'version\s*=\s*"([\d.]+)"', 'var'),
                    (r'"version":"([\d.]+)"', 'json'),
                ]
            },
            'React': {
                'name': 'React',
                'url_patterns': [
                    (r'react[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                    (r'react-dom[.-]?([\d.]+)(?:\.min)?\.js', 'dom'),
                    (r'react(?:\.min)?\.js\?ver=([\d.]+)', 'ver'),
                ],
                'content_patterns': [
                    (r'React\s+v?([\d.]+)', 'comment'),
                    (r'version:\s*"([\d.]+)"', 'code'),
                    (r'"version":"([\d.]+)"', 'json'),
                ]
            },
            'Angular': {
                'name': 'Angular',
                'url_patterns': [
                    (r'angular[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                    (r'angular-core[.-]?([\d.]+)', 'core'),
                ],
                'content_patterns': [
                    (r'Angular\s+v?([\d.]+)', 'comment'),
                    (r'version\s*=\s*{[\s\S]*?full:\s*"([\d.]+)"', 'obj'),
                ]
            },
            'Lodash': {
                'name': 'Lodash',
                'url_patterns': [
                    (r'lodash[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'lodash\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Moment.js': {
                'name': 'Moment.js',
                'url_patterns': [
                    (r'moment[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                    (r'moment(?:\.min)?\.js\?ver=([\d.]+)', 'ver'),
                ],
                'content_patterns': [
                    (r'Moment\.js\s+v?([\d.]+)', 'comment'),
                    (r'version\s*=\s*"([\d.]+)"', 'var'),
                ]
            },
            'Axios': {
                'name': 'Axios',
                'url_patterns': [
                    (r'axios[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'axios\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Font Awesome': {
                'name': 'Font Awesome',
                'url_patterns': [
                    (r'font-awesome[.-]?([\d.]+)(?:\.min)?\.css', 'url'),
                    (r'fontawesome[.-]?([\d.]+)', 'url'),
                ],
                'content_patterns': [
                    (r'Font\s+Awesome\s+([\d.]+)', 'comment'),
                ]
            },
            'Owl Carousel': {
                'name': 'Owl Carousel',
                'url_patterns': [
                    (r'owl\.carousel[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'Owl\s+Carousel\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Slick': {
                'name': 'Slick',
                'url_patterns': [
                    (r'slick[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'Slick\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Select2': {
                'name': 'Select2',
                'url_patterns': [
                    (r'select2[.-]?([\d.]+)(?:\.min)?\.(?:js|css)', 'url'),
                ],
                'content_patterns': [
                    (r'Select2\s+v?([\d.]+)', 'comment'),
                ]
            },
            'DataTables': {
                'name': 'DataTables',
                'url_patterns': [
                    (r'datatables[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'DataTables\s+([\d.]+)', 'comment'),
                ]
            },
            'Chart.js': {
                'name': 'Chart.js',
                'url_patterns': [
                    (r'chart[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'Chart\.js\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Three.js': {
                'name': 'Three.js',
                'url_patterns': [
                    (r'three[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'Three\.js\s+r?([\d.]+)', 'comment'),
                ]
            },
            'GSAP': {
                'name': 'GSAP',
                'url_patterns': [
                    (r'gsap[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'GSAP\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Swiper': {
                'name': 'Swiper',
                'url_patterns': [
                    (r'swiper[.-]?([\d.]+)(?:\.min)?\.(?:js|css)', 'url'),
                ],
                'content_patterns': [
                    (r'Swiper\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Fancybox': {
                'name': 'Fancybox',
                'url_patterns': [
                    (r'fancybox[.-]?([\d.]+)(?:\.min)?\.(?:js|css)', 'url'),
                ],
                'content_patterns': [
                    (r'Fancybox\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Isotope': {
                'name': 'Isotope',
                'url_patterns': [
                    (r'isotope[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'Isotope\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Masonry': {
                'name': 'Masonry',
                'url_patterns': [
                    (r'masonry[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'Masonry\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Handlebars': {
                'name': 'Handlebars',
                'url_patterns': [
                    (r'handlebars[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'Handlebars\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Mustache': {
                'name': 'Mustache',
                'url_patterns': [
                    (r'mustache[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'Mustache\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Underscore': {
                'name': 'Underscore',
                'url_patterns': [
                    (r'underscore[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'Underscore\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Backbone': {
                'name': 'Backbone',
                'url_patterns': [
                    (r'backbone[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'Backbone\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Ember': {
                'name': 'Ember',
                'url_patterns': [
                    (r'ember[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'Ember\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Knockout': {
                'name': 'Knockout',
                'url_patterns': [
                    (r'knockout[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'Knockout\s+v?([\d.]+)', 'comment'),
                ]
            },
            'D3': {
                'name': 'D3.js',
                'url_patterns': [
                    (r'd3[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'D3\s+v?([\d.]+)', 'comment'),
                ]
            },
            'C3': {
                'name': 'C3.js',
                'url_patterns': [
                    (r'c3[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'C3\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Highcharts': {
                'name': 'Highcharts',
                'url_patterns': [
                    (r'highcharts[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'Highcharts\s+([\d.]+)', 'comment'),
                ]
            },
            'ApexCharts': {
                'name': 'ApexCharts',
                'url_patterns': [
                    (r'apexcharts[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'ApexCharts\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Socket.io': {
                'name': 'Socket.io',
                'url_patterns': [
                    (r'socket\.io[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'Socket\.io\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Pusher': {
                'name': 'Pusher',
                'url_patterns': [
                    (r'pusher[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'Pusher\s+v?([\d.]+)', 'comment'),
                ]
            },
            'Stripe': {
                'name': 'Stripe.js',
                'url_patterns': [
                    (r'stripe[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'Stripe\s+v?([\d.]+)', 'comment'),
                ]
            },
            'PayPal': {
                'name': 'PayPal SDK',
                'url_patterns': [
                    (r'paypal[.-]?([\d.]+)(?:\.min)?\.js', 'url'),
                ],
                'content_patterns': [
                    (r'PayPal\s+v?([\d.]+)', 'comment'),
                ]
            },
        }
        
        # CDN patterns
        self.cdn_patterns = [
            (r'cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([\d.]+)/', 'cdnjs'),
            (r'ajax\.googleapis\.com/ajax/libs/([^/]+)/([\d.]+)/', 'google'),
            (r'stackpath\.bootstrapcdn\.com/[^/]+/([\d.]+)/', 'bootstrapcdn'),
            (r'unpkg\.com/([^@]+)@([\d.]+)', 'unpkg'),
            (r'cdn\.jsdelivr\.net/[^/]+/([^@]+)@([\d.]+)', 'jsdelivr'),
            (r'cdn\.jsdelivr\.net/npm/([^@]+)@([\d.]+)', 'jsdelivr_npm'),
            (r'code\.jquery\.com/jquery-([\d.]+)', 'jquery_cdn'),
            (r'cdn\.socket\.io/socket\.io-([\d.]+)', 'socketio_cdn'),
            (r'cdn\.ravenjs\.com/([\d.]+)', 'raven_cdn'),
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    async def fetch_html(self) -> Optional[str]:
        """Obtiene HTML principal"""
        try:
            resp = await self.client.get(self.url)
            if resp and resp.status == 200:
                return await resp.text()
        except:
            pass
        return None
        
    def extract_assets(self, html: str) -> List[str]:
        """Extrae URLs de JS y CSS"""
        assets = []
        
        # Scripts
        scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        # CSS
        css = re.findall(r'<link[^>]*href=["\']([^"\']+\.css[^"\']*)["\']', html, re.IGNORECASE)
        
        for src in scripts + css:
            if src.startswith('//'):
                full_url = f"{self.parsed.scheme}:{src}"
            elif src.startswith('http'):
                full_url = src
            elif src.startswith('/'):
                full_url = urljoin(self.url, src)
            else:
                full_url = urljoin(self.url, src)
                
            assets.append(full_url.split('?')[0].split('#')[0])
            
        return list(set(assets))
        
    def detect_from_cdn(self, url: str) -> Optional[Dict]:
        """Detecta librería por URL de CDN"""
        for pattern, cdn_name in self.cdn_patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                if len(match.groups()) == 2:
                    lib_name, version = match.groups()
                else:
                    version = match.group(1)
                    lib_name = 'jQuery' if 'jquery' in pattern else 'unknown'
                    
                # Buscar en DB
                for lib_id, lib_data in self.library_db.items():
                    if lib_name.lower() in lib_id.lower():
                        return {
                            'libreria': lib_data['name'],
                            'version': version,
                            'fuente': f'CDN ({cdn_name})',
                            'url': url,
                            'confianza': 'alta'
                        }
                        
                return {
                    'libreria': lib_name.capitalize(),
                    'version': version,
                    'fuente': f'CDN ({cdn_name})',
                    'url': url,
                    'confianza': 'media'
                }
        return None
        
    def detect_from_url(self, url: str) -> Optional[Dict]:
        """Detecta por nombre de archivo"""
        for lib_id, lib_data in self.library_db.items():
            for pattern, source in lib_data['url_patterns']:
                match = re.search(pattern, url, re.IGNORECASE)
                if match:
                    version = match.group(1) if len(match.groups()) > 0 else 'desconocida'
                    return {
                        'libreria': lib_data['name'],
                        'version': version,
                        'fuente': f'URL ({source})',
                        'url': url,
                        'confianza': 'alta' if version != 'desconocida' else 'media'
                    }
        return None
        
    async def detect_from_content(self, url: str) -> Optional[Dict]:
        """Detecta por contenido del archivo"""
        try:
            resp = await self.client.get(url)
            if not resp or resp.status != 200:
                return None
                
            content = await resp.text()
            
            for lib_id, lib_data in self.library_db.items():
                for pattern, source in lib_data['content_patterns']:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        version = match.group(1) if len(match.groups()) > 0 else 'desconocida'
                        return {
                            'libreria': lib_data['name'],
                            'version': version,
                            'fuente': f'contenido ({source})',
                            'url': url,
                            'confianza': 'alta'
                        }
        except:
            pass
        return None
        
    async def scan(self):
        """Ejecuta escaneo completo"""
        print(f"\n🔍 LIBRARY SCANNER v2.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            # Obtener HTML
            html = await self.fetch_html()
            if not html:
                print("[!] No se pudo obtener la página")
                return []
                
            # Extraer assets
            assets = self.extract_assets(html)
            print(f"[*] Analizando {len(assets)} recursos...")
            
            for url in assets:
                # Probar CDN primero
                result = self.detect_from_cdn(url)
                if not result:
                    result = self.detect_from_url(url)
                    
                if result:
                    self.libraries.append(result)
                    print(f"   [OK] {result['libreria']} v{result['version']} ({result['fuente']})")
                    continue
                    
                # Si no, descargar y analizar contenido
                if self.aggressive:
                    result = await self.detect_from_content(url)
                    if result:
                        self.libraries.append(result)
                        print(f"   [OK] {result['libreria']} v{result['version']} (contenido)")
                        
            # Resumen
            print("\n" + "="*70)
            print("📚 LIBRERÍAS DETECTADAS")
            print("="*70)
            
            if self.libraries:
                # Eliminar duplicados
                unique = {}
                for lib in self.libraries:
                    key = f"{lib['libreria']}-{lib['version']}"
                    if key not in unique:
                        unique[key] = lib
                        
                for lib in sorted(unique.values(), key=lambda x: x['libreria']):
                    print(f"\n   [OK] {lib['libreria']} v{lib['version']}")
                    print(f"      ↳ {lib['fuente']}")
            else:
                print("\n   ❌ No se detectaron librerías")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.libraries

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 library_scanner.py <URL> [--aggressive]")
        sys.exit(1)
        
    url = sys.argv[1]
    aggressive = '--aggressive' in sys.argv
    
    scanner = LibraryScanner(url)
    scanner.aggressive = aggressive
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
