#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VERSION DETECTOR v2.0 - TANQUE EDITION
Detección precisa de versiones de software · Fingerprinting · Hash matching
Con base de datos de firmas actualizada
"""

import asyncio
import re
import hashlib
from urllib.parse import urljoin
from datetime import datetime
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class VersionDetector:
    def __init__(self, url: str):
        self.url = url.rstrip('/')
        self.client = None
        self.versions = {}
        self.software = []
        
        # Base de datos de firmas
        self.signatures = {
            # CMS
            'WordPress': {
                'paths': ['/wp-includes/js/jquery/jquery.js', '/wp-content/'],
                'patterns': [
                    (r'<meta name="generator" content="WordPress ([0-9.]+)"', 'meta'),
                    (r'WordPress ([0-9.]+)', 'comment'),
                    (r'ver=([0-9.]+)"', 'query'),
                ],
                'headers': [],
                'files': {
                    '/wp-includes/version.php': r'wp_version = \'([0-9.]+)\'',
                }
            },
            'Joomla': {
                'paths': ['/administrator/', '/media/system/js/'],
                'patterns': [
                    (r'<meta name="generator" content="Joomla! ([0-9.]+)"', 'meta'),
                ],
                'headers': [],
                'files': {
                    '/administrator/manifests/files/joomla.xml': r'<version>([0-9.]+)</version>',
                }
            },
            'Drupal': {
                'paths': ['/sites/default/', '/core/misc/drupal.js'],
                'patterns': [
                    (r'Drupal ([0-9.]+)', 'comment'),
                    (r'<meta name="generator" content="Drupal ([0-9.]+)"', 'meta'),
                ],
                'headers': ['X-Drupal-Cache'],
                'files': {
                    '/core/lib/Drupal.php': r'VERSION = \'([0-9.]+)\'',
                }
            },
            'Magento': {
                'paths': ['/js/mage/', '/skin/frontend/'],
                'patterns': [
                    (r'Magento/([0-9.]+)', 'header'),
                ],
                'headers': ['X-Magento'],
                'files': {
                    '/app/etc/local.xml': r'<version>([0-9.]+)</version>',
                }
            },
            
            # Frameworks
            'Laravel': {
                'paths': [],
                'patterns': [
                    (r'Laravel v([0-9.]+)', 'comment'),
                ],
                'headers': [],
                'files': {
                    '/vendor/laravel/framework/src/Illuminate/Foundation/Application.php': r'VERSION = \'([0-9.]+)\'',
                }
            },
            'Django': {
                'paths': [],
                'patterns': [],
                'headers': [],
                'files': {
                    '/admin/login/': None,  # Versión en admin
                }
            },
            'Ruby on Rails': {
                'paths': [],
                'patterns': [],
                'headers': ['X-Runtime'],
                'files': {}
            },
            
            # Servidores
            'nginx': {
                'paths': [],
                'patterns': [
                    (r'nginx/([0-9.]+)', 'header'),
                ],
                'headers': ['Server'],
                'files': {}
            },
            'Apache': {
                'paths': [],
                'patterns': [
                    (r'Apache/([0-9.]+)', 'header'),
                ],
                'headers': ['Server'],
                'files': {}
            },
            'IIS': {
                'paths': [],
                'patterns': [
                    (r'Microsoft-IIS/([0-9.]+)', 'header'),
                ],
                'headers': ['Server'],
                'files': {}
            },
            'PHP': {
                'paths': [],
                'patterns': [
                    (r'PHP/([0-9.]+)', 'header'),
                ],
                'headers': ['X-Powered-By'],
                'files': {
                    '/phpinfo.php': r'PHP Version ([0-9.]+)',
                }
            },
            'OpenSSL': {
                'paths': [],
                'patterns': [],
                'headers': [],
                'files': {}
            },
            
            # Bases de datos
            'MySQL': {
                'paths': [],
                'patterns': [],
                'headers': [],
                'files': {}
            },
            'PostgreSQL': {
                'paths': [],
                'patterns': [],
                'headers': [],
                'files': {}
            },
            'MongoDB': {
                'paths': [],
                'patterns': [],
                'headers': [],
                'files': {}
            },
            
            # Otros
            'jQuery': {
                'paths': [],
                'patterns': [
                    (r'jQuery v([0-9.]+)', 'comment'),
                    (r'jQuery ([0-9.]+)', 'comment'),
                ],
                'headers': [],
                'files': {}
            },
            'Bootstrap': {
                'paths': [],
                'patterns': [
                    (r'Bootstrap v([0-9.]+)', 'comment'),
                ],
                'headers': [],
                'files': {}
            },
        }
        
        # Archivos de versión comunes
        self.version_files = [
            'readme.html', 'CHANGELOG.txt', 'README.txt', 'version.php',
            'wp-links-opml.php', 'VERSION', 'RELEASE', 'build.properties',
            'composer.json', 'package.json', 'bower.json', 'pom.xml',
            '.version', 'version.md', 'version.txt', 'versions.txt',
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    async def check_headers(self):
        """Analiza headers HTTP"""
        try:
            resp = await self.client.get(self.url)
            if not resp:
                return
                
            headers = resp.headers
            
            for software, sig in self.signatures.items():
                for header_name in sig.get('headers', []):
                    header_value = headers.get(header_name.lower(), '')
                    if header_value:
                        self.software.append(software)
                        
                        # Buscar versión en header
                        for pattern, _ in sig.get('patterns', []):
                            match = re.search(pattern, header_value)
                            if match:
                                self.versions[software] = match.group(1)
                                
        except:
            pass
            
    async def check_paths(self):
        """Analiza rutas comunes"""
        for software, sig in self.signatures.items():
            for path in sig.get('paths', []):
                url = urljoin(self.url, path)
                try:
                    resp = await self.client.get(url)
                    if resp and resp.status == 200:
                        self.software.append(software)
                        
                        # Buscar versión en contenido
                        text = await resp.text()
                        for pattern, _ in sig.get('patterns', []):
                            match = re.search(pattern, text, re.IGNORECASE)
                            if match:
                                self.versions[software] = match.group(1)
                                break
                except:
                    pass
                    
    async def check_files(self):
        """Analiza archivos específicos de versión"""
        for software, sig in self.signatures.items():
            for file_path, pattern in sig.get('files', {}).items():
                if not pattern:
                    continue
                    
                url = urljoin(self.url, file_path)
                try:
                    resp = await self.client.get(url)
                    if resp and resp.status == 200:
                        text = await resp.text()
                        match = re.search(pattern, text, re.IGNORECASE)
                        if match:
                            self.software.append(software)
                            self.versions[software] = match.group(1)
                except:
                    pass
                    
    async def check_version_files(self):
        """Analiza archivos de versión comunes"""
        for vf in self.version_files:
            url = urljoin(self.url, vf)
            try:
                resp = await self.client.get(url)
                if resp and resp.status == 200:
                    text = await resp.text()
                    
                    # Buscar cualquier patrón de versión
                    version_patterns = [
                        r'version[:\s]+"?([0-9.]+)"?',
                        r'v([0-9]+\.[0-9]+\.[0-9]+)',
                        r'([0-9]+\.[0-9]+\.[0-9]+)',
                        r'([0-9]+\.[0-9]+)',
                    ]
                    
                    for pattern in version_patterns:
                        match = re.search(pattern, text, re.IGNORECASE)
                        if match:
                            self.versions[f'File:{vf}'] = match.group(1)
                            break
            except:
                pass
                
    async def check_error_pages(self):
        """Fuerza errores para revelar versiones"""
        error_paths = [
            '/does-not-exist-12345',
            '/%00',
            '/../../../../etc/passwd',
            '/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000',
            '/index.php/',
            '/admin/does-not-exist',
        ]
        
        for path in error_paths:
            url = urljoin(self.url, path)
            try:
                resp = await self.client.get(url)
                if resp:
                    text = await resp.text()
                    
                    # Buscar versiones en errores
                    patterns = [
                        (r'nginx/([0-9.]+)', 'nginx'),
                        (r'Apache/([0-9.]+)', 'Apache'),
                        (r'PHP/([0-9.]+)', 'PHP'),
                        (r'Microsoft-IIS/([0-9.]+)', 'IIS'),
                        (r'Tomcat/([0-9.]+)', 'Tomcat'),
                        (r'JBoss/([0-9.]+)', 'JBoss'),
                        (r'GlassFish/([0-9.]+)', 'GlassFish'),
                    ]
                    
                    for pattern, software in patterns:
                        match = re.search(pattern, text, re.IGNORECASE)
                        if match:
                            self.software.append(software)
                            self.versions[software] = match.group(1)
            except:
                pass
                
    async def scan(self):
        """Ejecuta detección completa"""
        print(f"\n🔍 VERSION DETECTOR v2.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            # Headers
            print("[*] Analizando headers...")
            await self.check_headers()
            
            # Paths
            print("[*] Analizando rutas comunes...")
            await self.check_paths()
            
            # Archivos específicos
            print("[*] Analizando archivos de versión...")
            await self.check_files()
            
            # Archivos comunes
            print("[*] Buscando archivos de versión comunes...")
            await self.check_version_files()
            
            # Errores
            print("[*] Forzando errores...")
            await self.check_error_pages()
            
            # Resumen
            print("\n" + "="*70)
            print("📊 VERSIONES DETECTADAS")
            print("="*70)
            
            if self.versions:
                print(f"\n[OK] Software con versión:")
                for software, version in self.versions.items():
                    print(f"   • {software}: {version}")
                    
            if self.software and not all(s in self.versions for s in self.software):
                print(f"\n[INFO] Software detectado (sin versión):")
                for software in set(self.software):
                    if software not in self.versions:
                        print(f"   • {software}")
                        
            if not self.software and not self.versions:
                print("\n❌ No se detectó software conocido")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.versions

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 version_detector.py <URL>")
        sys.exit(1)
        
    detector = VersionDetector(sys.argv[1])
    await detector.scan()

if __name__ == "__main__":
    asyncio.run(main())
