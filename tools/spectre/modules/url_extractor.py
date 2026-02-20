#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
URL EXTRACTOR v2.0 - TANQUE EDITION
Extracción de URLs de HTML, JS, CSS · Clasificación por tipo · Análisis recursivo
Con soporte para SPAs y contenido dinámico
"""

import asyncio
import re
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Set, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class URLExtractor:
    def __init__(self, base_url: str, recursive: bool = True, max_depth: int = 2):
        self.base_url = base_url.rstrip('/')
        self.parsed = urlparse(base_url)
        self.domain = self.parsed.netloc
        self.recursive = recursive
        self.max_depth = max_depth
        self.client = None
        self.visited = set()
        
        self.urls = {
            'internal': set(),
            'external': set(),
            'scripts': set(),
            'styles': set(),
            'images': set(),
            'media': set(),
            'documents': set(),
            'apis': set(),
            'forms': set(),
            'all': set(),
        }
        
        # Patrones de extracción
        self.patterns = [
            # Tags HTML
            (r'href=["\']([^"\']+)["\']', 'href'),
            (r'src=["\']([^"\']+)["\']', 'src'),
            (r'action=["\']([^"\']+)["\']', 'action'),
            (r'data-src=["\']([^"\']+)["\']', 'data-src'),
            (r'poster=["\']([^"\']+)["\']', 'poster'),
            (r'content=["\']([^"\']+)["\']', 'content'),
            
            # CSS
            (r'url\(["\']?([^"\')]+)["\']?\)', 'css_url'),
            (r'@import\s+["\']([^"\']+)["\']', 'css_import'),
            
            # JS
            (r'fetch\(["\']([^"\']+)["\']', 'fetch'),
            (r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']', 'axios'),
            (r'\$\.(?:get|post|ajax)\(["\']([^"\']+)["\']', 'jquery'),
            (r'XMLHttpRequest\([^)]*["\']([^"\']+)["\']', 'xhr'),
            (r'window\.location\s*=\s*["\']([^"\']+)["\']', 'redirect'),
            (r'window\.open\(["\']([^"\']+)["\']', 'window_open'),
            
            # URLs absolutas
            (r'https?://[^\s<>"\'{}|\\^`\[\]]+', 'absolute'),
        ]
        
        # Extensiones por tipo
        self.extensions = {
            'scripts': ['.js', '.jsx', '.ts', '.tsx', '.vue'],
            'styles': ['.css', '.scss', '.sass', '.less'],
            'images': ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.ico'],
            'media': ['.mp4', '.webm', '.ogg', '.mp3', '.wav', '.flv'],
            'documents': ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'],
        }
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    def normalize_url(self, url: str, base: str = None) -> Optional[str]:
        """Normaliza una URL"""
        if not url or url.startswith('#') or url.startswith('javascript:'):
            return None
            
        try:
            if url.startswith('//'):
                full_url = f"{self.parsed.scheme}:{url}"
            elif url.startswith('/'):
                full_url = urljoin(self.base_url, url)
            elif url.startswith('http'):
                full_url = url
            else:
                full_url = urljoin(base or self.base_url, url)
                
            # Eliminar fragmentos
            if '#' in full_url:
                full_url = full_url.split('#')[0]
                
            return full_url
        except:
            return None
            
    def classify_url(self, url: str) -> str:
        """Clasifica una URL por tipo"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Clasificar por extensión
        for category, exts in self.extensions.items():
            for ext in exts:
                if path.endswith(ext):
                    return category
                    
        # Clasificar por dominio
        if parsed.netloc == self.domain:
            category = 'internal'
        else:
            category = 'external'
            
        # Detectar APIs
        if '/api/' in path or '/v1/' in path or '/v2/' in path or '/graphql' in path:
            return 'apis'
            
        # Detectar formularios (se añadirán después)
        return category
        
    def extract_from_content(self, content: str, source_url: str) -> Set[str]:
        """Extrae URLs de un contenido"""
        found = set()
        
        for pattern, ptype in self.patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    url = match[0]
                else:
                    url = match
                    
                normalized = self.normalize_url(url, source_url)
                if normalized:
                    found.add(normalized)
                    
        return found
        
    async def process_url(self, url: str, depth: int = 0):
        """Procesa una URL y extrae sus URLs"""
        if url in self.visited or depth > self.max_depth:
            return
            
        self.visited.add(url)
        category = self.classify_url(url)
        
        # Añadir a categorías
        self.urls['all'].add(url)
        if category in self.urls:
            self.urls[category].add(url)
        elif urlparse(url).netloc == self.domain:
            self.urls['internal'].add(url)
        else:
            self.urls['external'].add(url)
            
        # Si es HTML y recursive, extraer más
        if self.recursive and depth < self.max_depth:
            if url.endswith(('.html', '.htm', '.php', '.asp', '/')) or not '.' in url.split('/')[-1]:
                try:
                    resp = await self.client.get(url)
                    if resp and resp.status == 200:
                        content = await resp.text()
                        new_urls = self.extract_from_content(content, url)
                        
                        for new_url in new_urls:
                            await self.process_url(new_url, depth + 1)
                except:
                    pass
                    
    async def scan(self):
        """Ejecuta extracción de URLs"""
        print(f"\n🔗 URL EXTRACTOR v2.0 TANQUE - {self.base_url}")
        print("=" * 70)
        print(f"[*] Modo recursivo: {'SÍ' if self.recursive else 'NO'}")
        print(f"[*] Profundidad máxima: {self.max_depth}")
        print("-" * 70)
        
        await self.setup()
        
        try:
            # Obtener HTML inicial
            resp = await self.client.get(self.base_url)
            if not resp or resp.status != 200:
                print("[!] No se pudo obtener la página")
                return self.urls
                
            content = await resp.text()
            
            # Extraer URLs del HTML
            urls = self.extract_from_content(content, self.base_url)
            
            # Procesar cada URL
            for url in urls:
                await self.process_url(url, 1)
                
            # Buscar JS y extraer de ellos
            for js_url in list(self.urls['scripts'])[:10]:
                try:
                    resp = await self.client.get(js_url)
                    if resp:
                        js_content = await resp.text()
                        js_urls = self.extract_from_content(js_content, js_url)
                        
                        for url in js_urls:
                            await self.process_url(url, 2)
                except:
                    pass
                    
            # Resumen
            print("\n" + "="*70)
            print("📊 URLs ENCONTRADAS")
            print("="*70)
            
            total = len(self.urls['all'])
            print(f"\n📈 Total URLs: {total}")
            
            for category, urls in self.urls.items():
                if category != 'all' and urls:
                    print(f"   • {category.upper()}: {len(urls)}")
                    
            # Mostrar algunas URLs
            if self.urls['apis']:
                print(f"\n🔌 APIs ({len(self.urls['apis'])}):")
                for url in list(self.urls['apis'])[:10]:
                    print(f"   • {url}")
                    
            if self.urls['scripts']:
                print(f"\n📜 Scripts ({len(self.urls['scripts'])}):")
                for url in list(self.urls['scripts'])[:10]:
                    print(f"   • {url}")
                    
            # Guardar resultados
            with open(f"urls_{self.domain}.txt", 'w') as f:
                for url in sorted(self.urls['all']):
                    f.write(f"{url}\n")
            print(f"\n💾 URLs guardadas en urls_{self.domain}.txt")
            
        finally:
            if self.client:
                await self.client.close()
                
        return self.urls

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 url_extractor.py <URL> [--no-recursive]")
        sys.exit(1)
        
    url = sys.argv[1]
    recursive = '--no-recursive' not in sys.argv
    
    extractor = URLExtractor(url, recursive=recursive)
    await extractor.scan()

if __name__ == "__main__":
    asyncio.run(main())
