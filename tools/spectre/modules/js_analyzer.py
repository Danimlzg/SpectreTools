#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
JS ANALYZER v2.0 - TANQUE EDITION
Extracción de endpoints · Secretos · API paths · Comentarios sospechosos
Con análisis profundo de JS
"""

import asyncio
import re
import json
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Set

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class JSAnalyzer:
    def __init__(self, url: str, js_files: List[str] = None, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.js_files = js_files or []
        self.aggressive = aggressive
        self.client = None
        self.findings = {
            'endpoints': [],
            'secrets': [],
            'hardcoded': [],
            'api_paths': set(),
            'suspicious_comments': [],
            'urls': set(),
        }
        
        # Patrones de endpoints (ampliados)
        self.endpoint_patterns = [
            # URLs
            (r'["\'](https?://[^"\']+)["\']', 'absolute_url'),
            (r'["\'](/{1,2}[a-zA-Z0-9_\-/\.]+)["\']', 'relative_path'),
            (r'["\'](/?api/[a-zA-Z0-9_\-/]+)["\']', 'api_path'),
            (r'["\'](/?v[0-9]+/[a-zA-Z0-9_\-/]+)["\']', 'versioned_api'),
            (r'["\'](/?graphql[^"\']*)["\']', 'graphql'),
            (r'["\'](/?rest[^"\']*)["\']', 'rest'),
            
            # Fetch/XHR
            (r'fetch\(["\']([^"\']+)["\']', 'fetch'),
            (r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']', 'axios'),
            (r'\$\.(?:get|post|ajax)\(["\']([^"\']+)["\']', 'jquery'),
            (r'XMLHttpRequest\([^)]*["\']([^"\']+)["\']', 'xhr'),
            (r'new Request\([^)]*["\']([^"\']+)["\']', 'mootools'),
            (r'Http\.(?:get|post)\(["\']([^"\']+)["\']', 'angular'),
            
            # WebSockets
            (r'new WebSocket\(["\']([^"\']+)["\']', 'websocket'),
            (r'io\(["\']([^"\']+)["\']', 'socketio'),
            
            # Parámetros
            (r'[?&]([a-zA-Z0-9_]+)=', 'url_param'),
            (r'\{([a-zA-Z0-9_]+)\}', 'template_var'),
        ]
        
        # Patrones de secretos
        self.secret_patterns = [
            (r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', 'api_key'),
            (r'secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{8,})["\']', 'secret'),
            (r'token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{8,})["\']', 'token'),
            (r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'password'),
            (r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\'](AKIA[0-9A-Z]{16})["\']', 'aws_key'),
            (r'firebase.*?["\']([a-zA-Z0-9_\-]{30,})["\']', 'firebase'),
            (r'mongodb(?:\+srv)?://[^"\']+', 'mongodb_uri'),
            (r'mysql://[^"\']+', 'mysql_uri'),
            (r'postgresql://[^"\']+', 'postgres_uri'),
            (r'redis://[^"\']+', 'redis_uri'),
            (r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'jwt'),
        ]
        
        # Palabras sospechosas en comentarios
        self.suspicious_keywords = [
            'TODO', 'FIXME', 'BUG', 'HACK', 'XXX', 'NOTE',
            'REMOVE', 'DELETE', 'CHANGE', 'UPDATE', 'DEBUG',
            'TEST', 'DEMO', 'SECRET', 'PASSWORD', 'USERNAME',
            'EMAIL', 'TOKEN', 'API_KEY', 'CREDENTIALS', 'LOGIN',
            'CONTRASEÑA', 'USUARIO', 'CLAVE', 'SECRETO',
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    async def fetch_js(self, js_url: str) -> Optional[str]:
        """Descarga archivo JS"""
        try:
            resp = await self.client.get(js_url)
            if resp and resp.status == 200:
                return await resp.text()
        except:
            pass
        return None
        
    def extract_from_js(self, content: str, source: str) -> Dict:
        """Extrae toda la información de un JS"""
        result = {
            'endpoints': [],
            'secrets': [],
            'urls': set(),
            'api_paths': set(),
            'comments': [],
        }
        
        # 1. Extraer endpoints
        for pattern, ptype in self.endpoint_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                    
                # Normalizar
                if match.startswith('http'):
                    full_url = match
                elif match.startswith('//'):
                    full_url = f"{self.parsed.scheme}:{match}"
                elif match.startswith('/'):
                    full_url = urljoin(self.url, match)
                else:
                    full_url = match
                    
                result['endpoints'].append({
                    'url': full_url,
                    'type': ptype,
                    'source': source,
                    'original': match[:100]
                })
                
                result['urls'].add(full_url)
                if 'api' in match.lower() or '/v' in match:
                    result['api_paths'].add(match)
                    
        # 2. Extraer secretos
        for pattern, stype in self.secret_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                    
                if len(match) > 8:
                    result['secrets'].append({
                        'type': stype,
                        'value': match[:4] + '*' * (len(match)-8) + match[-4:] if len(match) > 8 else '****',
                        'source': source,
                        'length': len(match)
                    })
                    
        # 3. Extraer comentarios
        # Comentarios de una línea
        single = re.findall(r'//(.*?)$', content, re.MULTILINE)
        # Comentarios multi-línea
        multi = re.findall(r'/\*(.*?)\*/', content, re.DOTALL)
        
        for comment in single + multi:
            comment_lower = comment.lower()
            found = [k for k in self.suspicious_keywords if k.lower() in comment_lower]
            if found:
                result['comments'].append({
                    'comment': comment[:200] + '...' if len(comment) > 200 else comment,
                    'keywords': found,
                    'source': source
                })
                
        return result
        
    async def analyze_js_file(self, js_url: str) -> Dict:
        """Analiza un archivo JS completo"""
        print(f"\n[*] Analizando: {js_url}")
        
        content = await self.fetch_js(js_url)
        if not content:
            print(f"   → Error al descargar")
            return {}
            
        result = self.extract_from_js(content, js_url)
        
        # Mostrar resumen
        print(f"   → Endpoints: {len(result['endpoints'])}")
        print(f"   → Secretos: {len(result['secrets'])}")
        print(f"   → Comentarios: {len(result['comments'])}")
        
        # Buscar más JS (recursivo si aggressive)
        if self.aggressive:
            js_pattern = r'["\']([^"\']+\.js)["\']'
            more_js = re.findall(js_pattern, content)
            for js in more_js[:3]:  # Limitar profundidad
                nested_url = urljoin(self.url, js)
                if nested_url != js_url:
                    nested = await self.analyze_js_file(nested_url)
                    if nested:
                        for key in ['endpoints', 'secrets', 'comments']:
                            result[key].extend(nested.get(key, []))
                            
        return result
        
    async def scan(self):
        """Ejecuta análisis completo"""
        print(f"\n🔬 JS ANALYZER v2.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            # Si no hay JS files, intentar extraer del HTML
            if not self.js_files:
                print("[*] Extrayendo JS del HTML...")
                resp = await self.client.get(self.url)
                if resp:
                    html = await resp.text()
                    js_pattern = r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']'
                    self.js_files = re.findall(js_pattern, html, re.IGNORECASE)
                    self.js_files = [urljoin(self.url, js) for js in self.js_files]
                    
            print(f"[*] Analizando {len(self.js_files)} archivos JavaScript")
            
            for js_url in self.js_files:
                result = await self.analyze_js_file(js_url)
                
                if result:
                    self.findings['endpoints'].extend(result.get('endpoints', []))
                    self.findings['secrets'].extend(result.get('secrets', []))
                    self.findings['suspicious_comments'].extend(result.get('comments', []))
                    self.findings['urls'].update(result.get('urls', set()))
                    self.findings['api_paths'].update(result.get('api_paths', set()))
                    
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS ANÁLISIS JS")
            print("="*70)
            
            if self.findings['endpoints']:
                print(f"\n🔗 ENDPOINTS: {len(self.findings['endpoints'])}")
                unique_urls = set()
                for e in self.findings['endpoints'][:20]:
                    if e['url'] not in unique_urls:
                        unique_urls.add(e['url'])
                        print(f"   • {e['url']}")
                        
            if self.findings['secrets']:
                print(f"\n[SECURE] SECRETOS: {len(self.findings['secrets'])}")
                for s in self.findings['secrets'][:10]:
                    print(f"   • {s['type']}: {s['value']}")
                    
            if self.findings['suspicious_comments']:
                print(f"\n[WARN]  COMENTARIOS: {len(self.findings['suspicious_comments'])}")
                
            if self.findings['api_paths']:
                print(f"\n[INFO] API PATHS: {len(self.findings['api_paths'])}")
                
            total = (len(self.findings['endpoints']) + 
                    len(self.findings['secrets']) + 
                    len(self.findings['suspicious_comments']))
            print(f"\n[OK] TOTAL HALLAZGOS: {total}")
            
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 js_analyzer.py <URL> [js_files...] [--aggressive]")
        sys.exit(1)
        
    url = sys.argv[1]
    aggressive = '--aggressive' in sys.argv
    
    js_files = []
    for arg in sys.argv[2:]:
        if not arg.startswith('--'):
            js_files.append(arg)
            
    analyzer = JSAnalyzer(url, js_files, aggressive)
    await analyzer.scan()

if __name__ == "__main__":
    asyncio.run(main())
