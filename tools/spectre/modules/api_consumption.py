#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API CONSUMPTION v2.0 - TANQUE EDITION
Detección de APIs externas · Validación · HTTPS · Datos sensibles
Con análisis de JS y HTML
"""

import asyncio
import json
import re
import random
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class APIConsumption:
    def __init__(self, url: str, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        
        # Patrones de APIs externas (ampliado)
        self.api_patterns = [
            # URLs directas
            (r'https?://[^"\']*api[^"\']*', 'url_api'),
            (r'https?://[^"\']*/v[0-9]+/[^"\']*', 'url_versioned'),
            (r'https?://[^"\']*\.amazonaws\.com/[^"\']*', 'aws'),
            (r'https?://[^"\']*\.azure\.com/[^"\']*', 'azure'),
            (r'https?://[^"\']*\.googleapis\.com/[^"\']*', 'google'),
            (r'https?://[^"\']*\.cloudfront\.net/[^"\']*', 'cloudfront'),
            
            # Fetch/XHR
            (r'fetch\(["\']([^"\']+)["\']', 'fetch'),
            (r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']', 'axios'),
            (r'\$\.(?:get|post|ajax)\(["\']([^"\']+)["\']', 'jquery'),
            (r'XMLHttpRequest\([^)]*["\']([^"\']+)["\']', 'xhr'),
            
            # Import/require
            (r'import\s+.*\s+from\s+["\']([^"\']+)["\']', 'import'),
            (r'require\(["\']([^"\']+)["\']\)', 'require'),
            
            # En HTML
            (r'<script[^>]*src=["\']([^"\']+)["\']', 'script_src'),
            (r'<link[^>]*href=["\']([^"\']+)["\']', 'link_href'),
            (r'<img[^>]*src=["\']([^"\']+)["\']', 'img_src'),
        ]
        
        # Palabras clave sensibles
        self.sensitive_patterns = [
            'password', 'token', 'secret', 'key', 'email', 'ssn',
            'credit', 'card', 'jwt', 'api_key', 'access_key',
            'auth', 'bearer', 'basic', 'authorization',
            'user', 'username', 'login', 'pass', 'contraseña',
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    async def fetch_html_and_js(self) -> tuple:
        """Obtiene HTML y JS principal"""
        html = None
        js_files = []
        
        try:
            resp = await self.client.get(self.url)
            if resp:
                html = await resp.text()
                
                # Extraer JS del HTML
                js_pattern = r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']'
                js_matches = re.findall(js_pattern, html, re.IGNORECASE)
                
                for js in js_matches[:5]:  # Limitar
                    js_url = urljoin(self.url, js)
                    js_files.append(js_url)
                    
        except:
            pass
            
        return html, js_files
        
    def extract_apis(self, content: str, source: str) -> List[Dict]:
        """Extrae APIs de un contenido"""
        apis = []
        
        for pattern, pattern_type in self.api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                    
                if not match or len(match) < 5:
                    continue
                    
                # Normalizar URL
                if match.startswith('//'):
                    full_url = f"{self.parsed.scheme}:{match}"
                elif match.startswith('/'):
                    full_url = urljoin(self.url, match)
                elif match.startswith('http'):
                    full_url = match
                else:
                    continue
                    
                # Verificar si es externa
                parsed = urlparse(full_url)
                if parsed.netloc and parsed.netloc != self.domain:
                    apis.append({
                        'url': full_url,
                        'source': source,
                        'type': pattern_type,
                        'domain': parsed.netloc
                    })
                    
        return apis
        
    async def test_api_security(self, api_url: str) -> List[Dict]:
        """Prueba seguridad de API externa"""
        findings = []
        
        try:
            # Verificar HTTPS
            if not api_url.startswith('https'):
                findings.append({
                    'type': 'API_HTTP',
                    'url': api_url,
                    'severity': 'ALTO',
                    'note': 'API usando HTTP (tráfico no cifrado)'
                })
                
            # Probar acceso
            resp = await self.client.get(api_url)
            
            if resp and resp.status == 200:
                text = await resp.text()
                
                # Verificar datos sensibles
                for pattern in self.sensitive_patterns:
                    if pattern in text.lower():
                        findings.append({
                            'type': 'API_SENSITIVE_DATA',
                            'url': api_url,
                            'pattern': pattern,
                            'severity': 'ALTO'
                        })
                        
                # Verificar si es JSON
                try:
                    data = json.loads(text)
                    findings.append({
                        'type': 'EXTERNAL_API_ACCESSIBLE',
                        'url': api_url,
                        'status': resp.status,
                        'has_data': bool(data),
                        'severity': 'MEDIO'
                    })
                except:
                    pass
                    
        except:
            pass
            
        return findings
        
    async def scan(self):
        """Ejecuta análisis de consumo de APIs"""
        print(f"\n[WEB] API CONSUMPTION v2.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            # Obtener HTML y JS
            print("[*] Analizando HTML y JavaScript...")
            html, js_files = await self.fetch_html_and_js()
            
            if not html:
                print("[!] No se pudo obtener el contenido")
                return []
                
            all_apis = []
            
            # Extraer del HTML
            html_apis = self.extract_apis(html, 'HTML')
            all_apis.extend(html_apis)
            
            # Extraer de JS
            for js_url in js_files:
                try:
                    resp = await self.client.get(js_url)
                    if resp:
                        js_content = await resp.text()
                        js_apis = self.extract_apis(js_content, js_url)
                        all_apis.extend(js_apis)
                except:
                    pass
                    
            # Eliminar duplicados
            unique_apis = {}
            for api in all_apis:
                if api['url'] not in unique_apis:
                    unique_apis[api['url']] = api
                    
            apis = list(unique_apis.values())
            print(f"[*] Encontradas {len(apis)} APIs externas")
            
            # Probar cada API
            for i, api in enumerate(apis[:20]):  # Limitar
                print(f"\n[{i+1}/{min(20, len(apis))}] Analizando: {api['url']}")
                
                # Verificar HTTPS
                findings = await self.test_api_security(api['url'])
                self.findings.extend(findings)
                
                for f in findings:
                    if f['severity'] == 'ALTO':
                        print(f"   [[WARN]] {f['type']}")
                        
                await asyncio.sleep(random.uniform(0.5, 1))
                
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS CONSUMO APIs")
            print("="*70)
            
            if self.findings:
                altos = [f for f in self.findings if f['severity'] == 'ALTO']
                medios = [f for f in self.findings if f['severity'] == 'MEDIO']
                
                if altos:
                    print(f"\n[WARN]  ALTOS: {len(altos)}")
                    for f in altos[:10]:
                        print(f"   • {f['type']}: {f.get('url', '')}")
                        
                if medios:
                    print(f"\n[INFO] MEDIOS: {len(medios)}")
                    
                print(f"\n[OK] TOTAL: {len(self.findings)}")
            else:
                print("\n[OK] Consumo de APIs seguro")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 api_consumption.py <URL>")
        sys.exit(1)
        
    url = sys.argv[1]
    
    checker = APIConsumption(url)
    await checker.scan()

if __name__ == "__main__":
    asyncio.run(main())
