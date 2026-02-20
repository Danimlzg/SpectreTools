#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CORS SCANNER v2.0 - TANQUE EDITION
Detección de CORS misconfig · Credentials · Wildcards · Null origin
Con fuzzing de orígenes
"""

import asyncio
import random
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url, headers=None): return None

class CORSScanner:
    def __init__(self, url: str, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.scheme = self.parsed.scheme
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        
        # Orígenes de prueba
        self.test_origins = [
            # Mismo origen
            f"{self.scheme}://{self.domain}",
            f"{self.scheme}://{self.domain}:8080",
            f"{self.scheme}://www.{self.domain}",
            
            # Orígenes maliciosos
            "https://evil.com",
            "http://evil.com",
            "https://evil.org",
            "http://evil.org",
            "null",
            "file://",
            "http://localhost",
            "https://localhost",
            "http://127.0.0.1",
            "https://127.0.0.1",
            
            # Subdominios
            f"https://{self.domain}.evil.com",
            f"https://evil{self.domain}",
            f"https://evil-{self.domain}.com",
            
            # Codificados
            f"https://{self.domain}%40evil.com",
            f"https://evil.com#{self.domain}",
            f"https://evil.com/?{self.domain}",
        ]
        
        # Endpoints a probar
        self.test_paths = [
            '', '/api', '/api/v1', '/graphql', '/rest',
            '/user', '/users', '/auth', '/login', '/data',
            '/api/user', '/api/users', '/api/data', '/api/auth',
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=10, max_retries=2)
        
    async def test_cors(self, url: str, origin: str) -> Optional[Dict]:
        """Prueba CORS para un origen específico"""
        try:
            headers = {
                'Origin': origin,
                'Host': self.domain
            }
            
            resp = await self.client.get(url, headers=headers)
            
            if not resp:
                return None
                
            # Verificar cabeceras CORS
            allow_origin = resp.headers.get('access-control-allow-origin', '')
            allow_credentials = resp.headers.get('access-control-allow-credentials', '')
            allow_methods = resp.headers.get('access-control-allow-methods', '')
            
            if not allow_origin:
                return None
                
            issues = []
            severity = 'INFO'
            
            # 1. Wildcard peligroso
            if allow_origin == '*':
                issues.append("Access-Control-Allow-Origin: *")
                severity = 'ALTO'
                
            # 2. Null origin
            elif allow_origin == 'null':
                issues.append("Access-Control-Allow-Origin: null")
                severity = 'ALTO'
                
            # 3. Refleja origen (misconfig)
            elif origin != allow_origin and allow_origin != '*':
                if origin in allow_origin or allow_origin.endswith(origin):
                    issues.append(f"Refleja origen: {allow_origin}")
                    severity = 'MEDIO'
                    
            # 4. Credenciales + wildcard = CRÍTICO
            if allow_credentials == 'true' and allow_origin == '*':
                issues.append("Credenciales permitidas con origen * (CRÍTICO)")
                severity = 'CRITICO'
                
            # 5. Credenciales a origen externo
            elif allow_credentials == 'true' and allow_origin not in [f"{self.scheme}://{self.domain}"]:
                issues.append(f"Credenciales a origen externo: {allow_origin}")
                severity = 'ALTO'
                
            # 6. Métodos peligrosos
            if allow_methods and '*' in allow_methods:
                issues.append("Métodos permitidos: *")
                if severity not in ['CRITICO', 'ALTO']:
                    severity = 'MEDIO'
                    
            if issues:
                return {
                    'url': url,
                    'origin': origin,
                    'allow_origin': allow_origin,
                    'allow_credentials': allow_credentials,
                    'allow_methods': allow_methods,
                    'issues': issues,
                    'severity': severity
                }
                
        except Exception as e:
            pass
        return None
        
    async def scan(self):
        """Ejecuta escaneo CORS"""
        print(f"\n🌍 CORS SCANNER v2.0 TANQUE - {self.url}")
        print("=" * 70)
        print(f"[*] Orígenes: {len(self.test_origins)}")
        print(f"[*] Endpoints: {len(self.test_paths)}")
        print("-" * 70)
        
        await self.setup()
        
        try:
            for path in self.test_paths:
                test_url = urljoin(self.url, path)
                print(f"\n[*] Probando: {test_url}")
                
                for origin in self.test_origins:
                    result = await self.test_cors(test_url, origin)
                    
                    if result:
                        self.findings.append(result)
                        
                        icon = '[CRITICO]' if result['severity'] == 'CRITICO' else '[WARN]'
                        print(f"   [{icon}] {origin}")
                        for issue in result['issues']:
                            print(f"        ↳ {issue}")
                            
                    await asyncio.sleep(random.uniform(0.1, 0.3))
                    
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS CORS")
            print("="*70)
            
            if self.findings:
                criticos = [f for f in self.findings if f['severity'] == 'CRITICO']
                altos = [f for f in self.findings if f['severity'] == 'ALTO']
                medios = [f for f in self.findings if f['severity'] == 'MEDIO']
                
                if criticos:
                    print(f"\n[CRITICO] CRÍTICOS: {len(criticos)}")
                    for f in criticos[:5]:
                        print(f"   • {f['url']} - {f['issues'][0]}")
                        
                if altos:
                    print(f"\n[WARN]  ALTOS: {len(altos)}")
                    
                if medios:
                    print(f"\n[INFO] MEDIOS: {len(medios)}")
                    
                print(f"\n[OK] TOTAL: {len(self.findings)}")
            else:
                print("\n[OK] No se encontraron problemas CORS")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 cors_scanner.py <URL>")
        sys.exit(1)
        
    url = sys.argv[1]
    
    scanner = CORSScanner(url)
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
