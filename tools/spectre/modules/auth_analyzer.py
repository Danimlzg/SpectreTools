#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AUTH ANALYZER v2.0 - TANQUE EDITION
Rate limiting · OAuth · SAML · 2FA bypass · JWT · Session fixation
Con pruebas de fuerza bruta controladas
"""

import asyncio
import time
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
        async def post(self, url, json=None): return None

class AuthAnalyzer:
    def __init__(self, url: str, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        
        # Endpoints de autenticación
        self.auth_endpoints = [
            '/login', '/signin', '/auth', '/oauth', '/oauth2',
            '/saml', '/sso', '/token', '/jwt', '/api/auth',
            '/2fa', '/mfa', '/verify', '/validate',
            '/user/login', '/admin/login', '/api/login',
            '/auth/login', '/auth/oauth', '/auth/token',
            '/oauth/token', '/oauth/authorize', '/oauth/revoke',
        ]
        
        # Credenciales para pruebas
        self.test_creds = [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': '123456'},
            {'username': 'admin', 'password': 'password'},
            {'username': 'user', 'password': 'user'},
            {'username': 'test', 'password': 'test'},
            {'username': 'root', 'password': 'root'},
            {'username': 'administrator', 'password': 'administrator'},
        ]
        
        # Headers de rate limiting
        self.rate_limit_headers = [
            'X-RateLimit-Limit', 'X-RateLimit-Remaining',
            'X-RateLimit-Reset', 'Retry-After',
            'RateLimit-Limit', 'RateLimit-Remaining',
        ]
        
        # Códigos 2FA comunes
        self.common_2fa = ['000000', '123456', '111111', '999999']
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    async def test_rate_limiting(self, endpoint: str) -> List[Dict]:
        """Prueba rate limiting con múltiples intentos"""
        findings = []
        url = urljoin(self.url, endpoint)
        
        print(f"   Probando rate limiting en {endpoint}...")
        
        responses = []
        start_time = time.time()
        
        # 20 intentos rápidos
        for i in range(20):
            cred = self.test_creds[i % len(self.test_creds)]
            resp = await self.client.post(url, json=cred)
            
            if resp:
                responses.append(resp.status)
                
                # Verificar headers
                for header in self.rate_limit_headers:
                    if header in resp.headers:
                        findings.append({
                            'type': 'RATE_LIMIT_HEADER',
                            'endpoint': endpoint,
                            'header': header,
                            'value': resp.headers[header],
                            'severity': 'INFO'
                        })
                        
            await asyncio.sleep(0.1)  # Pequeño delay
            
        duration = time.time() - start_time
        
        # Analizar si hay rate limiting
        if len(set(responses)) == 1 and responses[0] in [200, 401, 403]:
            # Todas iguales, probablemente sin rate limiting
            findings.append({
                'type': 'NO_RATE_LIMITING',
                'endpoint': endpoint,
                'requests': len(responses),
                'duration': round(duration, 2),
                'severity': 'ALTO',
                'note': f"{len(responses)} intentos en {duration:.1f}s sin bloqueo"
            })
            print(f"      [[WARN]] Sin rate limiting: {len(responses)} intentos")
            
        return findings
        
    async def test_oauth_flows(self) -> List[Dict]:
        """Prueba endpoints OAuth"""
        findings = []
        
        oauth_endpoints = [
            '/oauth/authorize', '/oauth/token', '/oauth/revoke',
            '/oauth2/authorize', '/oauth2/token', '/oauth2/revoke',
        ]
        
        for endpoint in oauth_endpoints:
            url = urljoin(self.url, endpoint)
            resp = await self.client.get(url)
            
            if resp and resp.status != 404:
                findings.append({
                    'type': 'OAUTH_ENDPOINT',
                    'endpoint': endpoint,
                    'status': resp.status,
                    'severity': 'INFO'
                })
                print(f"   [[INFO]] Endpoint OAuth: {endpoint}")
                
        return findings
        
    async def test_2fa_bypass(self) -> List[Dict]:
        """Prueba bypass de 2FA"""
        findings = []
        
        twofa_endpoints = ['/2fa', '/mfa', '/verify-2fa', '/2fa/verify']
        
        for endpoint in twofa_endpoints:
            url = urljoin(self.url, endpoint)
            
            # 1. Probar sin código
            resp = await self.client.post(url, json={})
            if resp and resp.status == 200:
                findings.append({
                    'type': '2FA_BYPASS_EMPTY',
                    'endpoint': endpoint,
                    'severity': 'CRITICO'
                })
                print(f"      [[CRITICO]] 2FA bypass: código vacío aceptado")
                
            # 2. Probar códigos comunes
            for code in self.common_2fa:
                resp = await self.client.post(url, json={'code': code})
                if resp and resp.status == 200:
                    findings.append({
                        'type': '2FA_WEAK_CODE',
                        'endpoint': endpoint,
                        'code': code,
                        'severity': 'ALTO'
                    })
                    print(f"      [[WARN]] 2FA débil: código {code} aceptado")
                    break
                    
        return findings
        
    async def test_saml(self) -> List[Dict]:
        """Prueba endpoints SAML"""
        findings = []
        
        saml_paths = ['/saml', '/sso', '/Shibboleth.sso', '/auth/saml']
        
        for path in saml_paths:
            url = urljoin(self.url, path)
            resp = await self.client.get(url)
            
            if resp and resp.status != 404:
                text = await resp.text()
                if 'SAML' in text or 'saml' in text or 'Shibboleth' in text:
                    findings.append({
                        'type': 'SAML_ENDPOINT',
                        'endpoint': path,
                        'severity': 'INFO'
                    })
                    print(f"   [[INFO]] Endpoint SAML: {path}")
                    
        return findings
        
    async def test_session_fixation(self) -> List[Dict]:
        """Prueba session fixation"""
        findings = []
        
        login_url = urljoin(self.url, '/login')
        
        # Obtener cookie antes de login
        resp = await self.client.get(self.url)
        if not resp:
            return findings
            
        cookies_before = resp.headers.get('set-cookie', '')
        
        # Intentar login
        for cred in self.test_creds[:2]:
            resp = await self.client.post(login_url, json=cred)
            if resp:
                cookies_after = resp.headers.get('set-cookie', '')
                
                # Verificar si la cookie cambió
                if cookies_before and cookies_before == cookies_after:
                    findings.append({
                        'type': 'SESSION_FIXATION',
                        'endpoint': login_url,
                        'severity': 'ALTO',
                        'note': 'La cookie no cambia después del login'
                    })
                    print(f"      [[WARN]] Posible session fixation")
                    
        return findings
        
    async def scan(self):
        """Ejecuta análisis completo"""
        print(f"\n[SECURE] AUTH ANALYZER v2.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            # Rate limiting
            print("[*] Probando rate limiting...")
            for endpoint in self.auth_endpoints[:5]:  # Limitar
                findings = await self.test_rate_limiting(endpoint)
                self.findings.extend(findings)
                await asyncio.sleep(1)
                
            # OAuth
            print("\n[*] Analizando OAuth...")
            findings = await self.test_oauth_flows()
            self.findings.extend(findings)
            
            # 2FA Bypass
            print("\n[*] Probando bypass de 2FA...")
            findings = await self.test_2fa_bypass()
            self.findings.extend(findings)
            
            # SAML
            print("\n[*] Analizando SAML...")
            findings = await self.test_saml()
            self.findings.extend(findings)
            
            # Session fixation (aggressive)
            if self.aggressive:
                print("\n[*] Probando session fixation...")
                findings = await self.test_session_fixation()
                self.findings.extend(findings)
                
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS AUTENTICACIÓN")
            print("="*70)
            
            if self.findings:
                criticos = [f for f in self.findings if f['severity'] == 'CRITICO']
                altos = [f for f in self.findings if f['severity'] == 'ALTO']
                
                if criticos:
                    print(f"\n[CRITICO] CRÍTICOS: {len(criticos)}")
                    for f in criticos:
                        print(f"   • {f['type']}")
                        
                if altos:
                    print(f"\n[WARN]  ALTOS: {len(altos)}")
                    for f in altos[:5]:
                        print(f"   • {f['type']} en {f.get('endpoint', '')}")
                        
                print(f"\n[OK] TOTAL: {len(self.findings)}")
            else:
                print("\n[OK] No se encontraron problemas de autenticación")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 auth_analyzer.py <URL> [--aggressive]")
        sys.exit(1)
        
    url = sys.argv[1]
    aggressive = '--aggressive' in sys.argv
    
    analyzer = AuthAnalyzer(url, aggressive)
    await analyzer.scan()

if __name__ == "__main__":
    asyncio.run(main())
