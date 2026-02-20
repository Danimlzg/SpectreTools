#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CLIENT STORAGE v2.0 - TANQUE EDITION
Cookies · localStorage · sessionStorage · IndexedDB
Con análisis de seguridad y detección de JWT
"""

import asyncio
import json
import re
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Optional

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    print("[!] Playwright no instalado. Usando modo básico.")

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class ClientStorage:
    def __init__(self, url: str, headless: bool = True):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.headless = headless
        self.client = None
        self.findings = []
        
        # Patrones de cookies inseguras
        self.insecure_cookie_issues = {
            'secure': 'Sin flag Secure - enviada en HTTP',
            'httponly': 'Sin flag HttpOnly - accesible desde JS',
            'samesite': 'Sin flag SameSite - vulnerable a CSRF',
            'domain': 'Dominio amplio - enviada a subdominios',
        }
        
        # Patrones de datos sensibles
        self.sensitive_patterns = [
            'token', 'jwt', 'session', 'user', 'pass', 'key', 'secret',
            'auth', 'credentials', 'password', 'contraseña', 'api_key',
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    async def scan_with_playwright(self) -> Dict:
        """Escaneo completo con Playwright"""
        if not PLAYWRIGHT_AVAILABLE:
            return {'error': 'Playwright no disponible'}
            
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'
            )
            page = await context.new_page()
            
            try:
                print("[*] Navegando con Playwright...")
                await page.goto(self.url, timeout=30000, wait_until='domcontentloaded')
                await asyncio.sleep(3)
                
                # Cookies
                cookies = await context.cookies()
                
                # localStorage
                local_storage = await page.evaluate('() => JSON.stringify(localStorage)')
                local_storage = json.loads(local_storage) if local_storage else {}
                
                # sessionStorage
                session_storage = await page.evaluate('() => JSON.stringify(sessionStorage)')
                session_storage = json.loads(session_storage) if session_storage else {}
                
                # IndexedDB
                has_indexeddb = await page.evaluate('''() => {
                    return new Promise(resolve => {
                        const request = indexedDB.databases();
                        request.then(dbs => resolve(dbs.length > 0))
                               .catch(() => resolve(false));
                    });
                }''')
                
                await browser.close()
                
                return {
                    'cookies': cookies,
                    'localStorage': local_storage,
                    'sessionStorage': session_storage,
                    'hasIndexedDB': has_indexeddb
                }
                
            except Exception as e:
                await browser.close()
                return {'error': str(e)}
                
    async def scan_basic(self) -> Dict:
        """Escaneo básico sin Playwright"""
        try:
            resp = await self.client.get(self.url)
            if not resp:
                return {'error': 'No response'}
                
            # Cookies de headers
            cookies = []
            set_cookie = resp.headers.get('set-cookie', '')
            if set_cookie:
                # Parseo básico
                for cookie in set_cookie.split(','):
                    if '=' in cookie:
                        name = cookie.split('=')[0].strip()
                        cookies.append({'name': name, 'value': '***'})
                        
            return {
                'cookies': cookies,
                'localStorage': {},
                'sessionStorage': {},
                'hasIndexedDB': False,
                'mode': 'basic'
            }
            
        except Exception as e:
            return {'error': str(e)}
            
    def analyze_cookies(self, cookies: List[Dict]) -> List[Dict]:
        """Analiza cookies en busca de inseguridades"""
        findings = []
        
        for cookie in cookies:
            issues = []
            
            # Secure flag
            if not cookie.get('secure', False):
                issues.append(self.insecure_cookie_issues['secure'])
                
            # HttpOnly flag
            if not cookie.get('httpOnly', False):
                issues.append(self.insecure_cookie_issues['httponly'])
                
            # SameSite
            same_site = cookie.get('sameSite', '').lower()
            if not same_site:
                issues.append(self.insecure_cookie_issues['samesite'])
            elif same_site == 'none' and cookie.get('secure', False):
                # SameSite=None con Secure es aceptable
                pass
                
            # Domain
            domain = cookie.get('domain', '')
            if domain.startswith('.'):
                issues.append(f"Dominio amplio: {domain}")
                
            if issues:
                findings.append({
                    'type': 'INSECURE_COOKIE',
                    'name': cookie.get('name', 'unknown'),
                    'issues': issues,
                    'severity': 'ALTO'
                })
                
        return findings
        
    def analyze_storage(self, storage: Dict, storage_type: str) -> List[Dict]:
        """Analiza localStorage/sessionStorage"""
        findings = []
        
        for key, value in storage.items():
            # Buscar patrones sensibles
            for pattern in self.sensitive_patterns:
                if pattern in key.lower():
                    findings.append({
                        'type': f'SENSITIVE_{storage_type.upper()}',
                        'key': key,
                        'value_preview': str(value)[:50] + '...' if len(str(value)) > 50 else str(value),
                        'pattern': pattern,
                        'severity': 'ALTO'
                    })
                    break
                    
            # Detectar JWT
            if isinstance(value, str) and value.startswith('eyJ') and len(value) > 50:
                findings.append({
                    'type': f'JWT_IN_{storage_type.upper()}',
                    'key': key,
                    'value_preview': value[:30] + '...',
                    'severity': 'CRITICO'
                })
                
        return findings
        
    async def scan(self):
        """Ejecuta análisis completo"""
        print(f"\n💾 CLIENT STORAGE v2.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            # Escanear con Playwright si disponible
            if PLAYWRIGHT_AVAILABLE:
                data = await self.scan_with_playwright()
            else:
                data = await self.scan_basic()
                
            if 'error' in data:
                print(f"[!] Error: {data['error']}")
                return []
                
            # Analizar cookies
            if data.get('cookies'):
                print(f"\n[*] Analizando {len(data['cookies'])} cookies...")
                cookie_findings = self.analyze_cookies(data['cookies'])
                self.findings.extend(cookie_findings)
                
                for f in cookie_findings:
                    print(f"   [[WARN]] Cookie insegura: {f['name']}")
                    for issue in f['issues']:
                        print(f"        ↳ {issue}")
                        
            # Analizar localStorage
            if data.get('localStorage'):
                print(f"\n[*] Analizando localStorage ({len(data['localStorage'])} items)...")
                ls_findings = self.analyze_storage(data['localStorage'], 'LOCALSTORAGE')
                self.findings.extend(ls_findings)
                
                for f in ls_findings:
                    if f['severity'] == 'CRITICO':
                        print(f"   [[CRITICO]] {f['type']}: {f['key']}")
                    else:
                        print(f"   [[WARN]] {f['type']}: {f['key']}")
                        
            # Analizar sessionStorage
            if data.get('sessionStorage'):
                print(f"\n[*] Analizando sessionStorage ({len(data['sessionStorage'])} items)...")
                ss_findings = self.analyze_storage(data['sessionStorage'], 'SESSIONSTORAGE')
                self.findings.extend(ss_findings)
                
            # IndexedDB
            if data.get('hasIndexedDB'):
                self.findings.append({
                    'type': 'INDEXEDDB_PRESENT',
                    'severity': 'INFO',
                    'note': 'IndexedDB en uso - puede contener datos'
                })
                print(f"\n[ℹ️] IndexedDB detectado")
                
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS ALMACENAMIENTO CLIENTE")
            print("="*70)
            
            if self.findings:
                criticos = [f for f in self.findings if f['severity'] == 'CRITICO']
                altos = [f for f in self.findings if f['severity'] == 'ALTO']
                
                if criticos:
                    print(f"\n[CRITICO] CRÍTICOS: {len(criticos)}")
                    for f in criticos:
                        print(f"   • {f['type']}: {f.get('key', f.get('name', ''))}")
                        
                if altos:
                    print(f"\n[WARN]  ALTOS: {len(altos)}")
                    
                print(f"\n[OK] TOTAL: {len(self.findings)}")
            else:
                print("\n[OK] Almacenamiento cliente seguro")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 client_storage.py <URL>")
        sys.exit(1)
        
    url = sys.argv[1]
    
    scanner = ClientStorage(url)
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
