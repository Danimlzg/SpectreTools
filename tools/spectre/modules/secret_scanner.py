#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SECRET SCANNER v3.0 - TANQUE EDITION
Busca tokens, claves API, contraseñas y secretos
Filtrado inteligente · Integración con http_client TANQUE
"""

import asyncio
import re
import sys
import json
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class SecretScanner:
    def __init__(self, url: str):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.client = None
        self.findings = []
        
        # Patrones de secretos (igual que antes, mantenemos los mismos)
        self.secret_patterns = {
            'git_config': {
                'pattern': r'\[core\].*repositoryformatversion',
                'name': 'Git Config',
                'severity': 'CRITICO',
                'min_length': 10
            },
            'slack_token': {
                'pattern': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
                'name': 'Slack Token',
                'severity': 'CRITICO',
                'min_length': 10
            },
            'discord_token': {
                'pattern': r'[MN][A-Za-z\d]{23,24}\.[A-Za-z\d]{6}\.[A-Za-z\d\-_]{27,38}',
                'name': 'Discord Token',
                'severity': 'CRITICO',
                'min_length': 50
            },
            'github_token': {
                'pattern': r'github_pat_[a-zA-Z0-9]{22,}|ghp_[a-zA-Z0-9]{36,}',
                'name': 'GitHub Token',
                'severity': 'CRITICO',
                'min_length': 22
            },
            'aws_access_key': {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'name': 'AWS Access Key',
                'severity': 'CRITICO',
                'min_length': 20
            },
            'google_api_key': {
                'pattern': r'AIza[0-9A-Za-z\-_]{35}',
                'name': 'Google API Key',
                'severity': 'CRITICO',
                'min_length': 35
            },
            'stripe_live': {
                'pattern': r'(?:sk|pk)_live_[0-9a-zA-Z]{24,}',
                'name': 'Stripe Live Key',
                'severity': 'CRITICO',
                'min_length': 24
            },
            'private_key': {
                'pattern': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
                'name': 'Private Key',
                'severity': 'CRITICO',
                'min_length': 30
            },
            'jwt_token': {
                'pattern': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
                'name': 'JWT Token',
                'severity': 'ALTO',
                'min_length': 50
            },
        }
        
        # Falsos positivos (librerías conocidas)
        self.false_positive_contexts = [
            'jquery', 'vue', 'angular', 'react', 'bootstrap',
            'lodash', 'moment', 'chart.js', 'd3.js', 'three.js',
            'wordpress', 'wp-', 'plugin', 'theme'
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    def is_false_positive(self, secret: str, context: str) -> bool:
        """Filtro de falsos positivos"""
        secret_lower = secret.lower()
        context_lower = context.lower()
        
        # Código ofuscado
        if '***' in secret or len(set(secret)) < 10:
            return True
            
        # Librerías conocidas
        for lib in self.false_positive_contexts:
            if lib in context_lower:
                return True
                
        # Variables de 1-2 caracteres
        if re.match(r'^[a-z]{1,2}$', secret) or re.match(r'^[0-9]+$', secret):
            return True
            
        # Funciones JS
        if '(' in secret or ')' in secret or 'function' in secret_lower:
            return True
            
        # Longitud
        if len(secret) < 8 or len(secret) > 200:
            return True
            
        return False
        
    def mask_secret(self, secret: str) -> str:
        """Oculta secreto para mostrar"""
        if len(secret) <= 8:
            return '****'
        return secret[:4] + '*' * (len(secret) - 8) + secret[-4:]
        
    async def fetch_content(self, url: str) -> Optional[str]:
        """Obtiene contenido de URL usando http_client"""
        try:
            resp = await self.client.get(url)
            if resp:
                return await resp.text()
        except:
            pass
        return None
        
    def extract_js_files(self, html: str) -> List[str]:
        """Extrae URLs de JS"""
        pattern = r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']'
        matches = re.findall(pattern, html, re.IGNORECASE)
        
        js_files = []
        for match in matches:
            url = match.split('?')[0].split('#')[0]
            full_url = urljoin(self.url, url)
            js_files.append(full_url)
            
        return list(set(js_files))
        
    def scan_content(self, content: str, source: str) -> List[Dict]:
        """Escanea contenido buscando secretos"""
        findings = []
        
        for secret_type, data in self.secret_patterns.items():
            matches = re.findall(data['pattern'], content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match else ''
                    
                if not match or len(match) < data['min_length']:
                    continue
                    
                if self.is_false_positive(match, source):
                    continue
                    
                findings.append({
                    'type': data['name'],
                    'secret': self.mask_secret(match),
                    'source': source,
                    'severity': data['severity']
                })
                
        return findings
        
    async def scan(self):
        """Ejecuta escaneo completo"""
        print(f"\n[SECURE] SECRET SCANNER v3.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            # 1. HTML principal
            print("[*] Analizando HTML principal...")
            html = await self.fetch_content(self.url)
            
            if html:
                findings = self.scan_content(html, 'HTML principal')
                self.findings.extend(findings)
                
                # 2. Extraer JS
                js_files = self.extract_js_files(html)
                print(f"[*] Analizando {len(js_files)} archivos JS...")
                
                for js_url in js_files:
                    js_content = await self.fetch_content(js_url)
                    if js_content:
                        js_findings = self.scan_content(js_content, js_url)
                        self.findings.extend(js_findings)
                        
            # Resultados
            print("\n" + "="*70)
            print("📊 SECRETOS ENCONTRADOS")
            print("="*70)
            
            if self.findings:
                criticos = [f for f in self.findings if f['severity'] == 'CRITICO']
                altos = [f for f in self.findings if f['severity'] == 'ALTO']
                
                if criticos:
                    print(f"\n[CRITICO] CRÍTICOS: {len(criticos)}")
                    for f in criticos:
                        print(f"   • {f['type']}: {f['secret']}")
                        print(f"     ↳ {f['source']}")
                        
                if altos:
                    print(f"\n[WARN]  ALTOS: {len(altos)}")
                    
                print(f"\n[OK] TOTAL: {len(self.findings)}")
            else:
                print("\n[OK] No se encontraron secretos")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 secret_scanner.py <URL>")
        sys.exit(1)
        
    scanner = SecretScanner(sys.argv[1])
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
