#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CLICKJACKING TESTER v2.0 - TANQUE EDITION
X-Frame-Options · CSP frame-ancestors · PoC generator · Multi-endpoint
"""

import asyncio
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional
import random

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class ClickjackingTester:
    def __init__(self, url: str, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        
        # Endpoints a probar
        self.test_paths = [
            '', '/admin', '/login', '/api', '/dashboard',
            '/user/profile', '/settings', '/account', '/payment',
            '/checkout', '/cart', '/orders', '/profile'
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=10, max_retries=2)
        
    async def check_headers(self, url: str) -> Dict:
        """Verifica cabeceras anti-clickjacking"""
        try:
            resp = await self.client.get(url)
            if not resp:
                return {'vulnerable': False, 'reason': 'No response'}
                
            headers = resp.headers
            
            # X-Frame-Options
            xfo = headers.get('x-frame-options', '')
            if xfo:
                if xfo.upper() in ['DENY', 'SAMEORIGIN']:
                    return {
                        'vulnerable': False,
                        'protection': 'X-Frame-Options',
                        'value': xfo
                    }
                else:
                    return {
                        'vulnerable': True,
                        'protection': 'X-Frame-Options',
                        'value': xfo,
                        'note': 'Valor no seguro'
                    }
                    
            # CSP frame-ancestors
            csp = headers.get('content-security-policy', '')
            if 'frame-ancestors' in csp:
                if 'none' in csp or 'self' in csp:
                    return {
                        'vulnerable': False,
                        'protection': 'CSP frame-ancestors',
                        'value': csp
                    }
                else:
                    return {
                        'vulnerable': True,
                        'protection': 'CSP frame-ancestors',
                        'value': csp,
                        'note': 'Permite orígenes externos'
                    }
                    
            # Sin protecciones
            return {
                'vulnerable': True,
                'protection': 'none',
                'note': 'Sin cabeceras anti-clickjacking'
            }
            
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}
            
    async def generate_poc(self, vulnerable_url: str) -> str:
        """Genera PoC HTML"""
        poc = f'''<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC - {self.domain}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .iframe-container {{
            position: relative;
            width: 100%;
            height: 600px;
            border: 2px solid #333;
            margin: 20px 0;
        }}
        iframe {{
            width: 100%;
            height: 100%;
            border: none;
        }}
        .overlay {{
            position: absolute;
            top: 50px;
            left: 50px;
            z-index: 10;
            background: rgba(255,0,0,0.3);
            padding: 20px;
            border: 2px dashed red;
            cursor: pointer;
        }}
        .button {{
            background: #4CAF50;
            color: white;
            padding: 15px 32px;
            text-align: center;
            font-size: 16px;
            border: none;
            cursor: pointer;
        }}
        .warning {{
            background: #ff9800;
            color: white;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🖱️ Clickjacking Proof of Concept</h1>
        <div class="warning">
            <strong>[WARN] ADVERTENCIA:</strong> Esta página demuestra que {vulnerable_url} puede ser embebida en un iframe.
            El botón rojo está posicionado sobre elementos interactivos del sitio objetivo.
        </div>
        
        <h2>Sitio objetivo embebido:</h2>
        <div class="iframe-container">
            <iframe src="{vulnerable_url}" frameborder="1"></iframe>
            <div class="overlay">
                <button class="button" onclick="alert('¡Click engañoso!')">
                    HAZ CLIC AQUÍ (PERO ESTÁS CLICKEANDO EL SITIO)
                </button>
            </div>
        </div>
        
        <h3>Instrucciones:</h3>
        <ol>
            <li>Guarda este archivo como <code>clickjacking_{self.domain}.html</code></li>
            <li>Ábrelo en un navegador</li>
            <li>Si ves el sitio objetivo dentro del iframe, ES VULNERABLE</li>
            <li>Prueba a hacer clic en el botón rojo sobre diferentes áreas</li>
        </ol>
        
        <h3>Detalles técnicos:</h3>
        <ul>
            <li>URL vulnerable: {vulnerable_url}</li>
            <li>Dominio: {self.domain}</li>
            <li>Timestamp: {__import__('datetime').datetime.now().isoformat()}</li>
        </ul>
    </div>
</body>
</html>'''
        return poc
        
    async def scan(self):
        """Ejecuta test de clickjacking"""
        print(f"\n🖱️  CLICKJACKING TESTER v2.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            vulnerable_endpoints = []
            
            for path in self.test_paths:
                test_url = urljoin(self.url, path)
                print(f"\n[*] Probando: {test_url}")
                
                result = await self.check_headers(test_url)
                
                if result.get('vulnerable'):
                    finding = {
                        'type': 'CLICKJACKING_VULNERABLE',
                        'url': test_url,
                        'severity': 'CRITICO',
                        'details': result
                    }
                    self.findings.append(finding)
                    vulnerable_endpoints.append(test_url)
                    
                    print(f"   [[CRITICO]] VULNERABLE - {result.get('note', 'Sin protecciones')}")
                else:
                    protection = result.get('protection', 'desconocida')
                    print(f"   [[OK]] Protegido: {protection}")
                    
            # Generar PoC
            if vulnerable_endpoints:
                poc = await self.generate_poc(vulnerable_endpoints[0])
                filename = f"clickjacking_poc_{self.domain}.html"
                with open(filename, 'w') as f:
                    f.write(poc)
                print(f"\n[[INFO]] PoC guardado en {filename}")
                
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS CLICKJACKING")
            print("="*70)
            
            if self.findings:
                print(f"\n[CRITICO] VULNERABLES: {len(self.findings)}")
                for f in self.findings:
                    print(f"   • {f['url']}")
            else:
                print("\n[OK] Protegido contra clickjacking")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 clickjacking_tester.py <URL>")
        sys.exit(1)
        
    url = sys.argv[1]
    
    tester = ClickjackingTester(url)
    await tester.scan()

if __name__ == "__main__":
    asyncio.run(main())
