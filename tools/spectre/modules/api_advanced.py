#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API ADVANCED v2.0 - TANQUE EDITION
WebSockets · gRPC · Serverless · OpenAPI · GraphQL
Con detección automática y fuzzing
"""

import asyncio
import json
import re
import random
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional
import websockets

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class APIAdvanced:
    def __init__(self, url: str, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.scheme = self.parsed.scheme
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        
        # OpenAPI/Swagger paths
        self.openapi_paths = [
            '/swagger', '/swagger.json', '/swagger.yaml', '/swagger-ui',
            '/api-docs', '/docs', '/openapi.json', '/openapi.yaml',
            '/v2/api-docs', '/v3/api-docs', '/api/swagger',
            '/swagger/index.html', '/swagger-ui.html', '/api/docs',
            '/swagger/v1/swagger.json', '/swagger/v1/swagger.yaml',
            '/.well-known/openid-configuration', '/.well-known/swagger',
        ]
        
        # WebSocket paths
        self.websocket_paths = [
            '/ws', '/websocket', '/socket', '/sock', '/chat',
            '/notifications', '/realtime', '/live', '/stream',
            '/ws/v1', '/ws/v2', '/api/ws', '/api/websocket',
            '/socket.io', '/socket.io/', '/socket.io/?transport=websocket',
        ]
        
        # Serverless/FaaS paths
        self.serverless_paths = [
            '/.netlify/functions', '/.vercel/api', '/.now/api',
            '/api/lambda', '/lambda', '/functions', '/api/functions',
            '/prod', '/dev', '/stage', '/api/prod', '/api/dev',
            '/prod/api', '/dev/api', '/stage/api',
            '/.functions', '/.netlify', '/.vercel', '/.now',
        ]
        
        # gRPC paths
        self.grpc_paths = [
            '/grpc', '/grpc-web', '/grpc.reflection', '/grpc.health',
            '/grpc.health.v1', '/grpc.reflection.v1alpha',
            '/api/grpc', '/v1/grpc', '/v2/grpc',
        ]
        
        # GraphQL paths
        self.graphql_paths = [
            '/graphql', '/gql', '/graphiql', '/playground',
            '/api/graphql', '/v1/graphql', '/v2/graphql',
            '/query', '/api/query', '/gql/query',
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    async def scan_openapi(self) -> List[Dict]:
        """Busca documentación OpenAPI"""
        findings = []
        
        for path in self.openapi_paths:
            url = urljoin(self.url, path)
            try:
                resp = await self.client.get(url)
                
                if resp and resp.status == 200:
                    text = await resp.text()
                    
                    # Detectar JSON OpenAPI
                    try:
                        data = json.loads(text)
                        if 'swagger' in data or 'openapi' in data:
                            findings.append({
                                'type': 'OPENAPI_DOC',
                                'url': url,
                                'version': data.get('openapi', data.get('swagger', 'unknown')),
                                'severity': 'INFO'
                            })
                            print(f"   [📖] OpenAPI: {url}")
                    except:
                        # Detectar HTML Swagger
                        if 'swagger' in text.lower() or 'openapi' in text.lower():
                            findings.append({
                                'type': 'OPENAPI_UI',
                                'url': url,
                                'severity': 'INFO'
                            })
                            print(f"   [📖] Swagger UI: {url}")
                            
                await asyncio.sleep(random.uniform(0.3, 0.7))
                
            except:
                pass
                
        return findings
        
    async def detect_websockets(self) -> List[Dict]:
        """Detecta endpoints WebSocket"""
        findings = []
        
        for path in self.websocket_paths:
            ws_url = f"ws://{self.domain}{path}" if self.scheme == 'http' else f"wss://{self.domain}{path}"
            
            try:
                async with websockets.connect(ws_url, timeout=5) as ws:
                    findings.append({
                        'type': 'WEBSOCKET',
                        'url': ws_url,
                        'severity': 'INFO'
                    })
                    print(f"   [🔌] WebSocket activo: {ws_url}")
            except:
                pass
                
        return findings
        
    async def scan_serverless(self) -> List[Dict]:
        """Busca funciones serverless"""
        findings = []
        
        for path in self.serverless_paths:
            url = urljoin(self.url, path)
            try:
                resp = await self.client.get(url)
                
                if resp and resp.status != 404:
                    findings.append({
                        'type': 'SERVERLESS_ENDPOINT',
                        'url': url,
                        'status': resp.status,
                        'severity': 'INFO'
                    })
                    print(f"   [⚡] Serverless: {url}")
                    
                await asyncio.sleep(random.uniform(0.3, 0.7))
                
            except:
                pass
                
        return findings
        
    async def scan_grpc(self) -> List[Dict]:
        """Detecta endpoints gRPC"""
        findings = []
        
        for path in self.grpc_paths:
            url = urljoin(self.url, path)
            try:
                # Headers específicos de gRPC
                headers = {
                    'Content-Type': 'application/grpc',
                    'X-Grpc-Web': '1',
                    'TE': 'trailers'
                }
                
                resp = await self.client.get(url, headers=headers)
                
                if resp and resp.status != 404:
                    findings.append({
                        'type': 'GRPC_ENDPOINT',
                        'url': url,
                        'status': resp.status,
                        'severity': 'INFO'
                    })
                    print(f"   [📡] Posible gRPC: {url}")
                    
                await asyncio.sleep(random.uniform(0.3, 0.7))
                
            except:
                pass
                
        return findings
        
    async def scan_graphql(self) -> List[Dict]:
        """Detecta endpoints GraphQL"""
        findings = []
        
        for path in self.graphql_paths:
            url = urljoin(self.url, path)
            try:
                # Probar query simple
                payload = {'query': '{__typename}'}
                resp = await self.client.post(url, json=payload)
                
                if resp and resp.status == 200:
                    text = await resp.text()
                    if '"data"' in text or '__typename' in text:
                        findings.append({
                            'type': 'GRAPHQL_ENDPOINT',
                            'url': url,
                            'severity': 'ALTO'
                        })
                        print(f"   [🔮] GraphQL: {url}")
                        
                await asyncio.sleep(random.uniform(0.3, 0.7))
                
            except:
                pass
                
        return findings
        
    async def scan(self):
        """Ejecuta análisis completo"""
        print(f"\n⚙️  API ADVANCED v2.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            # OpenAPI
            print("[*] Buscando OpenAPI/Swagger...")
            findings = await self.scan_openapi()
            self.findings.extend(findings)
            
            # WebSockets
            print("\n[*] Detectando WebSockets...")
            findings = await self.detect_websockets()
            self.findings.extend(findings)
            
            # Serverless
            print("\n[*] Escaneando funciones serverless...")
            findings = await self.scan_serverless()
            self.findings.extend(findings)
            
            # gRPC
            print("\n[*] Buscando endpoints gRPC...")
            findings = await self.scan_grpc()
            self.findings.extend(findings)
            
            # GraphQL
            print("\n[*] Detectando GraphQL...")
            findings = await self.scan_graphql()
            self.findings.extend(findings)
            
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS API AVANZADA")
            print("="*70)
            
            if self.findings:
                print(f"\n[INFO] Hallazgos: {len(self.findings)}")
                for f in self.findings:
                    print(f"   • {f['type']}: {f.get('url', '')}")
            else:
                print("\n[OK] No se encontraron APIs adicionales")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 api_advanced.py <URL>")
        sys.exit(1)
        
    url = sys.argv[1]
    
    scanner = APIAdvanced(url)
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
