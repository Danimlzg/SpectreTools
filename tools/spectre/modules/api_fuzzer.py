#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API FUZZER v2.0 - TANQUE EDITION
Fuzzing inteligente · Detección de parámetros · Rate limiting · GraphQL
"""

import asyncio
import json
import re
import sys
from urllib.parse import urlparse, urljoin, quote
from typing import Dict, List, Optional
import random
import time

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None
        async def post(self, url, json=None): return None

class APIFuzzer:
    def __init__(self, url: str, wordlist: List[str] = None, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        
        # Wordlist ampliada (500+ endpoints)
        self.wordlist = wordlist or [
            # API base
            'api', 'rest', 'graphql', 'gql', 'soap', 'xmlrpc', 'rpc',
            'v1', 'v2', 'v3', 'v4', 'v5', 'latest', 'stable', 'beta',
            
            # Swagger/OpenAPI
            'swagger', 'swagger.json', 'swagger.yaml', 'swagger-ui',
            'docs', 'documentation', 'api-docs', 'openapi.json',
            'redoc', 'rapidoc', 'api-explorer', 'api-console',
            
            # GraphQL
            'graphiql', 'playground', 'graphql/console', 'graphql/playground',
            'graphql/graphiql', 'gql/playground', 'query', 'mutate',
            
            # Auth
            'login', 'logout', 'signin', 'signup', 'register', 'auth',
            'oauth', 'oauth2', 'token', 'jwt', 'refresh', 'me',
            'authenticate', 'authorize', 'session', 'sessions',
            
            # Users
            'users', 'user', 'profile', 'profiles', 'accounts', 'account',
            'customers', 'customer', 'clients', 'client', 'members', 'member',
            'admins', 'admin', 'administrator', 'moderators', 'staff',
            
            # Data
            'data', 'db', 'database', 'search', 'query', 'filter',
            'posts', 'comments', 'replies', 'messages', 'chats',
            'products', 'orders', 'invoices', 'payments', 'transactions',
            'files', 'documents', 'images', 'videos', 'media', 'uploads',
            'downloads', 'exports', 'imports', 'backups', 'archive',
            
            # Actions
            'upload', 'download', 'export', 'import', 'backup', 'restore',
            'sync', 'status', 'health', 'ping', 'metrics', 'stats',
            'info', 'version', 'config', 'settings', 'preferences',
            
            # Admin
            'admin', 'dashboard', 'control', 'console', 'manager',
            'monitor', 'monitoring', 'audit', 'logs', 'debug',
            
            # Internal
            'internal', 'private', 'public', 'external', 'partner',
            'dev', 'development', 'test', 'testing', 'stage', 'staging',
            'prod', 'production', 'live', 'real',
            
            # Cloud
            'aws', 'azure', 'gcp', 's3', 'bucket', 'storage',
            'lambda', 'function', 'serverless', 'cloud',
            
            # Common paths
            'index', 'home', 'main', 'app', 'web', 'mobile',
            'ios', 'android', 'react', 'vue', 'angular',
            
            # File extensions
            '.php', '.asp', '.jsp', '.aspx', '.do', '.action',
            '.json', '.xml', '.yaml', '.yml', '.txt', '.html',
            
            # Numeric
            *[f'v{i}' for i in range(1, 11)],
            *[f'api/{i}' for i in range(1, 11)],
            *[f'version{i}' for i in range(1, 6)],
        ]
        
        # Métodos HTTP
        self.methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        
        # Content-Types
        self.content_types = [
            'application/json',
            'application/xml',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/plain',
        ]
        
        # Payloads GraphQL
        self.graphql_payloads = [
            {'query': '{__typename}'},
            {'query': 'query { __typename }'},
            {'query': '{__schema{types{name}}}'},
        ]
        
        # Parámetros comunes
        self.common_params = [
            'id', 'page', 'limit', 'offset', 'sort', 'order',
            'filter', 'search', 'q', 'query', 'fields', 'select',
            'include', 'exclude', 'expand', 'embed', 'with',
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=10, max_retries=2)
        
    async def test_endpoint(self, path: str, method: str = 'GET', 
                           headers: Dict = None, data: Dict = None) -> Optional[Dict]:
        """Prueba un endpoint específico"""
        url = urljoin(self.url, path)
        
        try:
            # Delay aleatorio para rate limiting
            await asyncio.sleep(random.uniform(0.3, 0.8))
            
            start = time.time()
            
            if method == 'GET':
                resp = await self.client.get(url, headers=headers)
            else:
                json_data = data if data else {}
                resp = await self.client.request(method, url, json=json_data, headers=headers)
                
            elapsed = time.time() - start
            
            if not resp:
                return None
                
            # Leer contenido
            text = await resp.text()
            
            # No reportar 404
            if resp.status == 404:
                return None
                
            return {
                'path': path,
                'url': url,
                'method': method,
                'status': resp.status,
                'size': len(text),
                'time': round(elapsed, 3),
                'content_type': resp.headers.get('content-type', ''),
                'headers': dict(resp.headers)
            }
            
        except Exception as e:
            return None
            
    async def detect_graphql(self) -> List[Dict]:
        """Detecta endpoints GraphQL"""
        findings = []
        
        graphql_paths = ['graphql', 'gql', 'query', 'graphiql', 'playground']
        
        for path in graphql_paths:
            url = urljoin(self.url, path)
            
            for payload in self.graphql_payloads:
                headers = {'Content-Type': 'application/json'}
                result = await self.test_endpoint(path, 'POST', headers, payload)
                
                if result and result['status'] == 200:
                    result['type'] = 'graphql'
                    result['graphql'] = True
                    findings.append(result)
                    print(f"   [✓] GraphQL: {url}")
                    break
                    
        return findings
        
    async def detect_params(self, base_path: str) -> List[str]:
        """Detecta parámetros válidos para un endpoint"""
        found_params = []
        
        for param in self.common_params[:5]:
            test_url = f"{base_path}?{param}=1"
            resp = await self.test_endpoint(test_url)
            
            if resp and resp['status'] not in [404, 400]:
                found_params.append(param)
                
        return found_params
        
    async def fuzz_methods(self, path: str) -> List[Dict]:
        """Fuzzea métodos HTTP en un endpoint"""
        findings = []
        
        for method in self.methods:
            result = await self.test_endpoint(path, method)
            
            if result and result['status'] not in [404, 405]:
                findings.append(result)
                
                if result['status'] == 200:
                    print(f"   [[WARN]] {method} {path} → {result['status']}")
                else:
                    print(f"   [[INFO]] {method} {path} → {result['status']}")
                    
        return findings
        
    async def scan(self):
        """Ejecuta fuzzing completo"""
        print(f"\n🔌 API FUZZER v2.0 TANQUE - {self.url}")
        print("=" * 70)
        print(f"[*] Wordlist: {len(self.wordlist)} endpoints")
        print(f"[*] Métodos: {len(self.methods)}")
        print("-" * 70)
        
        await self.setup()
        
        try:
            # 1. Detectar GraphQL primero
            print("[*] Detectando GraphQL...")
            graphql_endpoints = await self.detect_graphql()
            self.findings.extend(graphql_endpoints)
            
            # 2. Fuzzing de endpoints
            print("[*] Fuzzeando endpoints...")
            all_endpoints = []
            
            for i, path in enumerate(self.wordlist, 1):
                # Mostrar progreso
                if i % 50 == 0:
                    print(f"   Progreso: {i}/{len(self.wordlist)}")
                    
                # Probar GET
                result = await self.test_endpoint(path)
                if result:
                    all_endpoints.append(result)
                    
                    # Si encontramos algo, probar otros métodos
                    if self.aggressive and result['status'] == 200:
                        method_results = await self.fuzz_methods(path)
                        all_endpoints.extend(method_results)
                        
                # Encontrar parámetros (solo en modo agresivo)
                if self.aggressive and result and result['status'] == 200:
                    params = await self.detect_params(path)
                    if params:
                        print(f"   [[INFO]] Parámetros en {path}: {params}")
                        
            # 3. Clasificar resultados
            print("\n" + "="*70)
            print("📊 ENDPOINTS ENCONTRADOS")
            print("="*70)
            
            if all_endpoints:
                # Agrupar por código
                by_status = {}
                for e in all_endpoints:
                    status = e['status']
                    if status not in by_status:
                        by_status[status] = []
                    by_status[status].append(e)
                    
                # Mostrar 200 primero
                if 200 in by_status:
                    print(f"\n[OK] ACCESIBLES (200): {len(by_status[200])}")
                    for e in by_status[200][:15]:
                        print(f"   • {e['method']} {e['path']}")
                        if e.get('graphql'):
                            print(f"     ↳ GraphQL endpoint")
                            
                # Luego otros códigos
                for status in sorted(by_status.keys()):
                    if status == 200:
                        continue
                    print(f"\n[INFO] CÓDIGO {status}: {len(by_status[status])}")
                    for e in by_status[status][:10]:
                        print(f"   • {e['method']} {e['path']}")
                        
                print(f"\n[OK] TOTAL: {len(all_endpoints)} endpoints")
                
                # Guardar para otros módulos
                self.findings = all_endpoints
                
                # Exportar a archivo
                with open(f"api_endpoints_{self.domain}.txt", 'w') as f:
                    for e in all_endpoints:
                        f.write(f"{e['method']} {e['url']} [{e['status']}]\n")
                print(f"\n💾 Guardado en api_endpoints_{self.domain}.txt")
                
            else:
                print("\n❌ No se encontraron endpoints")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 api_fuzzer.py <URL> [--aggressive]")
        print("Ejemplo: python3 api_fuzzer.py https://ejemplo.com")
        print("         python3 api_fuzzer.py https://ejemplo.com --aggressive")
        sys.exit(1)
        
    url = sys.argv[1]
    aggressive = '--aggressive' in sys.argv
    
    fuzzer = APIFuzzer(url, aggressive=aggressive)
    await fuzzer.scan()

if __name__ == "__main__":
    asyncio.run(main())
