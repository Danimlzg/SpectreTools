#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BUSINESS LOGIC v2.0 - TANQUE EDITION
Workflow flaws · Race conditions · Price manipulation · Coupon abuse
Con verificación de vulnerabilidades
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

class BusinessLogic:
    def __init__(self, url: str, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        
        # Endpoints de negocio
        self.business_endpoints = {
            'cart': ['/cart', '/cart/add', '/cart/remove', '/cart/update'],
            'checkout': ['/checkout', '/checkout/payment', '/checkout/confirm'],
            'order': ['/order', '/order/create', '/order/cancel'],
            'user': ['/user/register', '/user/update', '/user/delete'],
            'payment': ['/payment', '/payment/process', '/payment/refund'],
            'coupon': ['/cart/coupon', '/checkout/coupon', '/coupon/apply'],
        }
        
        # Pruebas de race condition
        self.race_tests = [
            {'name': 'add_to_cart', 'endpoint': '/cart/add', 'method': 'POST', 'data': {'product_id': 1, 'quantity': 1}},
            {'name': 'apply_coupon', 'endpoint': '/cart/coupon', 'method': 'POST', 'data': {'coupon': 'TEST'}},
            {'name': 'create_order', 'endpoint': '/order/create', 'method': 'POST', 'data': {'product_id': 1}},
        ]
        
        # Valores para manipulación
        self.test_quantities = [-1, -10, -999, 0, 0.5, 1.5, 9999]
        self.test_prices = [0, 0.01, 0.99, -1, 999.99]
        self.test_coupons = ['TEST', 'WELCOME10', 'SAVE20', 'FREESHIPPING', 'DISCOUNT']
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    async def test_workflow_skip(self) -> List[Dict]:
        """Prueba saltos en flujo de trabajo"""
        findings = []
        
        # Intentar acceder a checkout sin carrito
        checkout_url = urljoin(self.url, '/checkout')
        cart_url = urljoin(self.url, '/cart')
        
        try:
            # Sin carrito
            resp = await self.client.get(checkout_url)
            if resp and resp.status == 200:
                text = await resp.text()
                if 'payment' in text.lower() or 'order' in text.lower():
                    findings.append({
                        'type': 'WORKFLOW_SKIP',
                        'url': checkout_url,
                        'description': 'Checkout accesible sin carrito',
                        'severity': 'ALTO'
                    })
                    print(f"   [[WARN]] Workflow skip: checkout sin carrito")
                    
            # Primero crear carrito, luego checkout
            # (implementación básica)
            
        except:
            pass
            
        return findings
        
    async def test_quantity_manipulation(self) -> List[Dict]:
        """Prueba manipulación de cantidades"""
        findings = []
        
        cart_add = urljoin(self.url, '/cart/add')
        
        for qty in self.test_quantities:
            try:
                data = {'product_id': 1, 'quantity': qty}
                resp = await self.client.post(cart_add, json=data)
                
                if resp and resp.status == 200:
                    text = await resp.text()
                    if 'added' in text.lower() or 'success' in text.lower():
                        findings.append({
                            'type': 'QUANTITY_MANIPULATION',
                            'url': cart_add,
                            'quantity': qty,
                            'severity': 'ALTO'
                        })
                        print(f"      [[WARN]] Cantidad {qty} aceptada")
                        break
                        
            except:
                pass
                
        return findings
        
    async def test_price_manipulation(self) -> List[Dict]:
        """Prueba manipulación de precios"""
        findings = []
        
        endpoints = ['/cart/update', '/checkout/payment', '/order/create']
        
        for endpoint in endpoints:
            url = urljoin(self.url, endpoint)
            
            for price in self.test_prices:
                try:
                    data = {'product_id': 1, 'price': price}
                    resp = await self.client.post(url, json=data)
                    
                    if resp and resp.status == 200:
                        findings.append({
                            'type': 'PRICE_MANIPULATION',
                            'url': url,
                            'price': price,
                            'severity': 'CRITICO'
                        })
                        print(f"      [[CRITICO]] Precio {price} aceptado")
                        break
                        
                except:
                    pass
                    
        return findings
        
    async def test_coupon_abuse(self) -> List[Dict]:
        """Prueba abuso de cupones"""
        findings = []
        
        endpoints = ['/cart/coupon', '/checkout/coupon', '/coupon/apply']
        
        for endpoint in endpoints:
            url = urljoin(self.url, endpoint)
            
            for coupon in self.test_coupons:
                try:
                    data = {'coupon': coupon}
                    resp = await self.client.post(url, json=data)
                    
                    if resp and resp.status == 200:
                        text = await resp.text()
                        if 'applied' in text.lower() or 'success' in text.lower():
                            findings.append({
                                'type': 'COUPON_ABUSE',
                                'url': url,
                                'coupon': coupon,
                                'severity': 'ALTO'
                            })
                            print(f"      [[WARN]] Cupón {coupon} aceptado")
                            break
                            
                except:
                    pass
                    
        return findings
        
    async def test_race_condition(self) -> List[Dict]:
        """Prueba race conditions"""
        findings = []
        
        for test in self.race_tests:
            url = urljoin(self.url, test['endpoint'])
            
            # Múltiples requests concurrentes
            tasks = []
            for i in range(10):
                data = test['data'].copy()
                if 'product_id' in data:
                    data['product_id'] = i + 1
                tasks.append(self.client.post(url, json=data))
                
            try:
                start = time.time()
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                duration = time.time() - start
                
                # Contar éxitos
                success = 0
                for resp in responses:
                    if isinstance(resp, type(self.client.response)) and resp.status == 200:
                        success += 1
                        
                if success > 1 and duration < 0.5:
                    findings.append({
                        'type': 'RACE_CONDITION',
                        'endpoint': test['endpoint'],
                        'name': test['name'],
                        'success_count': success,
                        'duration': round(duration, 3),
                        'severity': 'ALTO'
                    })
                    print(f"      [[WARN]] Race condition: {success} éxitos en {duration:.3f}s")
                    
            except:
                pass
                
        return findings
        
    async def scan(self):
        """Ejecuta análisis completo"""
        print(f"\n🧠 BUSINESS LOGIC v2.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            # Workflow skip
            print("[*] Probando saltos en flujo...")
            findings = await self.test_workflow_skip()
            self.findings.extend(findings)
            
            # Quantity manipulation
            print("\n[*] Probando manipulación de cantidades...")
            findings = await self.test_quantity_manipulation()
            self.findings.extend(findings)
            
            # Price manipulation
            print("\n[*] Probando manipulación de precios...")
            findings = await self.test_price_manipulation()
            self.findings.extend(findings)
            
            # Coupon abuse
            print("\n[*] Probando abuso de cupones...")
            findings = await self.test_coupon_abuse()
            self.findings.extend(findings)
            
            # Race conditions
            print("\n[*] Probando race conditions...")
            findings = await self.test_race_condition()
            self.findings.extend(findings)
            
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS LÓGICA DE NEGOCIO")
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
                    
                print(f"\n[OK] TOTAL: {len(self.findings)}")
            else:
                print("\n[OK] No se encontraron fallos en lógica de negocio")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 business_logic.py <URL> [--aggressive]")
        sys.exit(1)
        
    url = sys.argv[1]
    aggressive = '--aggressive' in sys.argv
    
    scanner = BusinessLogic(url, aggressive)
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
