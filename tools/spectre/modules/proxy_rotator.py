#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PROXY ROTATOR v2.0 - TANQUE EDITION
Rotación inteligente de proxies · Test de velocidad · Fallback automático
Con lista de proxies públicos y soporte para autenticación
"""

import asyncio
import random
import time
from typing import Dict, List, Optional, Tuple

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url, proxy=None): return None

class ProxyRotator:
    def __init__(self, target: str, proxies_file: str = None, test_url: str = "http://httpbin.org/ip"):
        self.target = target
        self.test_url = test_url
        self.proxies = []
        self.working_proxies = []
        self.proxy_stats = {}
        self.client = None
        
        # Proxies públicos (para pruebas)
        self.default_proxies = [
            # Formato: protocol://ip:port
            # Nota: Estos son proxies de ejemplo, en producción usar una lista real
        ]
        
        if proxies_file:
            self.load_proxies(proxies_file)
        else:
            self.proxies = self.default_proxies
            
    def load_proxies(self, filename: str):
        """Carga proxies desde archivo"""
        try:
            with open(filename, 'r') as f:
                for line in f:
                    proxy = line.strip()
                    if proxy and not proxy.startswith('#'):
                        self.proxies.append(proxy)
            print(f"[*] Cargados {len(self.proxies)} proxies de {filename}")
        except Exception as e:
            print(f"[!] Error cargando proxies: {e}")
            
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=1)
        
    async def test_proxy(self, proxy: str) -> Tuple[bool, float, str]:
        """Prueba un proxy individual"""
        try:
            start = time.time()
            resp = await self.client.get(self.test_url, proxy=proxy)
            elapsed = time.time() - start
            
            if resp and resp.status == 200:
                data = await resp.json()
                ip = data.get('origin', 'unknown')
                return True, elapsed, ip
        except:
            pass
        return False, 0, ''
        
    async def test_all_proxies(self, max_concurrent: int = 20) -> List[Dict]:
        """Prueba todos los proxies en paralelo"""
        print(f"\n🔍 Probando {len(self.proxies)} proxies...")
        
        # Limitar concurrencia
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def test_with_semaphore(proxy):
            async with semaphore:
                success, speed, ip = await self.test_proxy(proxy)
                if success:
                    self.proxy_stats[proxy] = {
                        'speed': speed,
                        'ip': ip,
                        'last_used': 0
                    }
                    return {'proxy': proxy, 'speed': speed, 'ip': ip}
                return None
                
        tasks = [test_with_semaphore(p) for p in self.proxies]
        results = await asyncio.gather(*tasks)
        
        working = [r for r in results if r]
        self.working_proxies = [r['proxy'] for r in working]
        
        # Ordenar por velocidad
        working.sort(key=lambda x: x['speed'])
        
        print(f"\n[OK] Proxies funcionales: {len(working)}/{len(self.proxies)}")
        
        # Mostrar top 5
        if working:
            print("\n⚡ Top 5 más rápidos:")
            for i, w in enumerate(working[:5], 1):
                print(f"   {i}. {w['proxy']} - {w['speed']:.3f}s - IP: {w['ip']}")
                
        return working
        
    async def get_proxy(self, strategy: str = 'fastest') -> Optional[str]:
        """Obtiene un proxy según estrategia"""
        if not self.working_proxies:
            return None
            
        if strategy == 'fastest':
            # El más rápido
            proxy = self.working_proxies[0]
        elif strategy == 'random':
            # Aleatorio
            proxy = random.choice(self.working_proxies)
        elif strategy == 'round_robin':
            # Round robin (implementar)
            proxy = self.working_proxies[0]  # Placeholder
        else:
            proxy = random.choice(self.working_proxies)
            
        # Actualizar estadísticas
        if proxy in self.proxy_stats:
            self.proxy_stats[proxy]['last_used'] = time.time()
            
        return proxy
        
    async def make_request_with_rotation(self, url: str, max_retries: int = 3) -> Optional[Dict]:
        """Hace una petición rotando proxies si falla"""
        for attempt in range(max_retries):
            proxy = await self.get_proxy('random')
            if not proxy:
                return None
                
            try:
                resp = await self.client.get(url, proxy=proxy)
                if resp and resp.status == 200:
                    text = await resp.text()
                    return {
                        'url': url,
                        'proxy': proxy,
                        'status': resp.status,
                        'content': text[:200],
                        'attempt': attempt + 1
                    }
            except:
                # Si falla, quitar de working?
                if proxy in self.working_proxies:
                    self.working_proxies.remove(proxy)
                continue
                
        return None
        
    async def rotate_requests(self, num_requests: int = 10, strategy: str = 'random') -> List[Dict]:
        """Realiza múltiples peticiones rotando proxies"""
        print(f"\n🔄 PROXY ROTATOR v2.0 TANQUE")
        print("=" * 70)
        print(f"[*] Objetivo: {self.target}")
        print(f"[*] Peticiones: {num_requests}")
        print(f"[*] Estrategia: {strategy}")
        print(f"[*] Proxies funcionales: {len(self.working_proxies)}")
        print("-" * 70)
        
        results = []
        
        for i in range(num_requests):
            proxy = await self.get_proxy(strategy)
            if not proxy:
                print(f"[!] No hay proxies funcionales")
                break
                
            try:
                start = time.time()
                resp = await self.client.get(self.target, proxy=proxy)
                elapsed = time.time() - start
                
                if resp and resp.status == 200:
                    result = {
                        'request': i + 1,
                        'proxy': proxy,
                        'status': resp.status,
                        'time': round(elapsed, 3),
                        'ip': self.proxy_stats.get(proxy, {}).get('ip', 'unknown')
                    }
                    results.append(result)
                    
                    print(f"\n[{i+1}] [OK] {proxy}")
                    print(f"     Status: {resp.status} | Tiempo: {elapsed:.3f}s")
                    
            except Exception as e:
                print(f"\n[{i+1}] ❌ {proxy} - Error: {str(e)[:50]}")
                
            await asyncio.sleep(random.uniform(0.5, 1.5))
            
        # Estadísticas finales
        print("\n" + "="*70)
        print("📊 ESTADÍSTICAS")
        print("="*70)
        
        if results:
            success_rate = len(results) / num_requests * 100
            avg_time = sum(r['time'] for r in results) / len(results)
            print(f"\n[OK] Éxito: {len(results)}/{num_requests} ({success_rate:.1f}%)")
            print(f"⚡ Tiempo promedio: {avg_time:.3f}s")
            
            # Mejor proxy
            best = min(results, key=lambda x: x['time'])
            print(f"🏆 Mejor proxy: {best['proxy']} - {best['time']:.3f}s")
            
        return results
        
    async def run(self, num_requests: int = 10):
        """Ejecuta prueba completa"""
        await self.setup()
        
        # Probar proxies primero
        await self.test_all_proxies()
        
        if not self.working_proxies:
            print("\n[!] No se encontraron proxies funcionales")
            return []
            
        # Hacer peticiones rotando
        results = await self.rotate_requests(num_requests)
        
        return results

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 proxy_rotator.py <URL> [num_requests] [proxies_file]")
        print("Ejemplo: python3 proxy_rotator.py https://ejemplo.com 20 proxies.txt")
        sys.exit(1)
        
    url = sys.argv[1]
    num = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    proxies_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    rotator = ProxyRotator(url, proxies_file)
    await rotator.run(num)

if __name__ == "__main__":
    asyncio.run(main())
