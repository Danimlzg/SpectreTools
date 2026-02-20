#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HTTP CLIENT v2.0 - TANQUE EDITION
Manejo de errores robusto · Reintentos automáticos · Anti-detección
"""

import aiohttp
import asyncio
import random
from typing import Optional, Dict, Any
from datetime import datetime

# User-Agents rotativos (como humanos reales)
USER_AGENTS = [
    # Windows Chrome
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    # Windows Firefox
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    # Mac Chrome
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    # Mac Safari
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    # Linux Chrome
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    # iPhone
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    # Android
    'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
]

# Cabeceras base (sin User-Agent para rotarlo después)
BASE_HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Cache-Control': 'max-age=0',
}

class HTTPClient:
    """Cliente HTTP robusto con reintentos y manejo de errores"""
    
    def __init__(self, timeout: int = 30, max_retries: int = 3, verify_ssl: bool = False):
        self.timeout = aiohttp.ClientTimeout(
            total=timeout,
            connect=10,
            sock_read=timeout
        )
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.session: Optional[aiohttp.ClientSession] = None
        self._connector: Optional[aiohttp.TCPConnector] = None
        
    async def __aenter__(self):
        """Context manager entry"""
        await self.get_session()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - asegura limpieza"""
        await self.close()
        
    async def get_session(self) -> aiohttp.ClientSession:
        """Obtiene o crea la sesión (singleton por instancia)"""
        if self.session is None or self.session.closed:
            self._connector = aiohttp.TCPConnector(
                ssl=bool(self.verify_ssl),
                limit=100,
                ttl_dns_cache=300,  # Cache DNS 5 minutos
                force_close=True  # Evita conexiones colgadas
            )
            
            self.session = aiohttp.ClientSession(
                timeout=self.timeout,
                connector=self._connector
            )
        return self.session
        
    def _get_headers(self, custom_headers: Optional[Dict] = None) -> Dict:
        """Genera headers con User-Agent aleatorio"""
        headers = BASE_HEADERS.copy()
        headers['User-Agent'] = random.choice(USER_AGENTS)
        
        # Añadir headers personalizados
        if custom_headers:
            headers.update(custom_headers)
            
        return headers
        
    async def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Optional[aiohttp.ClientResponse]:
        """
        Realiza petición HTTP con reintentos automáticos
        """
        session = await self.get_session()
        headers = self._get_headers(kwargs.pop('headers', {}))
        
        for attempt in range(self.max_retries):
            try:
                # Delay exponencial entre reintentos
                if attempt > 0:
                    wait_time = 2 ** attempt + random.random()
                    await asyncio.sleep(wait_time)
                    
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    allow_redirects=True,
                    max_redirects=5,
                    ssl=self.verify_ssl,
                    **kwargs
                ) as resp:
                    # Leer contenido para poder usarlo después
                    await resp.read()
                    
                    # Si es rate limiting, esperar más
                    if resp.status in [429, 503]:
                        retry_after = int(resp.headers.get('Retry-After', 5))
                        await asyncio.sleep(retry_after)
                        continue
                        
                    return resp
                    
            except asyncio.TimeoutError:
                if attempt == self.max_retries - 1:
                    raise
                    
            except aiohttp.ClientConnectorError:
                if attempt == self.max_retries - 1:
                    raise
                    
            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise
                    
        return None
        
    async def get(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """GET request"""
        return await self.request('GET', url, **kwargs)
        
    async def post(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """POST request"""
        return await self.request('POST', url, **kwargs)
        
    async def head(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """HEAD request"""
        return await self.request('HEAD', url, **kwargs)
        
    async def options(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """OPTIONS request"""
        return await self.request('OPTIONS', url, **kwargs)
        
    async def close(self):
        """Cierra sesión y conexiones"""
        if self.session and not self.session.closed:
            await self.session.close()
        if self._connector and not self._connector.closed:
            await self._connector.close()
            
    async def test_connection(self, url: str) -> bool:
        """Prueba rápida de conectividad"""
        try:
            resp = await self.get(url, timeout=aiohttp.ClientTimeout(total=5))
            return resp is not None and resp.status < 500
        except:
            return False


# Funciones de compatibilidad con código existente
async def get_session():
    """Wrapper para compatibilidad"""
    client = HTTPClient()
    return await client.get_session()


async def close_session(session):
    """Wrapper para compatibilidad"""
    if session and not session.closed:
        await session.close()


# Ejemplo de uso
async def main():
    async with HTTPClient(max_retries=3) as client:
        # Test de conexión
        if await client.test_connection("https://httpbin.org/get"):
            print("[OK] Conexión OK")
            
            # GET con reintentos automáticos
            resp = await client.get("https://httpbin.org/get")
            if resp:
                data = await resp.json()
                print(f"[OK] Respuesta: {data['headers']['User-Agent'][:50]}...")
        else:
            print("❌ Fallo de conexión")

if __name__ == "__main__":
    asyncio.run(main())
