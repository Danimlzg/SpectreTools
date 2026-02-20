#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ENDPOINT HARVESTER v3.0 - TANQUE EDITION
Captura TOTAL de endpoints · JS · APIs · Subdomains · Storage
SIN LÍMITES · MODO PRODUCCIÓN
"""

import asyncio
import json
import sys
import os
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
import tldextract
from playwright.async_api import async_playwright
from typing import Dict, List, Optional, Set
import aiohttp

# Importar http_client TANQUE
try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class EndpointHarvester:
    def __init__(self, url: str, headless: bool = True, deep_scan: bool = True):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.base_domain = self._get_base_domain()
        self.headless = headless
        self.deep_scan = deep_scan
        self.browser = None
        self.context = None
        self.page = None
        self.http_client = None
        
        # Almacenamiento
        self.endpoints = {
            'xhr': [], 'documents': [], 'stylesheets': [], 'images': [],
            'media': [], 'fonts': [], 'scripts': [], 'other': []
        }
        self.apis: Set[str] = set()
        self.subdomains: Set[str] = set()
        self.cookies = []
        self.local_storage = {}
        self.session_storage = {}
        self.console_logs = []
        self.errors = []
        self.all_requests = []
        self.all_js_files: Set[str] = set()
        self.all_urls: Set[str] = set()
        self.forms = []
        self.inputs = []
        
        # Estadísticas
        self.start_time = None
        self.request_count = 0
        
    def _get_base_domain(self) -> str:
        """Extrae dominio base"""
        extracted = tldextract.extract(self.domain)
        return f"{extracted.domain}.{extracted.suffix}"
        
    async def setup(self):
        """Inicializa browser y cliente HTTP"""
        # Cliente HTTP para peticiones rápidas
        self.http_client = HTTPClient(timeout=30, max_retries=3)
        
        # Playwright para JS real
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=self.headless,
            args=[
                '--disable-web-security',
                '--disable-features=IsolateOrigins,site-per-process',
                '--disable-site-isolation-trials',
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--disable-gpu'
            ]
        )
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            ignore_https_errors=True,
            java_script_enabled=True
        )
        self.page = await self.context.new_page()
        
        # Configurar event listeners
        await self._setup_listeners()
        
    async def _setup_listeners(self):
        """Configura todos los listeners de eventos"""
        
        # Console logs
        self.page.on('console', lambda msg: self.console_logs.append({
            'type': msg.type,
            'text': msg.text,
            'location': msg.location,
            'timestamp': datetime.now().isoformat()
        }))
        
        # Errores de página
        self.page.on('pageerror', lambda error: self.errors.append({
            'message': str(error),
            'stack': error.stack,
            'timestamp': datetime.now().isoformat()
        }))
        
        # Request handler
        async def handle_request(request):
            self.request_count += 1
            resource_type = request.resource_type
            url = request.url
            method = request.method
            
            # Evitar duplicados
            if url in self.all_urls:
                return
            self.all_urls.add(url)
            
            entry = {
                'url': url,
                'method': method,
                'resource_type': resource_type,
                'headers': dict(request.headers),
                'timestamp': datetime.now().isoformat()
            }
            self.all_requests.append(entry)
            
            # Clasificar
            if resource_type == 'script' or url.endswith('.js') or '.js?' in url:
                self.all_js_files.add(url)
                self.endpoints['scripts'].append(url)
            elif resource_type == 'xhr' or resource_type == 'fetch':
                self.endpoints['xhr'].append(url)
                if re.search(r'/api/|/v[0-9]/|graphql|rest', url, re.I):
                    self.apis.add(url)
            elif resource_type == 'document':
                self.endpoints['documents'].append(url)
            elif resource_type == 'stylesheet':
                self.endpoints['stylesheets'].append(url)
            elif resource_type == 'image':
                self.endpoints['images'].append(url)
            elif resource_type == 'media':
                self.endpoints['media'].append(url)
            elif resource_type == 'font':
                self.endpoints['fonts'].append(url)
            else:
                self.endpoints['other'].append(url)
            
            # Detectar subdominios
            try:
                req_domain = urlparse(url).netloc
                if req_domain and req_domain != self.domain:
                    extracted = tldextract.extract(req_domain)
                    if f"{extracted.domain}.{extracted.suffix}" == self.base_domain:
                        self.subdomains.add(req_domain)
            except:
                pass
                
        self.page.on('request', handle_request)
        
        # Response handler (para códigos de estado)
        async def handle_response(response):
            url = response.url
            status = response.status
            for req in self.all_requests:
                if req['url'] == url:
                    req['status'] = status
                    break
                    
        self.page.on('response', handle_response)
        
    async def extract_forms(self):
        """Extrae todos los formularios del DOM"""
        forms = await self.page.evaluate('''() => {
            const forms = [];
            document.querySelectorAll('form').forEach((form, index) => {
                const formData = {
                    id: index,
                    action: form.action,
                    method: form.method,
                    inputs: []
                };
                form.querySelectorAll('input, textarea, select').forEach(input => {
                    formData.inputs.push({
                        name: input.name,
                        type: input.type,
                        value: input.value
                    });
                });
                forms.push(formData);
            });
            return forms;
        }''')
        self.forms = forms
        
    async def extract_links(self):
        """Extrae todos los enlaces del DOM"""
        links = await self.page.evaluate('''() => {
            return Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
        }''')
        for link in links:
            self.all_urls.add(link)
            
    async def navigate_and_scroll(self):
        """Navega y hace scroll para cargar contenido dinámico"""
        print(f"[*] Navegando a {self.url}...")
        
        try:
            # Carga inicial
            await self.page.goto(self.url, timeout=60000, wait_until='networkidle')
            print(f"[✓] Página cargada. Título: {await self.page.title()}")
            
            # Esperar a que cargue JS
            await asyncio.sleep(3)
            
            # Scroll infinito (para SPAs)
            if self.deep_scan:
                print("[*] Escaneando contenido dinámico...")
                last_height = await self.page.evaluate('document.body.scrollHeight')
                
                for i in range(5):  # 5 scrolls máximos
                    await self.page.evaluate('window.scrollTo(0, document.body.scrollHeight)')
                    await asyncio.sleep(2)
                    
                    new_height = await self.page.evaluate('document.body.scrollHeight')
                    if new_height == last_height:
                        break
                    last_height = new_height
                    print(f"   Scroll {i+1}/5 completado")
                    
            # Extraer forms y links
            await self.extract_forms()
            await self.extract_links()
            
            # Obtener storage
            self.cookies = await self.context.cookies()
            self.local_storage = await self.page.evaluate('() => JSON.stringify(localStorage)')
            self.local_storage = json.loads(self.local_storage) if self.local_storage else {}
            self.session_storage = await self.page.evaluate('() => JSON.stringify(sessionStorage)')
            self.session_storage = json.loads(self.session_storage) if self.session_storage else {}
            
        except Exception as e:
            print(f"[!] Error durante navegación: {e}")
            self.errors.append({'message': str(e), 'phase': 'navigation'})
            
    async def harvest(self):
        """Ejecuta la cosecha completa"""
        print(f"\n🔍 ENDPOINT HARVESTER v3.0 TANQUE - {self.url}")
        print("=" * 70)
        print(f"[*] Deep scan: {'SÍ' if self.deep_scan else 'NO'}")
        print(f"[*] Headless: {'SÍ' if self.headless else 'NO'}")
        print("-" * 70)
        
        self.start_time = datetime.now()
        
        try:
            await self.setup()
            await self.navigate_and_scroll()
            
        except Exception as e:
            print(f"[!] Error fatal: {e}")
        finally:
            await self.close()
            
        # Mostrar resultados
        await self.print_results()
        
        # Guardar datos
        await self.save_results()
        
        return {
            'endpoints': self.endpoints,
            'apis': list(self.apis),
            'subdomains': list(self.subdomains),
            'cookies': self.cookies,
            'local_storage': self.local_storage,
            'session_storage': self.session_storage,
            'console_logs': self.console_logs[-50:],  # Últimos 50
            'errors': self.errors,
            'all_js_files': list(self.all_js_files),
            'forms': self.forms,
            'total_requests': self.request_count,
            'duration': str(datetime.now() - self.start_time)
        }
        
    async def print_results(self):
        """Muestra resultados formateados"""
        elapsed = datetime.now() - self.start_time
        
        print("\n" + "="*70)
        print("📊 RESULTADOS DEL HARVESTER")
        print("="*70)
        
        print(f"\n⏱️  Tiempo total: {elapsed}")
        print(f"📡 Peticiones totales: {self.request_count}")
        
        # Por tipo
        print(f"\n📦 RECURSOS POR TIPO:")
        for tipo, urls in self.endpoints.items():
            if urls:
                print(f"   • {tipo.upper()}: {len(urls)}")
                
        # APIs
        if self.apis:
            print(f"\n🔌 APIs DETECTADAS ({len(self.apis)}):")
            for api in sorted(self.apis)[:20]:
                print(f"   • {api}")
                
        # JS Files
        if self.all_js_files:
            print(f"\n📜 ARCHIVOS JS ({len(self.all_js_files)}):")
            for js in list(self.all_js_files)[:15]:
                print(f"   • {js}")
                
        # Subdominios
        if self.subdomains:
            print(f"\n[WEB] SUBDOMINIOS ({len(self.subdomains)}):")
            for sub in sorted(self.subdomains)[:15]:
                print(f"   • {sub}")
                
        # Forms
        if self.forms:
            print(f"\n📝 FORMULARIOS ({len(self.forms)}):")
            for form in self.forms[:5]:
                print(f"   • {form['method']} → {form['action']}")
                for inp in form['inputs'][:3]:
                    print(f"     ↳ {inp['name']} ({inp['type']})")
                    
        # Cookies
        if self.cookies:
            print(f"\n🍪 COOKIES ({len(self.cookies)}):")
            for cookie in self.cookies[:10]:
                secure = "[SECURE]" if cookie.get('secure') else "[WEB]"
                http_only = "[LOCK]" if cookie.get('httpOnly') else "📝"
                print(f"   {secure}{http_only} {cookie['name']}")
                
        # LocalStorage
        if self.local_storage:
            print(f"\n💾 LOCALSTORAGE ({len(self.local_storage)}):")
            for key, value in list(self.local_storage.items())[:10]:
                print(f"   • {key} = {str(value)[:50]}...")
                
        # Errores
        if self.errors:
            print(f"\n❌ ERRORES ({len(self.errors)}):")
            for err in self.errors[:5]:
                print(f"   • {err['message'][:100]}")
                
    async def save_results(self):
        """Guarda resultados a archivo"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain_clean = self.domain.replace('.', '_')
        filename = f"harvest_{domain_clean}_{timestamp}.json"
        
        output = {
            'metadata': {
                'url': self.url,
                'domain': self.domain,
                'timestamp': str(datetime.now()),
                'duration': str(datetime.now() - self.start_time),
                'total_requests': self.request_count
            },
            'endpoints': {k: list(set(v)) for k, v in self.endpoints.items()},
            'apis': list(self.apis),
            'subdomains': list(self.subdomains),
            'js_files': list(self.all_js_files),
            'cookies': self.cookies,
            'local_storage': self.local_storage,
            'session_storage': self.session_storage,
            'forms': self.forms,
            'errors': self.errors[-20:],  # Últimos 20 errores
            'console_logs': self.console_logs[-50:]  # Últimos 50 logs
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2, default=str)
            
        print(f"\n💾 Resultados guardados en {filename}")
        
        # Guardar lista de JS aparte
        if self.all_js_files:
            js_file = f"js_{domain_clean}_{timestamp}.txt"
            with open(js_file, 'w') as f:
                for js in sorted(self.all_js_files):
                    f.write(js + '\n')
            print(f"💾 Lista JS guardada en {js_file}")
            
    async def close(self):
        """Cierra todos los recursos"""
        if self.page:
            await self.page.close()
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if hasattr(self, 'playwright'):
            await self.playwright.stop()
        if self.http_client:
            await self.http_client.close()

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 endpoint_harvester.py <URL> [--quick]")
        print("Ejemplo: python3 endpoint_harvester.py https://ejemplo.com")
        print("         python3 endpoint_harvester.py https://ejemplo.com --quick")
        sys.exit(1)
        
    url = sys.argv[1]
    quick = '--quick' in sys.argv
    
    harvester = EndpointHarvester(url, headless=True, deep_scan=not quick)
    await harvester.harvest()

if __name__ == "__main__":
    asyncio.run(main())
