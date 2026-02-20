import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

#!/usr/bin/env python3
"""
Origin IP Finder - Busca la IP real detrás de Cloudflare
Técnicas: subdominios no proxy, registros históricos, SPF, certificados
"""

import asyncio
import aiohttp
import socket
import dns.resolver
import ssl
import json
import re
from datetime import datetime
try:
    from .http_client import get_session
except ImportError:
    from http_client import get_session
class OriginIPFinder:
    def __init__(self, domain):
        self.domain = domain
        self.results = {
            'domain': domain,
            'possible_ips': [],
            'subdomains_checked': 0,
            'timestamp': str(datetime.now())
        }
        # Subdominios comunes que suelen estar fuera de Cloudflare
        self.subdomain_wordlist = [
            'direct', 'origin', 'origin-www', 'direct-www',
            'mail', 'webmail', 'smtp', 'pop', 'imap',
            'ftp', 'sftp', 'ssh', 'cpanel', 'whm',
            'dev', 'development', 'staging', 'stage', 'test',
            'beta', 'alpha', 'demo', 'sandbox',
            'api', 'api-dev', 'api-staging',
            'admin', 'admin-dev', 'manager', 'dashboard',
            'backup', 'backups', 'old', 'archive',
            'vpn', 'remote', 'access', 'secure',
            'db', 'database', 'mysql', 'redis',
            'jenkins', 'gitlab', 'jira', 'confluence',
            'grafana', 'prometheus', 'kibana',
            'lb', 'loadbalancer', 'proxy',
            'static', 'assets', 'cdn', 'media',
            'autodiscover', 'autoconfig'
        ]
        # Resolvers DNS públicos
        self.resolvers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        # Rangos de IPs de Cloudflare (para filtrar)
        self.cloudflare_ranges = [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
            '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
            '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
            '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
        ]
    def is_cloudflare_ip(self, ip):
        """Verifica si una IP pertenece a Cloudflare"""
        from ipaddress import ip_address, ip_network
        try:
            ip_obj = ip_address(ip)
            for cidr in self.cloudflare_ranges:
                if ip_obj in ip_network(cidr):
                    return True
        except:
            pass
        return False
    async def check_subdomain(self, sub):
        """Comprueba si un subdominio tiene IP fuera de Cloudflare"""
        hostname = f"{sub}.{self.domain}"
        try:
            # Resolver IP
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(None, socket.gethostbyname, hostname)
            # Verificar si es IP de Cloudflare
            if not self.is_cloudflare_ip(ip):
                # Verificar que responde HTTP
                try:
                    session = await get_session()
                    url = f"http://{hostname}"
                    async with session.get(url, timeout=30) as resp:
                        if resp.status < 500:  # Responde algo
                            self.results['possible_ips'].append({
                                'source': f'subdomain: {hostname}',
                                'ip': ip,
                                'status': resp.status,
                                'title': await self.get_title(resp)
                            })
                            print(f"   [✓] IP REAL ENCONTRADA: {hostname} → {ip}")
                except Exception as e:
                    # No responde HTTP pero tiene IP
                    self.results['possible_ips'].append({
                        'source': f'subdomain: {hostname}',
                        'ip': ip,
                        'status': 'no-http'
                    })
                    print(f"   [✓] IP ENCONTRADA (no HTTP): {hostname} → {ip}")
                finally:
                    await session.close()
        except:
            pass
        self.results['subdomains_checked'] += 1
    async def get_title(self, response):
        """Extrae el título HTML para verificar que es el mismo sitio"""
        try:
            text = await response.text()
            match = re.search(r'<title>(.*?)</title>', text, re.IGNORECASE)
            if match:
                return match.group(1)
        except:
            pass
        return None
    async def check_spf_records(self):
        """Busca IPs en registros SPF"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.resolvers
            txt_records = resolver.resolve(self.domain, 'TXT')
            for txt in txt_records:
                txt_str = str(txt)
                if 'v=spf1' in txt_str:
                    # Extraer IPs del SPF
                    ips = re.findall(r'ip[46]:([0-9./]+)', txt_str)
                    for ip in ips:
                        if '/' not in ip:  # IP individual, no rango
                            self.results['possible_ips'].append({
                                'source': f'SPF record',
                                'ip': ip,
                                'type': 'mail-server'
                            })
                            print(f"   [✓] IP en SPF: {ip}")
        except:
            pass
    async def check_historical_services(self):
        """Simula búsqueda en servicios históricos"""
        # En versión real, aquí integraríamos APIs de:
        # - SecurityTrails
        # - Censys
        # - Shodan
        # - CRT.sh (certificados)
        print("\n   [*] Para búsqueda avanzada, usa:")
        print("      • SecurityTrails: https://securitytrails.com")
        print("      • Censys: https://censys.io")
        print("      • CRT.sh: https://crt.sh/?q=%25.domain")
    async def run(self):
        """Ejecuta todas las técnicas"""
        print(f"\n🔍 ORIGIN IP FINDER - Buscando IP real de {self.domain}")
        print("=" * 60)
        # 1. Buscar en subdominios
        print(f"\n[*] Probando {len(self.subdomain_wordlist)} subdominios...")
        tasks = [self.check_subdomain(sub) for sub in self.subdomain_wordlist]
        await asyncio.gather(*tasks)
        # 2. Buscar en SPF
        print("\n[*] Analizando registros SPF...")
        await self.check_spf_records()
        # 3. Sugerir servicios históricos
        await self.check_historical_services()
        # Mostrar resultados
        print("\n" + "=" * 60)
        print("📊 RESULTADOS - POSIBLES IPs DE ORIGEN")
        print("=" * 60)
        if self.results['possible_ips']:
            for ip_info in self.results['possible_ips']:
                print(f"\n   • {ip_info['source']}")
                print(f"     IP: {ip_info['ip']}")
                if 'status' in ip_info:
                    print(f"     HTTP Status: {ip_info['status']}")
                if 'title' in ip_info and ip_info['title']:
                    print(f"     Title: {ip_info['title']}")
        else:
            print("\n   ❌ No se encontraron IPs fuera de Cloudflare")
            print("   Prueba con servicios históricos:")
            print("   • https://securitytrails.com")
            print("   • https://censys.io")
            print("   • https://crt.sh")
        return self.results
async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 origin_ip_finder.py <dominio>")
        sys.exit(1)
    finder = OriginIPFinder(sys.argv[1])
    await finder.run()
if __name__ == "__main__":
    asyncio.run(main())
