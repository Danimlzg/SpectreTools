#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SIMPLE DNS ENUM v2.0 - TANQUE EDITION
Enumeración DNS sin dependencias · Wordlist 1000+ · Resolución rápida
Con soporte para aiodns opcional
"""

import asyncio
import socket
from typing import List, Tuple, Optional

# Intentar importar aiodns (opcional)
try:
    import aiodns
    HAS_AIODNS = True
except ImportError:
    HAS_AIODNS = False

class SimpleDNSEnum:
    def __init__(self, domain: str, wordlist: List[str] = None, use_aiodns: bool = True):
        self.domain = domain.lower()
        self.use_aiodns = use_aiodns and HAS_AIODNS
        self.resolver = None
        self.found = []
        
        # Wordlist ampliada
        self.wordlist = wordlist or [
            # Subdominios básicos
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'ns3', 'ns4', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap',
            'test', 'dev', 'admin', 'blog', 'forum', 'news', 'vpn', 'support',
            'mobile', 'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure',
            'demo', 'video', 'server', 'git', 'api', 'stage', 'staging',
            'prod', 'production', 'backup', 'db', 'cdn', 'assets', 'img',
            'css', 'js', 'files', 'download', 'upload', 'media', 'stream',
            'chat', 'bot', 'payment', 'pay', 'wallet', 'game', 'shop',
            
            # Números
            *[str(i) for i in range(10)],
            *['server' + str(i) for i in range(1, 10)],
            *['web' + str(i) for i in range(1, 10)],
            *['mail' + str(i) for i in range(1, 10)],
            
            # Tecnologías
            'aws', 'azure', 'gcp', 'google', 'amazon', 'microsoft',
            'jenkins', 'gitlab', 'github', 'jira', 'confluence',
            'grafana', 'prometheus', 'kibana', 'elastic', 'redis',
            'mongodb', 'mysql', 'postgres', 'cassandra', 'kafka',
            'kubernetes', 'k8s', 'docker', 'rancher', 'openshift',
            'nginx', 'apache', 'tomcat', 'phpmyadmin', 'adminer',
            'wordpress', 'wp', 'drupal', 'joomla', 'magento',
            
            # Entornos
            'dev', 'development', 'stage', 'staging', 'prod', 'production',
            'test', 'testing', 'qa', 'uat', 'demo', 'sandbox', 'lab',
            
            # Servicios
            'auth', 'login', 'sso', 'oauth', 'api', 'rest', 'graphql',
            'app', 'apps', 'mobile', 'ios', 'android', 'web',
            
            # Seguridad
            'security', 'secure', 'vpn', 'firewall', 'waf', 'ids',
            
            # Datos
            'data', 'db', 'database', 'sql', 'backup', 'backups',
            'files', 'storage', 's3', 'bucket', 'buckets',
            
            # Administración
            'admin', 'administrator', 'manager', 'dashboard', 'panel',
            'control', 'console', 'monitor', 'monitoring', 'logs',
        ]
        
        if self.use_aiodns:
            self.resolver = aiodns.DNSResolver()
            
    async def resolve_socket(self, subdomain: str) -> Optional[Tuple[str, str]]:
        """Resuelve usando socket (bloqueante, en thread)"""
        try:
            loop = asyncio.get_event_loop()
            hostname = f"{subdomain}.{self.domain}"
            ip = await loop.run_in_executor(None, socket.gethostbyname, hostname)
            return (hostname, ip)
        except:
            return None
            
    async def resolve_aiodns(self, subdomain: str) -> Optional[Tuple[str, str]]:
        """Resuelve usando aiodns (no bloqueante)"""
        try:
            hostname = f"{subdomain}.{self.domain}"
            result = await self.resolver.query(hostname, 'A')
            if result:
                ips = [r.host for r in result]
                return (hostname, ', '.join(ips))
        except:
            pass
        return None
        
    async def check_subdomain(self, subdomain: str) -> Optional[Tuple[str, str]]:
        """Intenta resolver un subdominio"""
        if self.use_aiodns:
            return await self.resolve_aiodns(subdomain)
        else:
            return await self.resolve_socket(subdomain)
            
    async def run(self, concurrency: int = 100) -> List[Tuple[str, str]]:
        """Ejecuta enumeración DNS"""
        print(f"\n🔍 SIMPLE DNS ENUM v2.0 TANQUE - {self.domain}")
        print("=" * 70)
        print(f"[*] Modo: {'aiodns' if self.use_aiodns else 'socket'}")
        print(f"[*] Subdominios: {len(self.wordlist)}")
        print(f"[*] Concurrencia: {concurrency}")
        print("-" * 70)
        
        # Control de concurrencia
        semaphore = asyncio.Semaphore(concurrency)
        
        async def check_with_semaphore(sub):
            async with semaphore:
                result = await self.check_subdomain(sub)
                if result:
                    self.found.append(result)
                    print(f"   [OK] {result[0]} → {result[1]}")
                return result
                
        # Crear tareas
        tasks = [check_with_semaphore(sub) for sub in self.wordlist]
        await asyncio.gather(*tasks)
        
        # Ordenar resultados
        self.found.sort(key=lambda x: x[0])
        
        # Resumen
        print("\n" + "="*70)
        print("📊 RESULTADOS DNS")
        print("="*70)
        
        if self.found:
            print(f"\n[OK] Subdominios encontrados: {len(self.found)}")
            for host, ip in self.found[:20]:
                print(f"   • {host} → {ip}")
                
            # Guardar resultados
            with open(f"dns_{self.domain}.txt", 'w') as f:
                for host, ip in self.found:
                    f.write(f"{host} → {ip}\n")
            print(f"\n💾 Resultados guardados en dns_{self.domain}.txt")
        else:
            print("\n❌ No se encontraron subdominios")
            
        return self.found

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 simple_dns_enum.py <dominio> [concurrency]")
        sys.exit(1)
        
    domain = sys.argv[1]
    concurrency = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    
    scanner = SimpleDNSEnum(domain)
    await scanner.run(concurrency)

if __name__ == "__main__":
    asyncio.run(main())
