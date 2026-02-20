#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RECON ADVANCED v2.0 - TANQUE EDITION
CRT.sh · Wayback Machine · ASN Lookup · GitHub dorks · Shodan
Con integración de APIs y caché
"""

import asyncio
import json
import socket
import subprocess
import re
from urllib.parse import urlparse, quote
from datetime import datetime
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class ReconAdvanced:
    def __init__(self, target: str, shodan_key: str = None, github_key: str = None):
        self.target = target.lower()
        self.parsed = urlparse(target if '://' in target else f"http://{target}")
        self.domain = self.parsed.netloc or target
        self.base_domain = '.'.join(self.domain.split('.')[-2:])
        self.shodan_key = shodan_key
        self.github_key = github_key
        self.client = None
        self.findings = []
        
        # GitHub dorks
        self.github_dorks = [
            f'"{self.domain}" filename:.env',
            f'"{self.domain}" filename:wp-config.php',
            f'"{self.domain}" filename:config.php',
            f'"{self.domain}" filename:.git/config',
            f'"{self.domain}" filename:credentials.json',
            f'"{self.domain}" filename:secrets.yml',
            f'"{self.domain}" password',
            f'"{self.domain}" api_key',
            f'"{self.domain}" secret',
            f'"{self.domain}" token',
            f'"{self.domain}" database',
            f'"{self.domain}" connectionstring',
            f'"{self.domain}" aws_access_key',
            f'"{self.base_domain}" password',
            f'"{self.base_domain}" secret',
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=20, max_retries=2)
        
    async def query_crtsh(self) -> List[Dict]:
        """Consulta CRT.sh para certificados"""
        findings = []
        print("[*] Consultando CRT.sh...")
        
        try:
            url = f"https://crt.sh/?q={self.base_domain}&output=json"
            resp = await self.client.get(url)
            
            if resp and resp.status == 200:
                data = await resp.json()
                domains = set()
                
                for cert in data[:200]:
                    name = cert.get('name_value', '')
                    if name:
                        for d in name.split('\n'):
                            d = d.strip()
                            if d and '*' not in d and d not in domains:
                                domains.add(d)
                                
                for domain in sorted(domains)[:50]:
                    findings.append({
                        'type': 'CRTSH_DOMAIN',
                        'domain': domain,
                        'severity': 'INFO'
                    })
                    
                print(f"   [OK] {len(domains)} subdominios encontrados")
                
        except Exception as e:
            print(f"   [WARN] Error: {e}")
            
        return findings
        
    async def query_wayback(self) -> List[Dict]:
        """Consulta Wayback Machine para URLs históricas"""
        findings = []
        print("\n[*] Consultando Wayback Machine...")
        
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url={self.base_domain}&output=json&fl=original&collapse=urlkey&limit=1000"
            resp = await self.client.get(url)
            
            if resp and resp.status == 200:
                data = await resp.json()
                urls = set()
                
                for item in data[1:1000]:
                    if item and len(item) > 0:
                        urls.add(item[0])
                        
                for url_item in sorted(urls)[:100]:
                    findings.append({
                        'type': 'WAYBACK_URL',
                        'url': url_item,
                        'severity': 'INFO'
                    })
                    
                print(f"   [OK] {len(urls)} URLs históricas")
                
        except Exception as e:
            print(f"   [WARN] Error: {e}")
            
        return findings
        
    async def asn_lookup(self) -> List[Dict]:
        """Consulta información ASN"""
        findings = []
        print("\n[*] Consultando ASN...")
        
        try:
            ip = socket.gethostbyname(self.domain)
            
            # whois lookup
            proc = await asyncio.create_subprocess_exec(
                'whois', ip,
                stdout=asyncio.PIPE,
                stderr=asyncio.PIPE
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode()
            
            # Buscar ASN
            asn_match = re.search(r'origin\s*:\s*(AS\d+)', output, re.IGNORECASE)
            if asn_match:
                findings.append({
                    'type': 'ASN_INFO',
                    'ip': ip,
                    'asn': asn_match.group(1),
                    'severity': 'INFO'
                })
                print(f"   [OK] ASN: {asn_match.group(1)} para {ip}")
                
            # Buscar CIDR
            cidr_match = re.search(r'route:\s*([0-9./]+)', output, re.IGNORECASE)
            if cidr_match:
                findings.append({
                    'type': 'CIDR_INFO',
                    'ip': ip,
                    'cidr': cidr_match.group(1),
                    'severity': 'INFO'
                })
                
        except Exception as e:
            print(f"   [WARN] Error: {e}")
            
        return findings
        
    async def github_dork(self) -> List[Dict]:
        """Busca en GitHub (requiere API key)"""
        findings = []
        print("\n[*] GitHub dorking...")
        
        if not self.github_key:
            print("   [WARN] GitHub API key no proporcionada")
            return findings
            
        try:
            headers = {'Authorization': f'token {self.github_key}'}
            
            for dork in self.github_dorks[:5]:  # Limitar
                url = f"https://api.github.com/search/code?q={quote(dork)}"
                resp = await self.client.get(url, headers=headers)
                
                if resp and resp.status == 200:
                    data = await resp.json()
                    count = data.get('total_count', 0)
                    
                    if count > 0:
                        findings.append({
                            'type': 'GITHUB_DORK',
                            'dork': dork,
                            'count': count,
                            'items': data.get('items', [])[:3],
                            'severity': 'ALTO'
                        })
                        print(f"   [OK] {dork}: {count} resultados")
                        
        except Exception as e:
            print(f"   [WARN] Error: {e}")
            
        return findings
        
    async def shodan_lookup(self) -> List[Dict]:
        """Consulta Shodan (requiere API key)"""
        findings = []
        print("\n[*] Shodan lookup...")
        
        if not self.shodan_key:
            print("   [WARN] Shodan API key no proporcionada")
            return findings
            
        try:
            # Resolver IP
            ip = socket.gethostbyname(self.domain)
            
            # Consultar Shodan
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
            resp = await self.client.get(url)
            
            if resp and resp.status == 200:
                data = await resp.json()
                
                findings.append({
                    'type': 'SHODAN_INFO',
                    'ip': ip,
                    'ports': data.get('ports', []),
                    'org': data.get('org', ''),
                    'os': data.get('os', ''),
                    'hostnames': data.get('hostnames', []),
                    'severity': 'INFO'
                })
                print(f"   [OK] Puertos: {data.get('ports', [])}")
                
        except Exception as e:
            print(f"   [WARN] Error: {e}")
            
        return findings
        
    async def scan(self):
        """Ejecuta reconocimiento avanzado"""
        print(f"\n🔍 RECON ADVANCED v2.0 TANQUE - {self.domain}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            # CRT.sh
            findings = await self.query_crtsh()
            self.findings.extend(findings)
            
            # Wayback
            findings = await self.query_wayback()
            self.findings.extend(findings)
            
            # ASN
            findings = await self.asn_lookup()
            self.findings.extend(findings)
            
            # GitHub
            if self.github_key:
                findings = await self.github_dork()
                self.findings.extend(findings)
                
            # Shodan
            if self.shodan_key:
                findings = await self.shodan_lookup()
                self.findings.extend(findings)
                
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS RECON AVANZADO")
            print("="*70)
            
            if self.findings:
                crtsh = [f for f in self.findings if f['type'] == 'CRTSH_DOMAIN']
                wayback = [f for f in self.findings if f['type'] == 'WAYBACK_URL']
                
                if crtsh:
                    print(f"\n[WEB] Subdominios CRT.sh: {len(crtsh)}")
                if wayback:
                    print(f"\n📜 URLs Wayback: {len(wayback)}")
                    
                print(f"\n[OK] TOTAL: {len(self.findings)}")
            else:
                print("\n[OK] No se encontraron hallazgos adicionales")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 recon_advanced.py <dominio> [shodan_key] [github_key]")
        sys.exit(1)
        
    domain = sys.argv[1]
    shodan = sys.argv[2] if len(sys.argv) > 2 else None
    github = sys.argv[3] if len(sys.argv) > 3 else None
    
    recon = ReconAdvanced(domain, shodan, github)
    await recon.scan()

if __name__ == "__main__":
    asyncio.run(main())
