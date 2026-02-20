#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RANSOMWARE DETECTOR v2.0 - TANQUE EDITION
Detección de IOCs · Extensiones maliciosas · Notas de rescate · C2 domains
Con análisis de comportamiento y crypto addresses
"""

import asyncio
import re
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class RansomwareDetector:
    def __init__(self, url: str):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.client = None
        self.findings = []
        
        # Extensiones de ransomware (actualizado 2025)
        self.ransomware_exts = [
            '.encrypted', '.locked', '.crypt', '.crypted', '.enc', '.locky',
            '.wanna', '.wcry', '.wncry', '.wnry', '.onion', '.thor', '.akira',
            '.black', '.lockbit', '.hive', '.lv', '.babyk', '.kraken', '.malox',
            '.phobos', '.qilin', '.ragnar', '.royal', '.sodin', '.spider',
            '.locker', '.crypto', '.cryptolocker', '.zepto', '.odin', '.thor',
            '.cerber', '.dharma', '.crysis', '.cryp', '.encrypt', '.encrypted',
            '.ezz', '.exx', '.zzz', '.xyz', '.aaa', '.ccc', '.vvv', '.ttt',
            '.kraken', '.leak', '.leaks', '.data', '.files', '.documents',
            '.backup', '.backups', '.dump', '.sql', '.db', '.mdb',
        ]
        
        # Notas de rescate
        .ransom_notes = [
            'readme.txt', 'README.html', 'README.png', 'HOW_TO_DECRYPT.txt',
            'DECRYPT_INSTRUCTION.txt', 'RECOVER_FILES.html', 'FILES_ENCRYPTED.txt',
            'DECRYPT_INFO.txt', 'DECRYPT.html', 'HELP_DECRYPT.html', 'README_FILES.txt',
            'README_RESTORE.txt', 'README_DECRYPT.txt', 'DECRYPT_FILES.html',
            'HOW_TO_RECOVER.html', 'RECOVERY.txt', 'RECOVERY.html', 'RESTORE.txt',
            '!!!READ_ME!!!.txt', '!!!README!!!.txt', '!!!READ_ME!!!.html',
            'read_me_unlock.txt', 'recover_files.txt', 'recover_instructions.txt',
            'how_to_recover_data.txt', 'how_to_decrypt_files.txt', 'unlock_instructions.txt',
        ]
        
        # Patrones C2 (Command & Control)
        self.c2_patterns = [
            (r'\.onion$', 'Tor hidden service'),
            (r'\.i2p$', 'I2P network'),
            (r'\.bit$', 'Namecoin'),
            (r'\.tor$', 'Tor domain'),
            (r'\.exit$', 'Tor exit node'),
            (r'tor2web\.', 'Tor2Web bridge'),
            (r'onion\.', 'Onion domain'),
            (r'\.onion\.to', 'Onion.to proxy'),
            (r'\.onion\.link', 'Onion.link proxy'),
            (r'\.onion\.cab', 'Onion.cab proxy'),
            (r'\.onion\.city', 'Onion.city proxy'),
        ]
        
        # Firmas de ransomware
        self.ransomware_signatures = [
            (r'wannacry|wannacrypt|wcry|wncry', 'WannaCry'),
            (r'locky', 'Locky'),
            (r'lockbit', 'LockBit'),
            (r'blackmatter', 'BlackMatter'),
            (r'darkside', 'DarkSide'),
            (r'conti', 'Conti'),
            (r'revil|sodinokibi', 'REvil'),
            (r'maze', 'Maze'),
            (r'egregor', 'Egregor'),
            (r'netwalker', 'NetWalker'),
            (r'phobos', 'Phobos'),
            (r'dharma|crysis', 'Dharma'),
            (r'cerber', 'Cerber'),
            (r'ryuk', 'Ryuk'),
            (r'trickbot', 'TrickBot'),
            (r'emotet', 'Emotet'),
            (r'qakbot', 'QakBot'),
            (r'dridex', 'Dridex'),
            (r'zeus|zbot', 'Zeus'),
        ]
        
        # Direcciones crypto
        self.crypto_patterns = [
            (r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', 'Bitcoin'),
            (r'\b0x[a-fA-F0-9]{40}\b', 'Ethereum'),
            (r'\bL[a-km-zA-HJ-NP-Z1-9]{26,33}\b', 'Litecoin'),
            (r'\bX[1-9A-HJ-NP-Za-km-z]{33}\b', 'Dash'),
            (r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b', 'Monero'),
            (r'\br[0-9a-zA-Z]{33}\b', 'Ripple'),
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    async def scan_files(self) -> List[Dict]:
        """Busca archivos con extensiones de ransomware"""
        findings = []
        
        test_paths = ['', 'uploads', 'files', 'documents', 'backup', 'temp', 'data']
        
        for ext in self.ransomware_exts[:20]:
            for path in test_paths:
                test_file = f"/{path}/test{ext}" if path else f"/test{ext}"
                url = urljoin(self.url, test_file)
                
                try:
                    resp = await self.client.head(url)
                    if resp and resp.status == 200:
                        findings.append({
                            'type': 'RANSOMWARE_EXTENSION',
                            'url': url,
                            'extension': ext,
                            'severity': 'CRITICO'
                        })
                        print(f"   [[CRITICO]] Posible archivo ransomware: {url}")
                except:
                    pass
                    
        return findings
        
    async def scan_notes(self) -> List[Dict]:
        """Busca notas de rescate"""
        findings = []
        
        for note in self.ransom_notes:
            url = urljoin(self.url, f"/{note}")
            try:
                resp = await self.client.get(url)
                if resp and resp.status == 200:
                    text = await resp.text()
                    
                    # Palabras clave típicas
                    keywords = ['bitcoin', 'decrypt', 'encrypted', 'ransom', 'pay', 'wallet',
                               'btc', 'ethereum', 'monero', 'tor', 'onion', 'darknet']
                    
                    found = [k for k in keywords if k in text.lower()]
                    
                    if found:
                        findings.append({
                            'type': 'RANSOMWARE_NOTE',
                            'url': url,
                            'keywords': found,
                            'severity': 'CRITICO'
                        })
                        print(f"   [[CRITICO]] Nota de rescate: {url}")
            except:
                pass
                
        return findings
        
    async def detect_c2(self) -> List[Dict]:
        """Detecta posibles servidores C2"""
        findings = []
        
        try:
            resp = await self.client.get(self.url)
            if not resp:
                return findings
                
            html = await resp.text()
            
            # Buscar URLs
            urls = re.findall(r'https?://[^\s<>"\'{}|\\^`\[\]]+', html)
            
            for url in urls:
                domain = urlparse(url).netloc
                
                # Patrones C2
                for pattern, c2_type in self.c2_patterns:
                    if re.search(pattern, domain, re.IGNORECASE):
                        findings.append({
                            'type': 'C2_DOMAIN',
                            'url': url,
                            'domain': domain,
                            'c2_type': c2_type,
                            'severity': 'ALTO'
                        })
                        print(f"   [[WARN]] Posible C2: {domain}")
                        
                # Firmas de ransomware
                for pattern, ransomware in self.ransomware_signatures:
                    if re.search(pattern, domain, re.IGNORECASE):
                        findings.append({
                            'type': 'RANSOMWARE_SIGNATURE',
                            'url': url,
                            'domain': domain,
                            'ransomware': ransomware,
                            'severity': 'CRITICO'
                        })
                        print(f"   [[CRITICO]] Ransomware: {ransomware}")
                        
        except:
            pass
            
        return findings
        
    async def check_crypto_addresses(self) -> List[Dict]:
        """Busca direcciones de criptomonedas"""
        findings = []
        
        try:
            resp = await self.client.get(self.url)
            if not resp:
                return findings
                
            html = await resp.text()
            
            for pattern, crypto in self.crypto_patterns:
                matches = re.findall(pattern, html)
                for match in matches[:5]:
                    findings.append({
                        'type': 'CRYPTO_ADDRESS',
                        'crypto': crypto,
                        'address': match,
                        'severity': 'ALTO'
                    })
                    
            if findings:
                print(f"   [[WARN]] Direcciones crypto encontradas: {len(findings)}")
                
        except:
            pass
            
        return findings
        
    async def check_behavior(self) -> List[Dict]:
        """Analiza comportamiento sospechoso"""
        findings = []
        
        try:
            # 1. Muchas redirecciones
            resp = await self.client.get(self.url, allow_redirects=False)
            if resp and resp.status in [301, 302, 307, 308]:
                location = resp.headers.get('location', '')
                if 'onion' in location or 'tor' in location:
                    findings.append({
                        'type': 'SUSPICIOUS_REDIRECT',
                        'url': self.url,
                        'location': location,
                        'severity': 'ALTO'
                    })
                    
            # 2. Timeouts extraños
            # (implementación básica)
            
        except:
            pass
            
        return findings
        
    async def scan(self):
        """Ejecuta detección completa"""
        print(f"\n💰 RANSOMWARE DETECTOR v2.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            # Extensiones
            print("[*] Buscando archivos con extensiones sospechosas...")
            findings = await self.scan_files()
            self.findings.extend(findings)
            
            # Notas
            print("\n[*] Buscando notas de rescate...")
            findings = await self.scan_notes()
            self.findings.extend(findings)
            
            # C2
            print("\n[*] Detectando servidores C2...")
            findings = await self.detect_c2()
            self.findings.extend(findings)
            
            # Crypto
            print("\n[*] Buscando direcciones de criptomonedas...")
            findings = await self.check_crypto_addresses()
            self.findings.extend(findings)
            
            # Comportamiento
            print("\n[*] Analizando comportamiento...")
            findings = await self.check_behavior()
            self.findings.extend(findings)
            
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS RANSOMWARE")
            print("="*70)
            
            if self.findings:
                criticos = [f for f in self.findings if f['severity'] == 'CRITICO']
                altos = [f for f in self.findings if f['severity'] == 'ALTO']
                
                if criticos:
                    print(f"\n[CRITICO] CRÍTICOS: {len(criticos)}")
                    for f in criticos:
                        print(f"   • {f['type']}")
                        
                if altos:
                    print(f"\n[WARN]  ALTOS: {len(altos)}")
                    
                print(f"\n[OK] TOTAL: {len(self.findings)}")
            else:
                print("\n[OK] No se detectaron indicadores de ransomware")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 ransomware_detector.py <URL>")
        sys.exit(1)
        
    detector = RansomwareDetector(sys.argv[1])
    await detector.scan()

if __name__ == "__main__":
    asyncio.run(main())
