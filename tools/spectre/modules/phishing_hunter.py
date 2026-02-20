#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PHISHING HUNTER v2.0 - ÉLITE
Detección de phishing en tiempo real para bug bounty
"""

import aiohttp
import asyncio
import re
import ssl
import socket
import whois
import json
from datetime import datetime, timedelta
from urllib.parse import urlparse
import dns.resolver

class PhishingHunter:
    def __init__(self, target, config=None):
        self.target = target.lower()
        self.config = config or {}
        self.parsed = urlparse(target if '://' in target else f"http://{target}")
        self.domain = self.parsed.netloc or target
        self.base_domain = '.'.join(self.domain.split('.')[-2:])
        self.findings = []
        self.risk_score = 0
        self.max_risk = 100
        
        # Palabras clave de marcas suplantadas
        self.brand_keywords = [
            'paypal', 'apple', 'microsoft', 'google', 'amazon',
            'netflix', 'spotify', 'facebook', 'instagram', 'whatsapp',
            'telegram', 'binance', 'coinbase', 'blockchain', 'wallet',
            'dhl', 'fedex', 'ups', 'correos', 'bank', 'bbva',
            'santander', 'caixabank', 'ing', 'payoneer', 'stripe'
        ]
        
    async def calculate_risk_score(self):
        """Calcula puntuación de riesgo 0-100"""
        checks = [
            self.check_domain_age,
            self.check_ssl_certificate,
            self.check_typosquatting,
            self.check_blacklists,
            self.check_url_shorteners,
            self.check_suspicious_tlds,
            self.check_forms_exfiltration
        ]
        
        for check in checks:
            try:
                score = await check()
                self.risk_score += score
            except:
                pass
                
        return min(self.risk_score, self.max_risk)
        
    async def check_domain_age(self):
        """Dominios recientes = phishing"""
        try:
            w = whois.whois(self.domain)
            if not w.creation_date:
                return 20
                
            creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            days_old = (datetime.now() - creation).days
            
            if days_old < 7:
                return 40  # CRÍTICO
            elif days_old < 30:
                return 30  # ALTO
            elif days_old < 90:
                return 15  # MEDIO
            return 0
        except:
            return 10
            
    async def check_ssl_certificate(self):
        """Certificados inválidos = phishing"""
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(5)
                s.connect((self.domain, 443))
                cert = s.getpeercert()
                
                # Verificar fechas
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if datetime.now() > not_after:
                    return 35  # Certificado expirado
                    
                # Verificar SAN
                san = [item[1] for item in cert.get('subjectAltName', [])]
                if self.domain not in san:
                    return 25  # Certificado no coincide
                    
                return 0
        except:
            return 30  # No HTTPS o error
            
    async def check_typosquatting(self):
        """Detección de typosquatting"""
        score = 0
        domain_lower = self.base_domain.lower()
        
        for brand in self.brand_keywords:
            if brand in domain_lower:
                # Calcular similitud
                if brand == domain_lower:
                    continue  # Es la marca real
                    
                # Typos comunes
                typos = [
                    brand.replace('o', '0'),
                    brand.replace('0', 'o'),
                    brand.replace('l', '1'),
                    brand.replace('i', '1'),
                    brand + 'secure',
                    'secure' + brand,
                    brand + 'login',
                    'login' + brand
                ]
                
                if any(typo in domain_lower for typo in typos):
                    score += 25
                    
                # Levenshtein distance (simplificado)
                if len(brand) > 3 and brand in domain_lower:
                    score += 15
                    
        return min(score, 40)
        
    async def check_blacklists(self):
        """Verifica en blacklists públicas"""
        score = 0
        session = aiohttp.ClientSession()
        
        try:
            # Google Safe Browsing (si hay API key)
            if self.config.get('apis', {}).get('google_safe_browsing'):
                api_key = self.config['apis']['google_safe_browsing']
                url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
                
                payload = {
                    "client": {"clientId": "spectre", "clientVersion": "6.5"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": f"https://{self.domain}"}]
                    }
                }
                
                async with session.post(url, json=payload) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get('matches'):
                            return 50  # CRÍTICO - En blacklist
                            
            # VirusTotal (si hay API key)
            if self.config.get('apis', {}).get('virustotal'):
                api_key = self.config['apis']['virustotal']
                url = f"https://www.virustotal.com/api/v3/domains/{self.domain}"
                
                headers = {"x-apikey": api_key}
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        if stats.get('malicious', 0) > 0:
                            score += 40
                        elif stats.get('suspicious', 0) > 0:
                            score += 20
                            
        except:
            pass
        finally:
            await session.close()
            
        return score
        
    async def check_url_shorteners(self):
        """Detecta acortadores de URLs"""
        shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'short.link', 'cutt.ly', 'rebrand.ly',
            't.co', 'lnkd.in', 'db.tt', 'qr.ae', 'cur.lv'
        ]
        
        if any(short in self.domain for short in shorteners):
            return 30  # ALTO - Los acortadores ocultan el destino
            
        return 0
        
    async def check_suspicious_tlds(self):
        """TLDs sospechosos para phishing"""
        suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Dominios gratis
            '.xyz', '.top', '.club', '.online', '.site',
            '.live', '.work', '.life', '.vin', '.bid',
            '.trade', '.webcam', '.science', '.date'
        ]
        
        for tld in suspicious_tlds:
            if self.domain.endswith(tld):
                return 25
                
        return 0
        
    async def check_forms_exfiltration(self):
        """Analiza si los forms envían datos a servidores externos"""
        score = 0
        session = aiohttp.ClientSession()
        
        try:
            async with session.get(f"https://{self.domain}", timeout=10, ssl=False) as resp:
                html = await resp.text()
                
                # Buscar forms que envían a dominios diferentes
                form_pattern = r'<form[^>]*action=["\'](https?://[^"\']+)["\']'
                matches = re.findall(form_pattern, html, re.IGNORECASE)
                
                for match in matches:
                    parsed = urlparse(match)
                    if parsed.netloc and parsed.netloc != self.domain:
                        score += 15  # Form envía a dominio externo
                        
                # Buscar iframes de pago falsos
                if 'paypal' in html.lower() and 'paypal.com' not in html.lower():
                    score += 20
                    
        except:
            pass
        finally:
            await session.close()
            
        return min(score, 30)
        
    async def scan(self):
        """Ejecuta el escaneo anti-phishing"""
        print(f"\n🎣 PHISHING HUNTER ÉLITE - {self.domain}")
        print("=" * 60)
        
        risk = await self.calculate_risk_score()
        
        # Clasificación de riesgo
        if risk >= 70:
            severity = "CRÍTICO"
            recommendation = "BLOQUEAR INMEDIATAMENTE - Phishing confirmado"
        elif risk >= 40:
            severity = "ALTO"
            recommendation = "SOSPECHOSO - Requiere análisis manual"
        elif risk >= 20:
            severity = "MEDIO"
            recommendation = "PRECAUCIÓN - Posible suplantación"
        else:
            severity = "BAJO"
            recommendation = "Probablemente legítimo"
            
        finding = {
            'type': 'PHISHING_ANALYSIS',
            'domain': self.domain,
            'risk_score': risk,
            'severity': severity,
            'recommendation': recommendation,
            'timestamp': str(datetime.now())
        }
        
        self.findings.append(finding)
        
        print(f"\n📊 PUNTUACIÓN DE RIESGO: {risk}/100")
        print(f"[WARN]  SEVERIDAD: {severity}")
        print(f"[INFO] RECOMENDACIÓN: {recommendation}")
        
        # Si es crítico, guardar evidencia
        if risk >= 70:
            evidence_file = f"phishing_evidence_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(evidence_file, 'w') as f:
                json.dump(self.findings, f, indent=2, default=str)
            print(f"💾 Evidencia guardada en {evidence_file}")
            
        return self.findings
