#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CLOUD ENUMERATOR v3.0 - TANQUE EDITION
Enumeración masiva de buckets · Verificación de propiedad · Sin rate limiting
AWS · Azure · Google · DigitalOcean · Alibaba
"""

import asyncio
import aiohttp
import sys
import re
import json
from typing import Dict, List, Optional
from urllib.parse import urlparse
from datetime import datetime
import random

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class CloudEnumerator:
    def __init__(self, domain: str, aggressive: bool = False):
        self.domain = domain.lower()
        self.base_name = domain.split('.')[0]
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        
        # ============================================================
        # WORDLISTS ÉLITE - 500+ patrones por proveedor
        # ============================================================
        self.bucket_patterns = {
            'aws': {
                'name': 'AWS S3',
                'patterns': self._generate_aws_patterns(),
                'urls': [
                    "https://{bucket}.s3.amazonaws.com",
                    "https://s3.amazonaws.com/{bucket}",
                    "https://{bucket}.s3-website-{region}.amazonaws.com",
                    "https://{bucket}.s3.{region}.amazonaws.com",
                ],
                'regions': ['us-east-1', 'us-west-1', 'eu-west-1', 'ap-southeast-1']
            },
            'azure': {
                'name': 'Azure Blob',
                'patterns': self._generate_azure_patterns(),
                'urls': [
                    "https://{bucket}.blob.core.windows.net",
                    "https://{bucket}.blob.core.windows.net/{container}",
                    "https://{bucket}.file.core.windows.net",
                    "https://{bucket}.queue.core.windows.net",
                ],
                'containers': ['public', 'private', 'assets', 'files', 'images', 'data']
            },
            'google': {
                'name': 'Google Storage',
                'patterns': self._generate_google_patterns(),
                'urls': [
                    "https://storage.googleapis.com/{bucket}",
                    "https://{bucket}.storage.googleapis.com",
                    "https://{bucket}.storage-download.googleapis.com",
                ]
            },
            'digitalocean': {
                'name': 'DigitalOcean Spaces',
                'patterns': self._generate_do_patterns(),
                'urls': [
                    "https://{bucket}.{region}.digitaloceanspaces.com",
                    "https://{bucket}.digitaloceanspaces.com",
                ],
                'regions': ['nyc3', 'sfo3', 'ams3', 'sgp1', 'fra1']
            },
            'alibaba': {
                'name': 'Alibaba OSS',
                'patterns': self._generate_alibaba_patterns(),
                'urls': [
                    "https://{bucket}.oss-{region}.aliyuncs.com",
                    "https://{bucket}.oss.aliyuncs.com",
                ],
                'regions': ['cn-hangzhou', 'cn-shanghai', 'us-east-1', 'eu-central-1']
            }
        }
        
        # Extensiones de archivos de configuración
        self.config_extensions = [
            '.env', '.json', '.yaml', '.yml', '.config', '.conf', 
            '.ini', '.xml', '.properties', '.cfg', '.backup', '.bak',
            '.old', '.txt', '.sql', '.db', '.credentials', '.secret'
        ]
        
        # Palabras clave para verificar propiedad
        self.ownership_keywords = [
            domain, self.base_name,
            domain.replace('.', '_'), domain.replace('.', '-'),
            f"@{domain}", f"www.{domain}"
        ]
        
    def _generate_aws_patterns(self) -> List[str]:
        """Genera patrones AWS (200+)"""
        patterns = []
        base = self.base_name
        
        # Básicos
        bases = [base, f"{base}-prod", f"{base}-dev", f"{base}-stg", f"{base}-test"]
        patterns.extend(bases)
        
        # Prefijos comunes
        prefixes = ['', 'aws-', 's3-', 'cloud-', 'data-', 'backup-', 'static-', 'media-']
        suffixes = ['', '-bucket', '-storage', '-files', '-assets', '-uploads', '-public', '-private']
        
        for prefix in prefixes:
            for suffix in suffixes:
                patterns.append(f"{prefix}{base}{suffix}")
                
        # Números
        for i in range(1, 100):
            patterns.append(f"{base}{i}")
            
        # Entornos
        envs = ['prod', 'production', 'dev', 'development', 'test', 'testing', 
                'stage', 'staging', 'qa', 'uat', 'demo', 'sandbox']
        for env in envs:
            patterns.append(f"{base}-{env}")
            patterns.append(f"{env}-{base}")
            
        return list(set(patterns))
        
    def _generate_azure_patterns(self) -> List[str]:
        """Genera patrones Azure"""
        patterns = []
        base = self.base_name
        
        # Sin guiones (Azure no permite)
        patterns.append(base)
        patterns.append(f"{base}backup")
        patterns.append(f"{base}data")
        patterns.append(f"{base}files")
        patterns.append(f"{base}static")
        patterns.append(f"{base}assets")
        patterns.append(f"{base}media")
        patterns.append(f"{base}public")
        patterns.append(f"{base}private")
        
        # Números
        for i in range(1, 50):
            patterns.append(f"{base}{i}")
            
        return list(set(patterns))
        
    def _generate_google_patterns(self) -> List[str]:
        """Genera patrones Google"""
        patterns = []
        base = self.base_name
        
        # Similares a AWS
        suffixes = ['', '-bucket', '-storage', '-files', '-assets', '-data']
        for suffix in suffixes:
            patterns.append(f"{base}{suffix}")
            patterns.append(f"{base}-prod{suffix}")
            patterns.append(f"{base}-dev{suffix}")
            
        return list(set(patterns))
        
    def _generate_do_patterns(self) -> List[str]:
        """Genera patrones DigitalOcean"""
        patterns = []
        base = self.base_name
        
        patterns.append(base)
        patterns.append(f"{base}-space")
        patterns.append(f"{base}-cdn")
        
        return list(set(patterns))
        
    def _generate_alibaba_patterns(self) -> List[str]:
        """Genera patrones Alibaba"""
        patterns = []
        base = self.base_name
        
        patterns.append(base)
        patterns.append(f"{base}-oss")
        patterns.append(f"{base}-bucket")
        
        return list(set(patterns))
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=10, max_retries=2)
        
    async def check_bucket(self, provider: str, bucket: str, url_template: str, **kwargs) -> Optional[Dict]:
        """Verifica un bucket con todas las variantes"""
        url = url_template.format(bucket=bucket, **kwargs)
        
        try:
            # Pequeño delay aleatorio para evitar rate limiting
            await asyncio.sleep(random.uniform(0.1, 0.3))
            
            resp = await self.client.get(url)
            if not resp:
                return None
                
            # Leer contenido (limitado)
            text = await resp.text()
            preview = text[:5000]
            
            # Determinar estado
            status = 'UNKNOWN'
            severity = 'INFO'
            
            if resp.status == 200:
                # Verificar si es listable
                if 'ListBucketResult' in text or 'Contents' in text or 'Key' in text:
                    status = 'PUBLIC_LISTABLE'
                    severity = 'CRITICO'
                else:
                    status = 'PUBLIC'
                    severity = 'ALTO'
                    
                # Verificar propiedad
                ownership = self.verify_ownership(preview)
                if ownership['confidence'] == 'ALTO':
                    severity = 'CRITICO'  # Si es del dominio, más grave
                    
            elif resp.status == 403:
                # Puede existir pero privado
                status = 'PRIVATE'
                severity = 'INFO'
                return None  # No reportamos privados
            else:
                return None
                
            return {
                'provider': provider,
                'bucket': bucket,
                'url': url,
                'status': status,
                'severity': severity,
                'ownership': ownership if status != 'PRIVATE' else None,
                'status_code': resp.status,
                'content_type': resp.headers.get('Content-Type', ''),
                'content_length': len(text)
            }
            
        except Exception as e:
            return None
            
    def verify_ownership(self, content: str) -> Dict:
        """Verifica si el contenido pertenece al dominio"""
        proof = {
            'confidence': 'BAJO',
            'evidence': []
        }
        
        content_lower = content.lower()
        
        for keyword in self.ownership_keywords:
            if keyword.lower() in content_lower:
                proof['evidence'].append(f"Dominio encontrado: {keyword}")
                proof['confidence'] = 'ALTO'
                break
                
        # Buscar archivos de configuración
        for ext in self.config_extensions:
            if ext in content_lower and len(content) < 10000:
                proof['evidence'].append(f"Archivo de configuración: {ext}")
                if proof['confidence'] == 'BAJO':
                    proof['confidence'] = 'MEDIO'
                    
        return proof
        
    async def scan(self):
        """Ejecuta escaneo masivo"""
        print(f"\n☁️  CLOUD ENUMERATOR v3.0 TANQUE - {self.domain}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            total_tests = 0
            for provider, config in self.bucket_patterns.items():
                patterns = config['patterns']
                urls = config['urls']
                
                # Estadísticas
                if 'regions' in config:
                    tests = len(patterns) * len(urls) * len(config['regions'])
                elif 'containers' in config:
                    tests = len(patterns) * len(urls) * len(config['containers'])
                else:
                    tests = len(patterns) * len(urls)
                    
                total_tests += tests
                print(f"[*] {config['name']}: {len(patterns)} patrones | {tests} pruebas")
                
            print(f"[*] TOTAL: {total_tests} combinaciones")
            print("-" * 70)
            
            # Escanear cada proveedor
            for provider, config in self.bucket_patterns.items():
                print(f"\n🔍 Escaneando {config['name']}...")
                
                for bucket in config['patterns'][:100]:  # Limitar a 100 por proveedor por ahora
                    for url_template in config['urls']:
                        
                        if 'regions' in config:
                            # Probar cada región
                            for region in config['regions']:
                                result = await self.check_bucket(
                                    config['name'], 
                                    bucket, 
                                    url_template,
                                    region=region
                                )
                                if result:
                                    self.findings.append(result)
                                    self._print_result(result)
                                    
                        elif 'containers' in config:
                            # Probar cada contenedor
                            for container in config['containers']:
                                result = await self.check_bucket(
                                    config['name'],
                                    bucket,
                                    url_template,
                                    container=container
                                )
                                if result:
                                    self.findings.append(result)
                                    self._print_result(result)
                        else:
                            # Sin variantes
                            result = await self.check_bucket(
                                config['name'],
                                bucket,
                                url_template
                            )
                            if result:
                                self.findings.append(result)
                                self._print_result(result)
                                
            # Mostrar resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS CLOUD")
            print("="*70)
            
            if self.findings:
                criticos = [f for f in self.findings if f['severity'] == 'CRITICO']
                altos = [f for f in self.findings if f['severity'] == 'ALTO']
                
                print(f"\n[CRITICO] CRÍTICOS (listables): {len(criticos)}")
                for f in criticos[:10]:
                    print(f"   • {f['provider']}: {f['url']}")
                    if f.get('ownership', {}).get('evidence'):
                        print(f"     ↳ {f['ownership']['evidence'][0][:100]}")
                        
                print(f"\n[WARN]  ALTOS (públicos): {len(altos)}")
                for f in altos[:10]:
                    print(f"   • {f['provider']}: {f['url']}")
                    
                print(f"\n[OK] TOTAL: {len(self.findings)} buckets públicos")
                
                # Guardar resultados
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"cloud_{self.domain}_{timestamp}.json"
                with open(filename, 'w') as f:
                    json.dump(self.findings, f, indent=2, default=str)
                print(f"\n💾 Resultados guardados en {filename}")
                
            else:
                print("\n[OK] No se encontraron buckets públicos")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings
        
    def _print_result(self, result: Dict):
        """Muestra resultado formateado"""
        if result['severity'] == 'CRITICO':
            print(f"   [[CRITICO]] {result['provider']} - {result['url']}")
            if result.get('ownership', {}).get('evidence'):
                print(f"        ↳ {result['ownership']['evidence'][0][:100]}")
        elif result['severity'] == 'ALTO':
            print(f"   [[WARN]] {result['provider']} - {result['url']}")

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 cloud_enum.py <dominio> [--aggressive]")
        print("Ejemplo: python3 cloud_enum.py ejemplo.com")
        sys.exit(1)
        
    domain = sys.argv[1]
    aggressive = '--aggressive' in sys.argv
    
    enumerator = CloudEnumerator(domain, aggressive)
    await enumerator.scan()

if __name__ == "__main__":
    asyncio.run(main())
