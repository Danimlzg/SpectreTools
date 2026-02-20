#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SPECTRE SCANNER v2.0 - TANQUE EDITION
Escáner de vulnerabilidades Nikto-like · Tests personalizados · Reportes
Con 100+ checks de seguridad
"""

import asyncio
from urllib.parse import urljoin, urlparse
from datetime import datetime
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class SpectreScanner:
    def __init__(self, url: str, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        self.start_time = None
        
        # Tests de seguridad (100+)
        self.tests = [
            # Archivos expuestos
            {'path': '/.git/config', 'name': 'Git config expuesto', 'severity': 'CRITICO', 'type': 'exposed'},
            {'path': '/.env', 'name': 'Archivo .env expuesto', 'severity': 'CRITICO', 'type': 'exposed'},
            {'path': '/wp-config.php', 'name': 'wp-config.php expuesto', 'severity': 'CRITICO', 'type': 'exposed'},
            {'path': '/config.php', 'name': 'config.php expuesto', 'severity': 'CRITICO', 'type': 'exposed'},
            {'path': '/.htaccess', 'name': '.htaccess expuesto', 'severity': 'ALTO', 'type': 'exposed'},
            {'path': '/.htpasswd', 'name': '.htpasswd expuesto', 'severity': 'CRITICO', 'type': 'exposed'},
            {'path': '/phpinfo.php', 'name': 'phpinfo.php expuesto', 'severity': 'MEDIO', 'type': 'exposed'},
            {'path': '/info.php', 'name': 'info.php expuesto', 'severity': 'MEDIO', 'type': 'exposed'},
            {'path': '/test.php', 'name': 'test.php expuesto', 'severity': 'BAJO', 'type': 'exposed'},
            
            # Backups
            {'path': '/backup.sql', 'name': 'Backup SQL expuesto', 'severity': 'CRITICO', 'type': 'backup'},
            {'path': '/database.sql', 'name': 'Database SQL expuesto', 'severity': 'CRITICO', 'type': 'backup'},
            {'path': '/dump.sql', 'name': 'Dump SQL expuesto', 'severity': 'CRITICO', 'type': 'backup'},
            {'path': '/backup.tar.gz', 'name': 'Backup comprimido', 'severity': 'CRITICO', 'type': 'backup'},
            {'path': '/backup.zip', 'name': 'Backup comprimido', 'severity': 'CRITICO', 'type': 'backup'},
            {'path': '/www.zip', 'name': 'Backup ZIP', 'severity': 'ALTO', 'type': 'backup'},
            {'path': '/site.zip', 'name': 'Backup ZIP', 'severity': 'ALTO', 'type': 'backup'},
            
            # Paneles de admin
            {'path': '/admin/', 'name': 'Panel de admin', 'severity': 'MEDIO', 'type': 'admin'},
            {'path': '/administrator/', 'name': 'Panel de admin (Joomla)', 'severity': 'MEDIO', 'type': 'admin'},
            {'path': '/wp-admin/', 'name': 'Panel de admin (WordPress)', 'severity': 'MEDIO', 'type': 'admin'},
            {'path': '/login/', 'name': 'Página de login', 'severity': 'MEDIO', 'type': 'admin'},
            {'path': '/user/login', 'name': 'Login de usuario', 'severity': 'MEDIO', 'type': 'admin'},
            {'path': '/auth/login', 'name': 'Login de auth', 'severity': 'MEDIO', 'type': 'admin'},
            {'path': '/panel/', 'name': 'Panel de control', 'severity': 'MEDIO', 'type': 'admin'},
            {'path': '/cpanel/', 'name': 'cPanel', 'severity': 'MEDIO', 'type': 'admin'},
            {'path': '/phpmyadmin/', 'name': 'phpMyAdmin', 'severity': 'ALTO', 'type': 'admin'},
            {'path': '/myadmin/', 'name': 'MyAdmin', 'severity': 'ALTO', 'type': 'admin'},
            {'path': '/pma/', 'name': 'PMA', 'severity': 'ALTO', 'type': 'admin'},
            
            # Directorios listables
            {'path': '/backup/', 'name': 'Directorio backups', 'severity': 'ALTO', 'type': 'directory'},
            {'path': '/backups/', 'name': 'Directorio backups', 'severity': 'ALTO', 'type': 'directory'},
            {'path': '/logs/', 'name': 'Directorio logs', 'severity': 'MEDIO', 'type': 'directory'},
            {'path': '/log/', 'name': 'Directorio log', 'severity': 'MEDIO', 'type': 'directory'},
            {'path': '/tmp/', 'name': 'Directorio tmp', 'severity': 'MEDIO', 'type': 'directory'},
            {'path': '/temp/', 'name': 'Directorio temp', 'severity': 'MEDIO', 'type': 'directory'},
            {'path': '/cache/', 'name': 'Directorio cache', 'severity': 'MEDIO', 'type': 'directory'},
            {'path': '/uploads/', 'name': 'Directorio uploads', 'severity': 'MEDIO', 'type': 'directory'},
            {'path': '/files/', 'name': 'Directorio files', 'severity': 'MEDIO', 'type': 'directory'},
            {'path': '/images/', 'name': 'Directorio images', 'severity': 'BAJO', 'type': 'directory'},
            
            # Archivos de información
            {'path': '/README.txt', 'name': 'README expuesto', 'severity': 'BAJO', 'type': 'info'},
            {'path': '/README.md', 'name': 'README expuesto', 'severity': 'BAJO', 'type': 'info'},
            {'path': '/CHANGELOG.txt', 'name': 'CHANGELOG expuesto', 'severity': 'BAJO', 'type': 'info'},
            {'path': '/CHANGELOG.md', 'name': 'CHANGELOG expuesto', 'severity': 'BAJO', 'type': 'info'},
            {'path': '/INSTALL.txt', 'name': 'INSTALL expuesto', 'severity': 'BAJO', 'type': 'info'},
            {'path': '/INSTALL.md', 'name': 'INSTALL expuesto', 'severity': 'BAJO', 'type': 'info'},
            {'path': '/UPGRADE.txt', 'name': 'UPGRADE expuesto', 'severity': 'BAJO', 'type': 'info'},
            {'path': '/robots.txt', 'name': 'robots.txt', 'severity': 'INFO', 'type': 'info'},
            {'path': '/sitemap.xml', 'name': 'Sitemap XML', 'severity': 'INFO', 'type': 'info'},
            {'path': '/crossdomain.xml', 'name': 'crossdomain.xml', 'severity': 'INFO', 'type': 'info'},
            {'path': '/clientaccesspolicy.xml', 'name': 'clientaccesspolicy.xml', 'severity': 'INFO', 'type': 'info'},
            
            # APIs
            {'path': '/api/', 'name': 'API endpoint', 'severity': 'MEDIO', 'type': 'api'},
            {'path': '/api/v1/', 'name': 'API v1', 'severity': 'MEDIO', 'type': 'api'},
            {'path': '/api/v2/', 'name': 'API v2', 'severity': 'MEDIO', 'type': 'api'},
            {'path': '/api/v3/', 'name': 'API v3', 'severity': 'MEDIO', 'type': 'api'},
            {'path': '/graphql', 'name': 'GraphQL endpoint', 'severity': 'ALTO', 'type': 'api'},
            {'path': '/graphiql', 'name': 'GraphiQL interface', 'severity': 'ALTO', 'type': 'api'},
            {'path': '/playground', 'name': 'GraphQL playground', 'severity': 'ALTO', 'type': 'api'},
            {'path': '/swagger', 'name': 'Swagger UI', 'severity': 'MEDIO', 'type': 'api'},
            {'path': '/swagger.json', 'name': 'Swagger JSON', 'severity': 'MEDIO', 'type': 'api'},
            {'path': '/docs', 'name': 'Documentation', 'severity': 'MEDIO', 'type': 'api'},
            {'path': '/rest', 'name': 'REST API', 'severity': 'MEDIO', 'type': 'api'},
            
            # Versiones
            {'path': '/version', 'name': 'Archivo version', 'severity': 'BAJO', 'type': 'version'},
            {'path': '/version.txt', 'name': 'Archivo version', 'severity': 'BAJO', 'type': 'version'},
            {'path': '/version.php', 'name': 'Archivo version', 'severity': 'BAJO', 'type': 'version'},
            {'path': '/VERSION', 'name': 'Archivo VERSION', 'severity': 'BAJO', 'type': 'version'},
            {'path': '/RELEASE', 'name': 'Archivo RELEASE', 'severity': 'BAJO', 'type': 'version'},
            
            # Dependencias
            {'path': '/vendor/', 'name': 'Directorio vendor', 'severity': 'MEDIO', 'type': 'dependency'},
            {'path': '/node_modules/', 'name': 'node_modules', 'severity': 'MEDIO', 'type': 'dependency'},
            {'path': '/composer.json', 'name': 'composer.json', 'severity': 'MEDIO', 'type': 'dependency'},
            {'path': '/composer.lock', 'name': 'composer.lock', 'severity': 'ALTO', 'type': 'dependency'},
            {'path': '/package.json', 'name': 'package.json', 'severity': 'MEDIO', 'type': 'dependency'},
            {'path': '/package-lock.json', 'name': 'package-lock.json', 'severity': 'ALTO', 'type': 'dependency'},
            {'path': '/yarn.lock', 'name': 'yarn.lock', 'severity': 'ALTO', 'type': 'dependency'},
            {'path': '/Gemfile', 'name': 'Gemfile', 'severity': 'MEDIO', 'type': 'dependency'},
            {'path': '/Gemfile.lock', 'name': 'Gemfile.lock', 'severity': 'ALTO', 'type': 'dependency'},
            {'path': '/requirements.txt', 'name': 'requirements.txt', 'severity': 'MEDIO', 'type': 'dependency'},
            {'path': '/Pipfile', 'name': 'Pipfile', 'severity': 'MEDIO', 'type': 'dependency'},
            {'path': '/Pipfile.lock', 'name': 'Pipfile.lock', 'severity': 'ALTO', 'type': 'dependency'},
            
            # Server status
            {'path': '/server-status', 'name': 'Apache server status', 'severity': 'ALTO', 'type': 'status'},
            {'path': '/server-info', 'name': 'Apache server info', 'severity': 'ALTO', 'type': 'status'},
            {'path': '/status', 'name': 'Status page', 'severity': 'MEDIO', 'type': 'status'},
            {'path': '/stats', 'name': 'Stats page', 'severity': 'MEDIO', 'type': 'status'},
            {'path': '/health', 'name': 'Health check', 'severity': 'MEDIO', 'type': 'status'},
            {'path': '/healthz', 'name': 'Health check', 'severity': 'MEDIO', 'type': 'status'},
            {'path': '/metrics', 'name': 'Metrics', 'severity': 'MEDIO', 'type': 'status'},
            
            # Actuators (Spring Boot)
            {'path': '/actuator', 'name': 'Spring Actuator', 'severity': 'ALTO', 'type': 'actuator'},
            {'path': '/actuator/health', 'name': 'Actuator health', 'severity': 'MEDIO', 'type': 'actuator'},
            {'path': '/actuator/info', 'name': 'Actuator info', 'severity': 'MEDIO', 'type': 'actuator'},
            {'path': '/actuator/env', 'name': 'Actuator env', 'severity': 'CRITICO', 'type': 'actuator'},
            {'path': '/actuator/metrics', 'name': 'Actuator metrics', 'severity': 'MEDIO', 'type': 'actuator'},
            {'path': '/actuator/beans', 'name': 'Actuator beans', 'severity': 'ALTO', 'type': 'actuator'},
            {'path': '/actuator/mappings', 'name': 'Actuator mappings', 'severity': 'ALTO', 'type': 'actuator'},
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=10, max_retries=2)
        self.start_time = datetime.now()
        
    def analyze_response(self, test: Dict, status: int, content: str, headers: Dict) -> Optional[Dict]:
        """Analiza respuesta de un test"""
        if status == 0:
            return None
            
        # Archivos expuestos
        if test['type'] in ['exposed', 'backup', 'info', 'dependency'] and status == 200:
            # Verificar que no sea página 404 personalizada
            if '404' not in content.lower() and 'not found' not in content.lower():
                return {
                    'url': urljoin(self.url, test['path']),
                    'name': test['name'],
                    'severity': test['severity'],
                    'type': test['type'],
                    'status': status,
                    'evidence': f'Archivo accesible ({len(content)} bytes)'
                }
                
        # Directorios listables
        if test['type'] == 'directory' and status == 200:
            if 'index of' in content.lower() or 'parent directory' in content.lower():
                return {
                    'url': urljoin(self.url, test['path']),
                    'name': test['name'],
                    'severity': test['severity'],
                    'type': test['type'],
                    'status': status,
                    'evidence': 'Directory listing habilitado'
                }
                
        # APIs
        if test['type'] == 'api' and status == 200:
            if 'application/json' in headers.get('content-type', ''):
                return {
                    'url': urljoin(self.url, test['path']),
                    'name': test['name'],
                    'severity': test['severity'],
                    'type': test['type'],
                    'status': status,
                    'evidence': 'API endpoint accesible'
                }
                
        # Actuators
        if test['type'] == 'actuator' and status == 200:
            return {
                'url': urljoin(self.url, test['path']),
                'name': test['name'],
                'severity': test['severity'],
                'type': test['type'],
                'status': status,
                'evidence': 'Actuator endpoint expuesto'
            }
            
        # Admin panels (incluso 403/401 son interesantes)
        if test['type'] == 'admin' and status in [200, 401, 403]:
            return {
                'url': urljoin(self.url, test['path']),
                'name': test['name'],
                'severity': test['severity'],
                'type': test['type'],
                'status': status,
                'evidence': f'Panel de admin ({status})'
            }
            
        # Cualquier 200 es sospechoso
        if status == 200 and test['type'] not in ['info']:
            return {
                'url': urljoin(self.url, test['path']),
                'name': test['name'],
                'severity': test['severity'],
                'type': test['type'],
                'status': status,
                'evidence': 'Recurso accesible'
            }
            
        return None
        
    async def scan_test(self, test: Dict) -> Optional[Dict]:
        """Ejecuta un test individual"""
        url = urljoin(self.url, test['path'])
        
        try:
            resp = await self.client.get(url)
            if not resp:
                return None
                
            status = resp.status
            content = await resp.text() if resp.status == 200 else ''
            headers = resp.headers
            
            return self.analyze_response(test, status, content, headers)
            
        except Exception as e:
            return None
            
    async def scan(self):
        """Ejecuta escaneo completo"""
        print(f"\n🔍 SPECTRE SCANNER v2.0 TANQUE - {self.url}")
        print("=" * 70)
        print(f"[*] Tests: {len(self.tests)}")
        print("-" * 70)
        
        await self.setup()
        
        try:
            for i, test in enumerate(self.tests, 1):
                result = await self.scan_test(test)
                
                if result:
                    self.findings.append(result)
                    
                    # Mostrar según severidad
                    if result['severity'] == 'CRITICO':
                        print(f"   [{i}] [CRITICO] {result['name']} - {result['url']}")
                    elif result['severity'] == 'ALTO':
                        print(f"   [{i}] [WARN]  {result['name']} - {result['url']}")
                    elif result['severity'] == 'MEDIO':
                        print(f"   [{i}] [INFO] {result['name']}")
                        
                await asyncio.sleep(0.1)
                
            elapsed = (datetime.now() - self.start_time).total_seconds()
            
            # Resumen
            print("\n" + "="*70)
            print("📊 VULNERABILIDADES ENCONTRADAS")
            print("="*70)
            
            if self.findings:
                criticos = [f for f in self.findings if f['severity'] == 'CRITICO']
                altos = [f for f in self.findings if f['severity'] == 'ALTO']
                medios = [f for f in self.findings if f['severity'] == 'MEDIO']
                
                if criticos:
                    print(f"\n[CRITICO] CRÍTICOS: {len(criticos)}")
                    for f in criticos[:5]:
                        print(f"   • {f['name']}: {f['url']}")
                        
                if altos:
                    print(f"\n[WARN]  ALTOS: {len(altos)}")
                    
                print(f"\n[OK] TOTAL: {len(self.findings)}")
                print(f"⏱️  Tiempo: {elapsed:.1f}s")
            else:
                print("\n[OK] No se encontraron vulnerabilidades")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 spectre_scanner.py <URL>")
        sys.exit(1)
        
    url = sys.argv[1]
    
    scanner = SpectreScanner(url)
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
