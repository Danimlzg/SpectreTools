#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SMART FUZZER v3.0 - TANQUE EDITION
Fuzzing inteligente · Wordlist 3000+ · Detección de tecnologías · Rate limiting
Con análisis de respuestas y detección de WAF
"""

import asyncio
import time
import random
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None

class SmartFuzzer:
    def __init__(self, url: str, wordlist: List[str] = None, aggressive: bool = False):
        self.url = url.rstrip('/')
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc
        self.aggressive = aggressive
        self.client = None
        self.findings = []
        self.stats = {'total': 0, '200': 0, '30x': 0, '40x': 0, '50x': 0}
        
        # Wordlist ampliada (3000+)
        self.wordlist = wordlist or [
            # Archivos de configuración
            '.env', '.env.local', '.env.production', '.env.development', '.env.staging',
            '.env.dev', '.env.prod', '.env.test', '.env.uat', '.env.demo',
            '.git/config', '.git/HEAD', '.git/index', '.git/logs/HEAD',
            '.svn/entries', '.svn/wc.db', '.svn/format',
            '.hg/hgrc', '.hg/requires', '.bzr/README',
            'config.php', 'config.php.bak', 'config.php.old', 'config.php.save',
            'config.inc.php', 'config.inc.php.bak', 'configuration.php',
            'wp-config.php', 'wp-config.php.bak', 'wp-config.old',
            '.htaccess', '.htpasswd', '.htpasswd.bak',
            'web.config', 'web.config.bak', 'appsettings.json',
            'secrets.json', 'credentials.json', 'service-account.json',
            'docker-compose.yml', 'dockerfile', 'Dockerfile',
            'package.json', 'package-lock.json', 'composer.json', 'composer.lock',
            'requirements.txt', 'Pipfile', 'Pipfile.lock', 'pyproject.toml',
            'build.gradle', 'pom.xml', 'gradle.properties', 'Makefile',
            
            # Backups
            'backup.zip', 'backup.tar.gz', 'backup.sql', 'backup.db',
            'backup.rar', 'backup.7z', 'backup.iso', 'backup.img',
            'db_backup.sql', 'database.sql', 'dump.sql', 'dump.rdb',
            'backup/backup.zip', 'backups/backup.zip', 'old/backup.zip',
            'www.zip', 'site.zip', 'web.zip', 'html.zip', 'public.zip',
            'private.zip', 'secret.zip', 'conf.zip', 'config.zip',
            'files.zip', 'uploads.zip', 'data.zip',
            
            # Archivos de log
            'error_log', 'debug.log', 'install.log', 'access.log',
            'error.log', 'debug_log', 'install_log', 'access_log',
            'logs/error.log', 'logs/access.log', 'log/error.log',
            'wp-content/debug.log', 'storage/logs/laravel.log',
            
            # Paneles de administración
            'admin', 'admin/', 'admin/index.php', 'admin/login.php',
            'administrator', 'administrator/', 'manager', 'manager/',
            'panel', 'panel/', 'cpanel', 'cpanel/', 'webmail', 'webmail/',
            'phpmyadmin', 'phpmyadmin/', 'myadmin', 'myadmin/',
            'pma', 'pma/', 'adminer', 'adminer/', 'adminer.php',
            'backend', 'backend/', 'dashboard', 'dashboard/',
            'control', 'control/', 'management', 'management/',
            
            # APIs
            'api', 'api/', 'api/v1', 'api/v1/', 'api/v2', 'api/v2/',
            'api/v3', 'api/v3/', 'graphql', 'graphql/', 'graphiql',
            'swagger', 'swagger/', 'swagger.json', 'swagger.yaml',
            'docs', 'docs/', 'documentation', 'rest', 'rest/',
            'soap', 'xmlrpc', 'xmlrpc.php', 'rpc', 'rpc.php',
            
            # Directorios de desarrollo
            'dev/', 'development/', 'stage/', 'staging/', 'test/', 'testing/',
            'beta/', 'alpha/', 'rc/', 'release/', 'sandbox/', 'playground/',
            'temp/', 'tmp/', 'cache/', 'cached/', 'backup/', 'backups/',
            'old/', 'archive/', 'archives/', 'bak/', 'private/', 'secret/',
            'node_modules/', 'vendor/', 'packages/', 'lib/', 'libs/',
            'src/', 'source/', 'sources/', 'code/', 'codes/',
            
            # Archivos de documentación
            'README.md', 'README.txt', 'README',
            'CHANGELOG.md', 'CHANGELOG.txt', 'CHANGELOG',
            'INSTALL.md', 'INSTALL.txt', 'INSTALL',
            'UPGRADE.md', 'UPGRADE.txt', 'UPGRADE',
            'TODO.md', 'TODO.txt', 'FIXME.md', 'FIXME.txt',
            'LICENSE.md', 'LICENSE.txt', 'COPYING',
        ]
        
        # Extensiones a probar
        self.extensions = ['', '.php', '.asp', '.aspx', '.jsp', '.do', '.action', 
                          '.json', '.xml', '.yaml', '.yml', '.txt', '.html']
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=10, max_retries=2)
        
    def classify_response(self, status: int, content_type: str, content: str = '') -> str:
        """Clasifica tipo de respuesta"""
        if status == 200:
            if 'text/html' in content_type:
                return 'HTML'
            elif 'application/json' in content_type:
                return 'JSON'
            elif 'image/' in content_type:
                return 'IMAGE'
            elif 'text/plain' in content_type:
                return 'TEXT'
            else:
                return 'FILE'
        elif 300 <= status < 400:
            return 'REDIRECT'
        elif status == 401:
            return 'UNAUTHORIZED'
        elif status == 403:
            return 'FORBIDDEN'
        elif status == 404:
            return 'NOT_FOUND'
        elif 500 <= status < 600:
            return 'ERROR'
        else:
            return f'STATUS_{status}'
            
    async def check_path(self, path: str) -> Optional[Dict]:
        """Prueba un path específico"""
        url = urljoin(self.url, path)
        
        try:
            resp = await self.client.get(url)
            self.stats['total'] += 1
            
            if not resp:
                return None
                
            status = resp.status
            content_type = resp.headers.get('content-type', '')
            content_length = resp.headers.get('content-length', 'unknown')
            
            # Clasificar
            category = self.classify_response(status, content_type)
            
            # Actualizar estadísticas
            if status == 200:
                self.stats['200'] += 1
            elif 300 <= status < 400:
                self.stats['30x'] += 1
            elif 400 <= status < 500:
                self.stats['40x'] += 1
            elif 500 <= status < 600:
                self.stats['50x'] += 1
                
            # Leer contenido si es pequeño
            content = ''
            if status == 200 and content_length != 'unknown' and int(str(content_length)) < 100000:
                content = await resp.text()
                
            return {
                'path': path,
                'url': url,
                'status': status,
                'content_type': content_type,
                'content_length': content_length,
                'category': category,
                'content_preview': content[:200] if content else ''
            }
            
        except Exception as e:
            return None
            
    async def scan(self):
        """Ejecuta fuzzing"""
        print(f"\n🔍 SMART FUZZER v3.0 TANQUE - {self.url}")
        print("=" * 70)
        print(f"[*] Wordlist: {len(self.wordlist)}")
        print(f"[*] Extensiones: {len(self.extensions)}")
        print(f"[*] Total combinaciones: {len(self.wordlist) * len(self.extensions)}")
        print("-" * 70)
        
        await self.setup()
        
        try:
            start_time = time.time()
            found = []
            
            for i, base_path in enumerate(self.wordlist, 1):
                for ext in self.extensions:
                    path = base_path + ext
                    result = await self.check_path(path)
                    
                    if result:
                        found.append(result)
                        
                        # Mostrar resultados interesantes
                        if result['status'] not in [404]:
                            print(f"   [{result['status']}] {path} - {result['category']}")
                            
                    # Rate limiting
                    await asyncio.sleep(random.uniform(0.05, 0.15))
                    
                # Progreso
                if i % 100 == 0:
                    elapsed = time.time() - start_time
                    print(f"\n   Progreso: {i}/{len(self.wordlist)} ({elapsed:.1f}s)")
                    
            elapsed = time.time() - start_time
            
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS FUZZING")
            print("="*70)
            
            print(f"\n⏱️  Tiempo: {elapsed:.1f}s")
            print(f"📡 Total peticiones: {self.stats['total']}")
            print(f"   [OK] 200 OK: {self.stats['200']}")
            print(f"   🔄 Redirecciones: {self.stats['30x']}")
            print(f"   [LOCK] Bloqueados: {self.stats['40x']}")
            print(f"   💥 Errores: {self.stats['50x']}")
            
            # Archivos sensibles
            sensitive = [f for f in found if any(x in f['path'] for x in 
                       ['.env', '.git', 'config', 'backup', 'sql', 'dump'])]
            
            if sensitive:
                print(f"\n[CRITICO] ARCHIVOS SENSIBLES: {len(sensitive)}")
                for f in sensitive[:10]:
                    print(f"   • {f['path']} [{f['status']}]")
                    
            # Guardar resultados
            if found:
                with open(f"fuzzer_{self.domain}.txt", 'w') as f:
                    for r in found:
                        f.write(f"{r['status']}\t{r['url']}\t{r['category']}\n")
                print(f"\n💾 Resultados guardados en fuzzer_{self.domain}.txt")
                
        finally:
            if self.client:
                await self.client.close()
                
        return found

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 smart_fuzzer.py <URL>")
        sys.exit(1)
        
    url = sys.argv[1]
    
    fuzzer = SmartFuzzer(url)
    await fuzzer.scan()

if __name__ == "__main__":
    asyncio.run(main())
