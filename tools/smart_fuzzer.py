import aiohttp
import asyncio
import time
import json
import sys

class SmartFuzzer:
    def __init__(self, base_url, wordlist=None):
        self.base_url = base_url.rstrip('/')
        self.wordlist = wordlist or [
            'admin', 'api', 'login', 'backup', '.env', 'config.php',
            'wp-admin', 'database.sql', 'dump.sql', 'credentials.json',
            '.git/config', '.git/HEAD', '.htaccess', 'phpinfo.php',
            'test.php', 'dev', 'staging', 'panel', 'cpanel',
            'webmail', 'phpmyadmin', 'myadmin', 'pma', 'administrator',
            'wp-content', 'uploads', 'files', 'images', 'css', 'js'
        ]
        self.found = []
        
    async def check_url(self, session, path):
        url = f"{self.base_url}/{path}"
        try:
            async with session.get(url, timeout=3, allow_redirects=False) as resp:
                return {
                    'path': path,
                    'url': url,
                    'status': resp.status,
                    'size': len(await resp.read()),
                    'headers': dict(resp.headers)
                }
        except:
            return None
    
    async def run(self):
        async with aiohttp.ClientSession() as session:
            tasks = [self.check_url(session, p) for p in self.wordlist]
            results = await asyncio.gather(*tasks)
            self.found = [r for r in results if r]
        return self.found

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 smart_fuzzer.py <URL>")
        sys.exit(1)
    
    fuzzer = SmartFuzzer(sys.argv[1])
    results = await fuzzer.run()
    
    print(f"\n📊 RESULTADOS ({len(results)} encontrados):")
    for r in results:
        print(f"\n🔗 {r['url']}")
        print(f"   📍 Status: {r['status']}")
        print(f"   📦 Size: {r['size']} bytes")

if __name__ == "__main__":
    asyncio.run(main())
