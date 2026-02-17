import aiohttp
import asyncio
import sys

class VulnScanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.vulns = []
        
    async def check_path(self, session, path):
        try:
            url = f"{self.base_url}/{path}"
            async with session.get(url, timeout=3, allow_redirects=False) as resp:
                if resp.status == 200:
                    content = await resp.read()
                    return {'path': path, 'status': 200, 'size': len(content)}
                elif resp.status in [401, 403]:
                    return {'path': path, 'status': resp.status, 'note': 'Existe pero bloquea'}
        except:
            pass
        return None
    
    async def check_sql(self, session, endpoint):
        payloads = ["'", "\"", "' OR '1'='1", "' UNION SELECT 1--"]
        for p in payloads:
            try:
                url = f"{self.base_url}/{endpoint}?id={p}"
                async with session.get(url, timeout=3) as resp:
                    text = await resp.text()
                    if any(x in text.lower() for x in ['sql', 'mysql', 'syntax']):
                        return {'type': 'SQLi', 'endpoint': endpoint, 'payload': p}
            except:
                pass
        return None
    
    async def run(self):
        paths = [
            '.env', '.git/config', 'wp-config.php', 'backup.zip',
            'phpinfo.php', 'test.php', 'admin', 'login.php',
            'api/v1', 'graphql', 'database.sql', 'dump.sql'
        ]
        
        async with aiohttp.ClientSession() as session:
            tasks = [self.check_path(session, p) for p in paths]
            results = await asyncio.gather(*tasks)
            self.vulns = [r for r in results if r]
            
            sql_tasks = [self.check_sql(session, e) for e in ['', 'index.php', 'api.php']]
            sql_results = await asyncio.gather(*sql_tasks)
            self.vulns.extend([r for r in sql_results if r])
        
        print(f"\n📊 Vulnerabilidades encontradas ({len(self.vulns)}):")
        for v in self.vulns:
            print(f"   ⚠️ {v}")
        return self.vulns

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 vuln_scanner.py <URL>")
        sys.exit(1)
    
    scanner = VulnScanner(sys.argv[1])
    await scanner.run()

if __name__ == "__main__":
    asyncio.run(main())
