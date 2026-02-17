import asyncio
import aiodns
import random
from datetime import datetime
import sys

class UltraDNSEnum:
    """
    DNS enumerator ultra-rápido con múltiples resolvers asíncronos
    """
    def __init__(self, domain, wordlist=None, resolvers=None, workers=100):
        self.domain = domain
        self.workers = workers
        self.found = []
        self.semaphore = asyncio.Semaphore(workers)
        
        self.wordlist = wordlist or [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp',
            'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm',
            'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin',
            'forum', 'news', 'vpn', 'ns3', 'mail2', 'new',
            'mysql', 'old', 'lists', 'support', 'mobile',
            'mx', 'static', 'docs', 'beta', 'shop', 'sql',
            'secure', 'demo', 'usa', 'video', 'smtp2', 'web',
            'podcast', 'mssql', 'remote', 'server', 'mail1',
            'email', 'gw', 'host', 'git', 'api', 'stage',
            'staging', 'prod', 'production', 'backup', 'db',
            'cdn', 'assets', 'img', 'css', 'js', 'files',
            'download', 'upload', 'media', 'video', 'stream',
            'chat', 'bot', 'telegram', 'whatsapp', 'signal',
            'payment', 'pay', 'wallet', 'balance', 'deposit',
            'withdraw', 'bonus', 'promo', 'game', 'casino',
            'slot', 'poker', 'bet', 'sport', 'live', 'result'
        ]
        
        self.resolvers = resolvers or [
            '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',
            '9.9.9.9', '149.112.112.112', '208.67.222.222',
            '208.67.220.220', '64.6.64.6', '64.6.65.6',
            '8.26.56.26', '8.20.247.20', '77.88.8.8',
            '77.88.8.1', '185.228.168.9', '185.228.169.9',
            '76.76.19.19', '76.223.122.150'
        ]
        
    async def query_with_resolver(self, resolver, sub):
        try:
            loop = asyncio.get_running_loop()
            resolver_obj = aiodns.DNSResolver(loop=loop, nameservers=[resolver])
            result = await resolver_obj.query(f"{sub}.{self.domain}", 'A')
            if result:
                ips = [r.host for r in result]
                return f"{sub}.{self.domain}", ips, resolver
        except:
            pass
        return None
    
    async def query_all_resolvers(self, sub):
        tasks = []
        for resolver in random.sample(self.resolvers, min(3, len(self.resolvers))):
            tasks.append(self.query_with_resolver(resolver, sub))
        
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                return r
        return None
    
    async def check_subdomain(self, sub):
        async with self.semaphore:
            result = await self.query_all_resolvers(sub)
            if result:
                self.found.append(result)
                return True
        return False
    
    async def run(self):
        print(f"\n🚀 UltraDNSEnum escaneando {self.domain}")
        print(f"   Subdominios: {len(self.wordlist)}")
        print(f"   Resolvers: {len(self.resolvers)}")
        print(f"   Concurrencia: {self.workers} tasks")
        print("-" * 50)
        
        start = datetime.now()
        
        tasks = [self.check_subdomain(sub) for sub in self.wordlist]
        
        batch_size = 200
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i+batch_size]
            await asyncio.gather(*batch)
            print(f"   Progreso: {min(i+batch_size, len(self.wordlist))}/{len(self.wordlist)}")
        
        elapsed = (datetime.now() - start).total_seconds()
        
        print("-" * 50)
        print(f"✅ Escaneo completado en {elapsed:.1f}s")
        print(f"📊 Subdominios encontrados: {len(self.found)}")
        
        return self.found

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 ultra_dns_enum.py <dominio>")
        sys.exit(1)
    
    scanner = UltraDNSEnum(sys.argv[1])
    await scanner.run()

if __name__ == "__main__":
    asyncio.run(main())
