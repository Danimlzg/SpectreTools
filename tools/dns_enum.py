import asyncio
import aiodns
import sys

class DNSEnum:
    def __init__(self, domain):
        self.domain = domain
        self.resolver = aiodns.DNSResolver()
        self.found = []
        self.wordlist = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'm', 'imap', 'test', 'dev',
            'blog', 'vpn', 'mysql', 'api', 'admin', 'forum', 'news',
            'support', 'mobile', 'mx', 'static', 'docs', 'beta', 'shop',
            'secure', 'demo', 'cdn', 'assets', 'img', 'css', 'js', 'files'
        ]
        
    async def query(self, sub):
        try:
            result = await self.resolver.query(f"{sub}.{self.domain}", 'A')
            if result:
                return f"{sub}.{self.domain}", [r.host for r in result]
        except:
            pass
        return None
    
    async def run(self):
        tasks = [self.query(sub) for sub in self.wordlist]
        results = await asyncio.gather(*tasks)
        self.found = [r for r in results if r]
        
        print(f"\n📊 Subdominios encontrados ({len(self.found)}):")
        for sub, ips in self.found:
            print(f"   📌 {sub} → {', '.join(ips)}")
        return self.found

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 dns_enum.py <dominio>")
        sys.exit(1)
    
    enum = DNSEnum(sys.argv[1])
    await enum.run()

if __name__ == "__main__":
    asyncio.run(main())
