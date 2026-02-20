#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HEADER ROTATOR v2.0 - TANQUE EDITION
Rotación inteligente de headers · Anti-detección · Fingerprinting evasion
Integrado con http_client
"""

import asyncio
import random
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url, headers=None): return None

class HeaderRotator:
    def __init__(self, target: str, num_requests: int = 10):
        self.target = target.rstrip('/')
        self.num_requests = num_requests
        self.client = None
        self.results = []
        
        # User-Agents (50+)
        self.user_agents = [
            # Windows Chrome
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36',
            
            # Windows Firefox
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            
            # Windows Edge
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.2210.91',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/119.0.2210.91',
            
            # Mac Chrome
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36',
            
            # Mac Safari
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/604.1',
            
            # iPhone
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148',
            
            # Android
            'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 Chrome/120.0.6099.210 Mobile',
            'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.6099.210 Mobile',
            'Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 Chrome/120.0.6099.210 Mobile',
            
            # Linux
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
            
            # Bots
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
            'Mozilla/5.0 (compatible; DuckDuckBot-Https; +https://duckduckgo.com/duckduckbot)',
            'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
            'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
            'Twitterbot/1.0',
            'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
            'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
            'TelegramBot (like TwitterBot)',
            'Discordbot/2.0 (+https://discordapp.com)',
        ]
        
        # Accept-Languages
        self.accept_languages = [
            'en-US,en;q=0.9',
            'es-ES,es;q=0.9,en;q=0.8',
            'fr-FR,fr;q=0.9,en;q=0.8',
            'de-DE,de;q=0.9,en;q=0.8',
            'it-IT,it;q=0.9,en;q=0.8',
            'pt-BR,pt;q=0.9,en;q=0.8',
            'ru-RU,ru;q=0.9,en;q=0.8',
            'ja-JP,ja;q=0.9,en;q=0.8',
            'zh-CN,zh;q=0.9,en;q=0.8',
            'ar-SA,ar;q=0.9,en;q=0.8',
            'he-IL,he;q=0.9,en;q=0.8',
            'tr-TR,tr;q=0.9,en;q=0.8',
            'nl-NL,nl;q=0.9,en;q=0.8',
            'pl-PL,pl;q=0.9,en;q=0.8',
            'sv-SE,sv;q=0.9,en;q=0.8',
            'da-DK,da;q=0.9,en;q=0.8',
            'fi-FI,fi;q=0.9,en;q=0.8',
            'no-NO,no;q=0.9,en;q=0.8',
            'cs-CZ,cs;q=0.9,en;q=0.8',
            'hu-HU,hu;q=0.9,en;q=0.8',
            'ro-RO,ro;q=0.9,en;q=0.8',
            'bg-BG,bg;q=0.9,en;q=0.8',
            'el-GR,el;q=0.9,en;q=0.8',
            'th-TH,th;q=0.9,en;q=0.8',
            'vi-VN,vi;q=0.9,en;q=0.8',
            'id-ID,id;q=0.9,en;q=0.8',
            'ms-MY,ms;q=0.9,en;q=0.8',
            'fil-PH,fil;q=0.9,en;q=0.8',
        ]
        
        # Referers
        self.referers = [
            'https://www.google.com/',
            'https://www.google.com/search?q=test',
            'https://www.bing.com/',
            'https://www.bing.com/search?q=test',
            'https://duckduckgo.com/',
            'https://duckduckgo.com/?q=test',
            'https://t.co/',
            'https://l.facebook.com/',
            'https://www.facebook.com/',
            'https://twitter.com/',
            'https://www.linkedin.com/',
            'https://www.reddit.com/',
            'https://news.ycombinator.com/',
            'https://mail.google.com/',
            'https://outlook.live.com/',
            'https://www.yahoo.com/',
            'https://www.baidu.com/',
            'https://yandex.ru/',
            'https://www.ecosia.org/',
            'https://www.qwant.com/',
        ]
        
        # Accept headers
        self.accept_headers = [
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'application/json, text/plain, */*',
            'application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5',
            '*/*',
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    def get_random_headers(self) -> Dict:
        """Genera headers aleatorios"""
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': random.choice(self.accept_headers),
            'Accept-Language': random.choice(self.accept_languages),
            'Referer': random.choice(self.referers),
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'Sec-Ch-Ua': '"Chromium";v="120", "Not_A Brand";v="8"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': f'"{random.choice(["Windows", "macOS", "Linux"])}"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': random.choice(['none', 'cross-site', 'same-origin', 'same-site']),
            'Sec-Fetch-User': '?1',
            'DNT': str(random.choice([0, 1])),
        }
        
    async def make_request(self, request_id: int) -> Dict:
        """Hace una petición con headers rotados"""
        headers = self.get_random_headers()
        
        try:
            resp = await self.client.get(self.target, headers=headers)
            
            result = {
                'id': request_id,
                'headers_used': {
                    'User-Agent': headers['User-Agent'][:50] + '...',
                    'Accept-Language': headers['Accept-Language'],
                    'Referer': headers['Referer'],
                },
                'status': resp.status if resp else 'ERROR',
                'success': resp is not None
            }
            
            if resp:
                result['content_type'] = resp.headers.get('content-type', 'unknown')
                result['server'] = resp.headers.get('server', 'unknown')
                
            return result
            
        except Exception as e:
            return {
                'id': request_id,
                'headers_used': {'User-Agent': headers['User-Agent'][:50] + '...'},
                'status': 'ERROR',
                'error': str(e),
                'success': False
            }
            
    async def run(self):
        """Ejecuta múltiples peticiones con headers rotados"""
        print(f"\n🔄 HEADER ROTATOR v2.0 TANQUE")
        print("=" * 70)
        print(f"[*] Objetivo: {self.target}")
        print(f"[*] Peticiones: {self.num_requests}")
        print(f"[*] User-Agents: {len(self.user_agents)}")
        print(f"[*] Languages: {len(self.accept_languages)}")
        print("-" * 70)
        
        await self.setup()
        
        try:
            tasks = [self.make_request(i+1) for i in range(self.num_requests)]
            results = await asyncio.gather(*tasks)
            
            # Estadísticas
            success = sum(1 for r in results if r.get('success'))
            failed = self.num_requests - success
            
            print(f"\n📊 RESULTADOS:")
            print(f"   [OK] Éxitos: {success}")
            print(f"   ❌ Fallos: {failed}")
            
            if success > 0:
                print(f"\n📝 Últimas peticiones:")
                for r in results[-5:]:
                    print(f"\n   [{r['id']}] Status: {r['status']}")
                    print(f"       UA: {r['headers_used']['User-Agent']}")
                    print(f"       Lang: {r['headers_used']['Accept-Language']}")
                    
        finally:
            if self.client:
                await self.client.close()
                
        return results

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 header_rotator.py <URL> [num_requests]")
        sys.exit(1)
        
    url = sys.argv[1]
    num = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    
    rotator = HeaderRotator(url, num)
    await rotator.run()

if __name__ == "__main__":
    asyncio.run(main())
