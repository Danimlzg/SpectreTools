import asyncio
import sys
from datetime import datetime

class AsyncPortScanner:
    def __init__(self, target, ports=range(1, 1001), timeout=0.3, workers=500):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.workers = workers
        self.open_ports = []
        
    async def scan_port(self, port):
        try:
            conn = asyncio.open_connection(self.target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return port
        except:
            return None
    
    async def run(self):
        print(f"🔍 Escaneando {self.target}...")
        start = datetime.now()
        
        tasks = [self.scan_port(p) for p in self.ports]
        results = await asyncio.gather(*tasks)
        self.open_ports = [p for p in results if p]
        
        elapsed = (datetime.now() - start).total_seconds()
        print(f"\n✅ Completado en {elapsed:.1f}s")
        print(f"📊 Puertos abiertos: {sorted(self.open_ports)}")
        return sorted(self.open_ports)

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 fast_port_scanner.py <IP>")
        sys.exit(1)
    
    scanner = AsyncPortScanner(sys.argv[1])
    await scanner.run()

if __name__ == "__main__":
    asyncio.run(main())
