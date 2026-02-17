import asyncio
from datetime import datetime
import sys

class UltraFastScanner:
    """
    Versión mejorada: escaneo stateless-style como masscan
    Workers reducidos para Raspberry Pi
    """
    def __init__(self, target, ports=range(1, 10001), timeout=0.2, workers=300):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.workers = workers
        self.open_ports = []
        self.semaphore = asyncio.Semaphore(workers)

    async def scan_port(self, port):
        """Escaneo optimizado con semáforo y timeout agresivo"""
        async with self.semaphore:
            try:
                conn = asyncio.open_connection(self.target, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                return port
            except:
                return None

    async def worker(self, port):
        """Worker individual"""
        result = await self.scan_port(port)
        if result:
            self.open_ports.append(result)
            print(f"  ✅ Puerto {result} abierto")

    async def run(self):
        """Ejecutar escaneo masivo optimizado"""
        print(f"\n🚀 UltraFastScanner escaneando {self.target}")
        print(f"   Puertos: {min(self.ports)}-{max(self.ports)}")
        print(f"   Workers: {self.workers}")
        print(f"   Timeout: {self.timeout}s")
        print("-" * 50)

        start = datetime.now()

        # Crear tareas para TODOS los puertos de una vez
        tasks = [self.worker(port) for port in self.ports]

        # Ejecutar en batches para no saturar la memoria
        batch_size = 2000
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i+batch_size]
            await asyncio.gather(*batch)
            print(f"   Progreso: {min(i+batch_size, len(self.ports))}/{len(self.ports)} puertos")

        elapsed = (datetime.now() - start).total_seconds()

        print("-" * 50)
        print(f"✅ Escaneo completado en {elapsed:.1f}s")
        print(f"📊 Puertos abiertos: {sorted(self.open_ports)}")
        return sorted(self.open_ports)

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 ultra_fast_scanner.py <IP> [puerto_inicio] [puerto_fin]")
        sys.exit(1)

    target = sys.argv[1]
    start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 10000

    scanner = UltraFastScanner(
        target=target,
        ports=range(start_port, end_port + 1),
        timeout=0.2,
        workers=300  # REDUCIDO para Raspberry
    )
    await scanner.run()

if __name__ == "__main__":
    asyncio.run(main())
