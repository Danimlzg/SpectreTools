#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ULTRA FAST SCANNER v2.0 - TANQUE EDITION
Escaneo de puertos masivo · Style masscan · Optimizado para Raspberry Pi
Con detección de servicios y banners
"""

import asyncio
import socket
from datetime import datetime
from typing import List, Optional

class UltraFastScanner:
    def __init__(self, target: str, start_port: int = 1, end_port: int = 10000, 
                 timeout: float = 0.2, workers: int = 500):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.workers = workers
        self.open_ports = []
        self.service_versions = {}
        
        # Servicios comunes por puerto
        self.common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB',
        }
        
    async def scan_port(self, port: int) -> Optional[int]:
        """Escanea un puerto individual"""
        try:
            conn = asyncio.open_connection(self.target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return port
        except:
            return None
            
    async def grab_banner(self, port: int) -> Optional[str]:
        """Intenta obtener banner del servicio"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port), 
                timeout=2
            )
            
            # Enviar petición genérica
            if port in [80, 8080, 8443]:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP banner viene al conectar
            elif port == 25:
                pass  # SMTP banner viene al conectar
                
            banner = await reader.read(1024)
            writer.close()
            await writer.wait_closed()
            
            return banner.decode('utf-8', errors='ignore').strip()
        except:
            return None
            
    async def worker(self, port: int, semaphore: asyncio.Semaphore):
        """Worker con semáforo"""
        async with semaphore:
            result = await self.scan_port(port)
            if result:
                service = self.common_services.get(port, 'Unknown')
                print(f"   🔓 Puerto {port} abierto - {service}")
                
                # Intentar banner
                banner = await self.grab_banner(port)
                if banner:
                    print(f"      Banner: {banner[:100]}")
                    self.service_versions[port] = banner
                    
                self.open_ports.append(port)
                
    async def scan(self):
        """Ejecuta escaneo masivo"""
        print(f"\n⚡ ULTRA FAST SCANNER v2.0 TANQUE")
        print("=" * 70)
        print(f"[*] Objetivo: {self.target}")
        print(f"[*] Puertos: {self.start_port}-{self.end_port}")
        print(f"[*] Workers: {self.workers}")
        print(f"[*] Timeout: {self.timeout}s")
        print("-" * 70)
        
        start_time = datetime.now()
        semaphore = asyncio.Semaphore(self.workers)
        
        # Crear tareas
        tasks = []
        for port in range(self.start_port, self.end_port + 1):
            tasks.append(self.worker(port, semaphore))
            
        # Ejecutar en batches
        batch_size = 2000
        total = len(tasks)
        
        for i in range(0, total, batch_size):
            batch = tasks[i:i+batch_size]
            await asyncio.gather(*batch)
            
            progress = (i + len(batch)) / total * 100
            print(f"\n   Progreso: {min(i+batch_size, total)}/{total} ({progress:.1f}%)")
            
        elapsed = (datetime.now() - start_time).total_seconds()
        
        # Resumen
        print("\n" + "="*70)
        print("📊 RESULTADOS ESCANEO")
        print("="*70)
        
        if self.open_ports:
            print(f"\n[OK] Puertos abiertos: {len(self.open_ports)}")
            for port in sorted(self.open_ports):
                service = self.common_services.get(port, 'Unknown')
                banner = self.service_versions.get(port, '')
                print(f"   • {port}/tcp - {service}")
                if banner:
                    print(f"     Banner: {banner[:100]}")
        else:
            print("\n❌ No se encontraron puertos abiertos")
            
        print(f"\n⏱️  Tiempo total: {elapsed:.1f}s")
        
        # Guardar resultados
        if self.open_ports:
            with open(f"ports_{self.target}.txt", 'w') as f:
                for port in sorted(self.open_ports):
                    f.write(f"{port}\n")
            print(f"\n💾 Puertos guardados en ports_{self.target}.txt")
            
        return sorted(self.open_ports)

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 ultra_fast_scanner.py <IP> [puerto_inicio] [puerto_fin] [workers]")
        print("Ejemplo: python3 ultra_fast_scanner.py 192.168.1.1 1 10000 500")
        sys.exit(1)
        
    target = sys.argv[1]
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end = int(sys.argv[3]) if len(sys.argv) > 3 else 10000
    workers = int(sys.argv[4]) if len(sys.argv) > 4 else 500
    
    scanner = UltraFastScanner(target, start, end, workers=workers)
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
