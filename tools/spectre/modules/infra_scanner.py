#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
INFRA SCANNER v1.0 - Cubre Containers, VMs, Hypervisors, DNS, IoT
"""

import aiohttp
import asyncio
import re
import sys
import socket
import subprocess
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional
try:
    from .http_client import get_session, DEFAULT_HEADERS, TIMEOUT
except ImportError:
    from http_client import get_session, DEFAULT_HEADERS, TIMEOUT

class InfraScanner:
    def __init__(self, target: str):
        self.target = target.lower()
        self.parsed = urlparse(target if '://' in target else f"http://{target}")
        self.domain = self.parsed.netloc or target
        self.findings = []
        
        # Endpoints de contenedores
        self.container_paths = [
            '/docker', '/containers', '/images', '/_ping',
            '/version', '/info', '/v1.41/containers/json',
            '/api/v1/containers', '/api/v1/images',
            '/k8s', '/kubernetes', '/api/v1/pods', '/apis/apps/v1',
            '/.kube/config', '/kubeconfig'
        ]
        
        # Headers de cloud providers
        self.cloud_headers = [
            'x-amz-', 'x-amzn-', 'x-aws-', 'x-azure-',
            'x-ms-', 'x-gcp-', 'x-google-', 'x-oracle-'
        ]
        
        # Servicios IoT comunes
        self.iot_paths = [
            '/mqtt', '/coap', '/amqp', '/stomp', '/iot',
            '/devices', '/things', '/sensors', '/actuators'
        ]

    async def detect_container_platform(self, session) -> List[Dict]:
        """Detecta plataformas de contenedores"""
        findings = []
        
        # Probar endpoints Docker
        for path in self.container_paths:
            url = urljoin(f"https://{self.domain}", path)
            try:
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        
                        # Docker
                        if 'Docker' in text or 'Api-Version' in resp.headers:
                            findings.append({
                                'type': 'DOCKER_API',
                                'url': url,
                                'severity': 'CRITICO'
                            })
                            print(f"   [[CRITICO]] Docker API expuesta: {url}")
                        
                        # Kubernetes
                        if 'kube' in text.lower() or 'kubernetes' in text.lower():
                            findings.append({
                                'type': 'KUBERNETES_API',
                                'url': url,
                                'severity': 'CRITICO'
                            })
                            print(f"   [[CRITICO]] Kubernetes API: {url}")
            except:
                pass
        
        return findings

    async def detect_cloud_provider(self, session) -> List[Dict]:
        """Detecta proveedor cloud por headers"""
        findings = []
        
        try:
            async with session.get(f"https://{self.domain}", timeout=10) as resp:
                for header in resp.headers:
                    header_lower = header.lower()
                    for cloud in self.cloud_headers:
                        if cloud in header_lower:
                            findings.append({
                                'type': 'CLOUD_PROVIDER',
                                'header': header,
                                'value': resp.headers[header],
                                'severity': 'INFO'
                            })
                            print(f"   [ℹ️] Cloud header: {header}")
        except:
            pass
        
        return findings

    async def detect_hypervisors(self) -> List[Dict]:
        """Detecta hypervisores por fingerprints"""
        findings = []
        
        # Intentar conexión a servicios comunes de hypervisores
        hypervisor_ports = [
            (443, 'ESXi'), (902, 'ESXi'), (903, 'ESXi'),
            (8006, 'Proxmox'), (8007, 'Proxmox'),
            (15672, 'XenServer'), (8080, 'XenServer'),
            (5000, 'vCenter'), (5001, 'vCenter')
        ]
        
        try:
            ip = socket.gethostbyname(self.domain)
            for port, hypervisor in hypervisor_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    findings.append({
                        'type': 'HYPERVISOR_PORT',
                        'port': port,
                        'service': hypervisor,
                        'severity': 'ALTO'
                    })
                    print(f"   [[WARN]] Puerto {port} ({hypervisor}) abierto")
                sock.close()
        except:
            pass
        
        return findings

    async def detect_iot_services(self, session) -> List[Dict]:
        """Detecta servicios IoT"""
        findings = []
        
        for path in self.iot_paths:
            url = urljoin(f"https://{self.domain}", path)
            try:
                async with session.get(url, timeout=5) as resp:
                    if resp.status != 404:
                        findings.append({
                            'type': 'IOT_ENDPOINT',
                            'url': url,
                            'status': resp.status,
                            'severity': 'MEDIO'
                        })
                        print(f"   [[INFO]] Posible IoT endpoint: {url}")
            except:
                pass
        
        return findings

    async def scan(self):
        """Ejecuta el escaneo de infraestructura"""
        print(f"\n🏗️  INFRA SCANNER v1.0 - {self.domain}")
        print("=" * 60)

        session = await get_session()
        
        try:
            # 1. Contenedores
            print("[*] Detectando plataformas de contenedores...")
            findings = await self.detect_container_platform(session)
            self.findings.extend(findings)
            
            # 2. Cloud providers
            print("\n[*] Detectando proveedor cloud...")
            findings = await self.detect_cloud_provider(session)
            self.findings.extend(findings)
            
            # 3. Hypervisores
            print("\n[*] Escaneando hypervisores...")
            findings = await self.detect_hypervisors()
            self.findings.extend(findings)
            
            # 4. IoT
            print("\n[*] Buscando servicios IoT...")
            findings = await self.detect_iot_services(session)
            self.findings.extend(findings)
            
            # Mostrar resultados
            print("\n" + "="*60)
            print("📊 RESULTADOS INFRAESTRUCTURA")
            print("="*60)
            
            if self.findings:
                criticos = [f for f in self.findings if f['severity'] == 'CRITICO']
                altos = [f for f in self.findings if f['severity'] == 'ALTO']
                
                if criticos:
                    print(f"\n[CRITICO] CRÍTICOS ({len(criticos)}):")
                    for f in criticos:
                        print(f"   • {f['type']}: {f.get('url', f.get('port', ''))}")
                
                if altos:
                    print(f"\n[WARN]  ALTOS ({len(altos)}):")
                    for f in altos:
                        print(f"   • {f['type']}: {f.get('service', '')} en puerto {f.get('port', '')}")
                
                print(f"\n[OK] Total hallazgos: {len(self.findings)}")
            else:
                print("\n   [OK] No se encontraron problemas de infraestructura")
        
        except Exception as e:
            print(f"   Error: {e}")
        finally:
            await session.close()
        
        return self.findings

async def main():
    if len(sys.argv) < 2:
        print("Uso: python3 infra_scanner.py <dominio>")
        sys.exit(1)

    scanner = InfraScanner(sys.argv[1])
    await scanner.scan()

if __name__ == "__main__":
    asyncio.run(main())
