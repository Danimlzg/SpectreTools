#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MOBILE ANALYZER v2.0 - TANQUE EDITION
APK/IPA detection · Permission analysis · Mobile endpoints · App config
Con detección de archivos móviles expuestos
"""

import asyncio
import re
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional

try:
    from http_client import HTTPClient
except ImportError:
    class HTTPClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def get(self, url): return None
        async def head(self, url): return None

class MobileAnalyzer:
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.parsed = urlparse(target)
        self.domain = self.parsed.netloc
        self.client = None
        self.findings = []
        
        # APK paths
        self.apk_paths = [
            '/app.apk', '/mobile.apk', '/android.apk', '/app-debug.apk',
            '/app-release.apk', '/app-unsigned.apk', '/app-signed.apk',
            '/download/app.apk', '/apk/app.apk', '/android/app.apk',
            '/app/app.apk', '/android/app-debug.apk', '/android/app-release.apk',
            '/app-debug.apk', '/app-release-unsigned.apk', '/app-prod.apk',
            '/mobile/app.apk', '/android-debug.apk', '/android-release.apk',
            '/app.apk?', '/app.apk.zip', '/app.apk.gz',
        ]
        
        # IPA paths
        self.ipa_paths = [
            '/app.ipa', '/ios.ipa', '/iphone.ipa', '/app-store.ipa',
            '/download/app.ipa', '/ios/app.ipa', '/iphone/app.ipa',
            '/ios/app.ipa', '/ios-release.ipa', '/ios-debug.ipa',
            '/mobile.ipa', '/ios.ipa?', '/app.ipa.zip',
        ]
        
        # AndroidManifest.xml paths (expuesto)
        self.manifest_paths = [
            '/AndroidManifest.xml', '/manifest.xml', '/android-manifest.xml',
            '/app/AndroidManifest.xml', '/android/AndroidManifest.xml',
            '/apk/AndroidManifest.xml', '/META-INF/MANIFEST.MF',
        ]
        
        # iOS plist paths
        self.plist_paths = [
            '/Info.plist', '/app/Info.plist', '/ios/Info.plist',
            '/Payload/*.app/Info.plist', '/export.plist',
        ]
        
        # Permisos peligrosos Android
        self.dangerous_android = [
            'CAMERA', 'RECORD_AUDIO', 'READ_CONTACTS', 'ACCESS_FINE_LOCATION',
            'ACCESS_COARSE_LOCATION', 'READ_SMS', 'SEND_SMS', 'CALL_PHONE',
            'READ_CALL_LOG', 'WRITE_CALL_LOG', 'ADD_VOICEMAIL', 'USE_SIP',
            'BODY_SENSORS', 'ACTIVITY_RECOGNITION', 'READ_EXTERNAL_STORAGE',
            'WRITE_EXTERNAL_STORAGE', 'INSTALL_PACKAGES', 'DELETE_PACKAGES',
            'SYSTEM_ALERT_WINDOW', 'WRITE_SETTINGS', 'GET_ACCOUNTS',
        ]
        
        # Permisos peligrosos iOS
        self.dangerous_ios = [
            'NSCameraUsageDescription', 'NSMicrophoneUsageDescription',
            'NSPhotoLibraryUsageDescription', 'NSLocationWhenInUseUsageDescription',
            'NSLocationAlwaysUsageDescription', 'NSContactsUsageDescription',
            'NSCalendarsUsageDescription', 'NSRemindersUsageDescription',
            'NSBluetoothAlwaysUsageDescription', 'NSAppleMusicUsageDescription',
            'NSFaceIDUsageDescription', 'NSMotionUsageDescription',
            'NSHealthShareUsageDescription', 'NSHomeKitUsageDescription',
        ]
        
        # Mobile API endpoints
        self.mobile_endpoints = [
            '/api/mobile', '/api/android', '/api/ios', '/mobile/api',
            '/v1/mobile', '/v2/mobile', '/app/api', '/app/version',
            '/api/version', '/api/ping', '/api/health', '/api/status',
            '/mobile/version', '/android/version', '/ios/version',
            '/app/config', '/mobile/config', '/android/config', '/ios/config',
        ]
        
    async def setup(self):
        """Inicializa cliente HTTP"""
        self.client = HTTPClient(timeout=15, max_retries=2)
        
    async def check_file(self, path: str, file_type: str) -> Optional[Dict]:
        """Verifica si un archivo existe"""
        url = urljoin(self.target, path)
        
        try:
            # HEAD request primero
            resp = await self.client.head(url)
            
            if resp and resp.status == 200:
                content_type = resp.headers.get('content-type', '')
                content_length = resp.headers.get('content-length', 'unknown')
                
                finding = {
                    'type': f'{file_type}_FOUND',
                    'url': url,
                    'content_type': content_type,
                    'size': content_length,
                    'severity': 'ALTO' if 'apk' in file_type.lower() or 'ipa' in file_type.lower() else 'MEDIO'
                }
                
                # Para archivos pequeños, intentar GET y analizar
                if content_length != 'unknown' and int(str(content_length)) < 1000000:
                    get_resp = await self.client.get(url)
                    if get_resp:
                        content = await get_resp.text()
                        finding['preview'] = content[:500]
                        
                return finding
                
        except:
            pass
        return None
        
    def analyze_manifest(self, content: str) -> List[Dict]:
        """Analiza AndroidManifest.xml en busca de permisos"""
        findings = []
        
        for perm in self.dangerous_android:
            if perm in content:
                findings.append({
                    'type': 'DANGEROUS_PERMISSION',
                    'permission': perm,
                    'platform': 'Android',
                    'severity': 'MEDIO'
                })
                
        return findings
        
    def analyze_plist(self, content: str) -> List[Dict]:
        """Analiza Info.plist en busca de permisos"""
        findings = []
        
        for perm in self.dangerous_ios:
            if perm in content:
                findings.append({
                    'type': 'DANGEROUS_PERMISSION',
                    'permission': perm,
                    'platform': 'iOS',
                    'severity': 'MEDIO'
                })
                
        return findings
        
    async def scan(self):
        """Ejecuta análisis móvil"""
        print(f"\n📱 MOBILE ANALYZER v2.0 TANQUE - {self.target}")
        print("=" * 70)
        
        await self.setup()
        
        try:
            # 1. Buscar APKs
            print("[*] Buscando archivos APK...")
            for path in self.apk_paths:
                result = await self.check_file(path, 'APK')
                if result:
                    self.findings.append(result)
                    print(f"   [📱] APK encontrado: {result['url']}")
                    
            # 2. Buscar IPAs
            print("\n[*] Buscando archivos IPA...")
            for path in self.ipa_paths:
                result = await self.check_file(path, 'IPA')
                if result:
                    self.findings.append(result)
                    print(f"   [📱] IPA encontrado: {result['url']}")
                    
            # 3. Buscar manifests
            print("\n[*] Buscando AndroidManifest.xml...")
            for path in self.manifest_paths:
                result = await self.check_file(path, 'MANIFEST')
                if result and result.get('preview'):
                    perm_findings = self.analyze_manifest(result['preview'])
                    self.findings.extend(perm_findings)
                    print(f"   [📄] Manifest encontrado: {result['url']}")
                    for p in perm_findings[:3]:
                        print(f"        ↳ Permiso: {p['permission']}")
                        
            # 4. Buscar plists
            print("\n[*] Buscando Info.plist...")
            for path in self.plist_paths:
                result = await self.check_file(path, 'PLIST')
                if result and result.get('preview'):
                    perm_findings = self.analyze_plist(result['preview'])
                    self.findings.extend(perm_findings)
                    print(f"   [📄] Plist encontrado: {result['url']}")
                    
            # 5. Buscar endpoints móviles
            print("\n[*] Buscando endpoints móviles...")
            headers = {
                'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9;)',
                'X-Platform': 'Android',
                'X-App-Version': '1.0.0'
            }
            
            for path in self.mobile_endpoints:
                url = urljoin(self.target, path)
                try:
                    resp = await self.client.get(url, headers=headers)
                    if resp and resp.status == 200:
                        self.findings.append({
                            'type': 'MOBILE_ENDPOINT',
                            'url': url,
                            'status': resp.status,
                            'severity': 'INFO'
                        })
                        print(f"   [[INFO]] Endpoint móvil: {url}")
                except:
                    pass
                    
            # Resumen
            print("\n" + "="*70)
            print("📊 RESULTADOS ANÁLISIS MÓVIL")
            print("="*70)
            
            if self.findings:
                apks = [f for f in self.findings if 'APK_FOUND' in f['type']]
                ipas = [f for f in self.findings if 'IPA_FOUND' in f['type']]
                perms = [f for f in self.findings if f['type'] == 'DANGEROUS_PERMISSION']
                endpoints = [f for f in self.findings if f['type'] == 'MOBILE_ENDPOINT']
                
                if apks:
                    print(f"\n📦 APKs: {len(apks)}")
                if ipas:
                    print(f"\n📦 IPAs: {len(ipas)}")
                if perms:
                    print(f"\n[SECURE] Permisos peligrosos: {len(perms)}")
                if endpoints:
                    print(f"\n[WEB] Endpoints móviles: {len(endpoints)}")
                    
                print(f"\n[OK] TOTAL: {len(self.findings)}")
            else:
                print("\n[OK] No se encontraron componentes móviles")
                
        finally:
            if self.client:
                await self.client.close()
                
        return self.findings

async def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 mobile_analyzer.py <URL>")
        sys.exit(1)
        
    analyzer = MobileAnalyzer(sys.argv[1])
    await analyzer.scan()

if __name__ == "__main__":
    asyncio.run(main())
