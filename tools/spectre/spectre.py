#!/usr/bin/env python3
"""
SPECTRE ENTERPRISE v7.0 - CORE TANQUE
Gestión de módulos · Concurrencia controlada · Logging · Dependencias
"""

import asyncio
import sys
import os
import json
import yaml
import argparse
import time
import importlib.util
import socket
import inspect
import logging
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Optional
from colorama import init, Fore, Style, Back
import traceback

# Importar HTTPClient TANQUE
try:
    from modules.http_client import HTTPClient
except ImportError:
    # Si no está en modules, buscar en el mismo directorio
    sys.path.insert(0, os.path.dirname(__file__))
    from http_client import HTTPClient

init(autoreset=True)

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('spectre_debug.log'),
        logging.StreamHandler() if os.getenv('DEBUG') else logging.NullHandler()
    ]
)
logger = logging.getLogger('spectre')

# ============ CONFIGURACIÓN ============
def load_config():
    """Carga configuración con valores por defecto"""
    default_config = {
        'empresa': 'SPECTRE OPS',
        'timeout': 30,
        'concurrency': 10,  # Máximo 10 módulos en paralelo
        'debug': False,
        'modules': {
            'enabled': [],  # Vacío = todos
            'disabled': [],
            'timeout': 300  # Timeout por módulo en segundos
        },
        'http': {
            'timeout': 30,
            'retries': 3,
            'verify_ssl': False
        }
    }

    try:
        if os.path.exists('config.yaml'):
            with open('config.yaml', 'r') as f:
                user_config = yaml.safe_load(f) or {}
                # Merge con defaults
                for key, value in user_config.items():
                    if key in default_config and isinstance(value, dict):
                        default_config[key].update(value)
                    else:
                        default_config[key] = value
    except Exception as e:
        logger.warning(f"Error cargando config.yaml: {e}")

    return default_config

CONFIG = load_config()

# ============ LOGGER DE HALLAZGOS ============
class FindingsLogger:
    """Logger especializado para hallazgos de seguridad"""
    def __init__(self, target):
        self.target = target
        self.domain = urlparse(target).netloc
        self.ip = None
        self.start_time = time.time()
        self.findings = []
        self.results = {
            'metadata': {
                'target': target,
                'dominio': self.domain,
                'timestamp': str(datetime.now()),
                'version': '7.0',
                'config': CONFIG
            },
            'vulnerabilidades': [],
            'errores': []
        }

    def resolve_ip(self):
        """Resuelve IP del objetivo"""
        try:
            self.ip = socket.gethostbyname(self.domain)
            self.results['metadata']['ip'] = self.ip
            print(f"{Fore.GREEN}[+] IP Objetivo: {self.ip}{Style.RESET_ALL}")
            return self.ip
        except Exception as e:
            logger.error(f"Fallo al resolver IP para {self.domain}: {e}")
            print(f"{Fore.RED}[-] Fallo al resolver IP para {self.domain}{Style.RESET_ALL}")
            return None

    def finding(self, tipo: str, severidad: str, mensaje: str, detalles: dict = None):
        """Registra un hallazgo"""
        hallazgo = {
            'tipo': tipo,
            'severidad': severidad.upper(),
            'mensaje': mensaje,
            'detalles': detalles or {},
            'timestamp': datetime.now().isoformat(),
            'tiempo_ejecucion': round(time.time() - self.start_time, 2)
        }

        self.findings.append(hallazgo)
        self.results['vulnerabilidades'].append(hallazgo)

        # Colores para consola
        colores = {
            'CRITICO': Fore.RED + Back.WHITE + Style.BRIGHT,
            'ALTO': Fore.RED + Style.BRIGHT,
            'MEDIO': Fore.YELLOW + Style.BRIGHT,
            'BAJO': Fore.BLUE + Style.BRIGHT,
            'INFO': Fore.CYAN
        }
        color = colores.get(severidad.upper(), Fore.WHITE)
        print(f"{color}[{severidad.upper()}] {tipo}: {mensaje}{Style.RESET_ALL}")

        # Loggear también
        logger.info(f"HALLAZGO [{severidad}] {tipo}: {mensaje}")

    def error(self, modulo: str, error: str, trace: str = None):
        """Registra un error de módulo"""
        error_entry = {
            'modulo': modulo,
            'error': str(error),
            'traceback': trace,
            'timestamp': datetime.now().isoformat()
        }
        self.results['errores'].append(error_entry)
        logger.error(f"Error en {modulo}: {error}")

# ============ MOTOR SPECTRE TANQUE ============
class SpectreScanner:
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.log = FindingsLogger(self.target)
        self.domain = urlparse(self.target).netloc
        self.ip = self.log.resolve_ip()
        self.modules_dir = os.path.join(os.path.dirname(__file__), 'modules')
        self.semaphore = asyncio.Semaphore(CONFIG.get('concurrency', 10))
        self.http_client = None

    async def setup(self):
        """Inicializa cliente HTTP compartido"""
        self.http_client = HTTPClient(
            timeout=CONFIG['http']['timeout'],
            max_retries=CONFIG['http']['retries']
        )

    async def cleanup(self):
        """Limpia recursos"""
        if self.http_client:
            await self.http_client.close()

    def get_available_modules(self) -> List[str]:
        """Descubre módulos disponibles"""
        if not os.path.exists(self.modules_dir):
            logger.error(f"Directorio de módulos no encontrado: {self.modules_dir}")
            return []

        modules = []
        for f in os.listdir(self.modules_dir):
            if f.endswith('.py') and f != '__init__.py':
                module_name = f[:-3]
                # Filtrar por configuración
                enabled = CONFIG.get('modules', {}).get('enabled', [])
                disabled = CONFIG.get('modules', {}).get('disabled', [])

                if enabled and module_name not in enabled:
                    continue
                if module_name in disabled:
                    continue

                modules.append(module_name)

        return sorted(modules)

    def check_dependencies(self, module_name: str) -> bool:
        """Verifica dependencias del módulo"""
        # Dependencias conocidas por módulo
        dependencies = {
            'client_storage': ['playwright'],
            'endpoint_harvester': ['playwright', 'tldextract'],
            'subdomain_bruteforcer': ['aiodns'],
            'open_redirect': [],
            'crlf_injection': [],
            'host_header': [],
            'csrf_tester': [],
            'lfi_rfi': [],
        }

        needed = dependencies.get(module_name, [])
        missing = []

        for dep in needed:
            try:
                __import__(dep)
            except ImportError:
                missing.append(dep)

        if missing:
            logger.warning(f"Módulo {module_name} requiere: {missing}")
            print(f"{Fore.YELLOW}[!] {module_name} requiere: {', '.join(missing)}{Style.RESET_ALL}")
            return False

        return True

    def load_module_class(self, module_name: str):
        """Carga clase principal del módulo"""
        path = os.path.join(self.modules_dir, f"{module_name}.py")

        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            # Buscar clase definida en el módulo
            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if obj.__module__ == module_name:
                    logger.debug(f"Módulo {module_name} cargado: {name}")
                    return obj

            logger.warning(f"No se encontró clase en {module_name}")
            return None

        except Exception as e:
            logger.error(f"Error cargando {module_name}: {e}")
            return None

    async def run_module(self, name: str):
        """Ejecuta un módulo con control de concurrencia"""
        async with self.semaphore:
            module_start = time.time()
            logger.info(f"Iniciando módulo: {name}")

            try:
                # Verificar dependencias
                if not self.check_dependencies(name):
                    return

                # Cargar módulo
                cls = self.load_module_class(name)
                if not cls:
                    logger.error(f"No se pudo cargar {name}")
                    return

                # Determinar target (dominio o URL completa)
                use_domain = any(x in name for x in ['dns', 'cloud', 'subdomain', 'origin'])
                target_to_use = self.domain if use_domain else self.target

                # Instanciar
                instance = cls(target_to_use)

                # Inyectar http_client si el módulo lo soporta
                if hasattr(instance, 'set_http_client'):
                    await instance.set_http_client(self.http_client)
                elif hasattr(instance, 'client') and self.http_client:
                    instance.client = self.http_client

                # Buscar método de ejecución
                method_name = None
                for m in ['run', 'scan', 'detect', 'execute', 'scan_target']:
                    if hasattr(instance, m):
                        method_name = m
                        break

                if not method_name:
                    logger.warning(f"{name} no tiene método ejecutable")
                    return

                # Ejecutar con timeout
                func = getattr(instance, method_name)
                timeout = CONFIG.get('modules', {}).get('timeout', 300)

                try:
                    if asyncio.iscoroutinefunction(func):
                        result = await asyncio.wait_for(func(), timeout=timeout)
                    else:
                        result = await asyncio.wait_for(
                            asyncio.get_event_loop().run_in_executor(None, func),
                            timeout=timeout
                        )

                except asyncio.TimeoutError:
                    logger.error(f"Módulo {name} excedió timeout de {timeout}s")
                    self.log.error(name, f"Timeout después de {timeout}s")
                    return

                # Procesar resultados
                if result:
                    await self.process_results(name, result)

                elapsed = time.time() - module_start
                logger.info(f"Módulo {name} completado en {elapsed:.2f}s")

            except Exception as e:
                logger.error(f"Error en {name}: {traceback.format_exc()}")
                self.log.error(name, str(e), traceback.format_exc())

    async def process_results(self, module_name: str, result):
        """Procesa resultados de un módulo"""
        if isinstance(result, dict):
            # Si es dict con estructura
            for key, value in result.items():
                if key == 'findings' and isinstance(value, list):
                    for finding in value:
                        self.process_finding(module_name, finding)
                elif key in ['vulnerabilities', 'hallazgos']:
                    for finding in value:
                        self.process_finding(module_name, finding)

        elif isinstance(result, list):
            # Si es lista de hallazgos
            for finding in result:
                self.process_finding(module_name, finding)

        elif result:
            # Resultado simple
            self.log.finding(
                module_name.upper(),
                self._guess_severity(str(result)),
                str(result)[:200]
            )

    def process_finding(self, module: str, finding):
        """Procesa un hallazgo individual"""
        if isinstance(finding, dict):
            tipo = finding.get('type', finding.get('tipo', module))
            severidad = finding.get('severity', finding.get('severidad', 'MEDIO'))
            mensaje = finding.get('message', finding.get('mensaje', str(finding)))
            detalles = finding.get('details', finding.get('detalles', {}))

            self.log.finding(tipo, severidad, mensaje, detalles)
        else:
            self.log.finding(module, 'MEDIO', str(finding))

    def _guess_severity(self, text: str) -> str:
        """Adivina severidad por texto"""
        text_lower = text.lower()
        if any(x in text_lower for x in ['critical', 'vulnerable', 'exploit', 'bypass', 'open redirect', 'crlf', 'csrf', 'lfi', 'rfi']):
            return 'CRITICO'
        elif any(x in text_lower for x in ['high', 'leak', 'exposed', 'warning', 'host header']):
            return 'ALTO'
        elif any(x in text_lower for x in ['medium', 'info', 'found']):
            return 'MEDIO'
        return 'INFO'

    def generate_html_report(self, html_path: str):
        """Genera reporte HTML profesional sin emojis"""
        
        # Agrupar hallazgos por severidad
        por_severidad = {'CRITICO': [], 'ALTO': [], 'MEDIO': [], 'BAJO': [], 'INFO': []}
        for f in self.log.findings:
            sev = f['severidad']
            if sev in por_severidad:
                por_severidad[sev].append(f)
        
        # Construir HTML
        lines = []
        lines.append("<!DOCTYPE html>")
        lines.append("<html>")
        lines.append("<head>")
        lines.append("  <meta charset='UTF-8'>")
        lines.append(f"  <title>SPECTRE SCAN - {self.domain}</title>")
        lines.append("  <style>")
        lines.append("    body { font-family: 'Courier New', monospace; background: #f5f5f5; margin: 20px; }")
        lines.append("    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border: 1px solid #ccc; }")
        lines.append("    h1 { font-size: 20px; border-bottom: 2px solid #333; padding-bottom: 5px; }")
        lines.append("    h2 { font-size: 16px; margin-top: 20px; border-bottom: 1px solid #999; }")
        lines.append("    .critico { color: #c00; font-weight: bold; }")
        lines.append("    .alto { color: #f60; font-weight: bold; }")
        lines.append("    .medio { color: #fa0; }")
        lines.append("    .bajo { color: #00c; }")
        lines.append("    .info { color: #666; }")
        lines.append("    .finding { margin: 10px 0 10px 20px; }")
        lines.append("    .detail { margin-left: 40px; color: #333; font-size: 13px; }")
        lines.append("    .stats { margin-top: 30px; padding: 10px; background: #eee; }")
        lines.append("  </style>")
        lines.append("</head>")
        lines.append("<body>")
        lines.append("<div class='container'>")
        
        # Cabecera
        lines.append(f"<h1>SPECTRE SCAN REPORT - {self.domain}</h1>")
        lines.append(f"<p>Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        
        # Hallazgos por severidad (solo las que tengan algo)
        severidades = [
            ('CRITICO', 'critico'),
            ('ALTO', 'alto'),
            ('MEDIO', 'medio'),
            ('BAJO', 'bajo'),
            ('INFO', 'info')
        ]
        
        for sev, clase in severidades:
            if por_severidad[sev]:
                lines.append(f"<h2 class='{clase}'>{sev} ({len(por_severidad[sev])})</h2>")
                for f in por_severidad[sev]:
                    lines.append(f"<div class='finding'>• {f['tipo']}</div>")
                    lines.append(f"<div class='detail'>→ {f['mensaje']}</div>")
                    if f.get('detalles'):
                        lines.append(f"<div class='detail'>→ Detalles: {f['detalles']}</div>")
        
        # Estadísticas
        lines.append("<div class='stats'>")
        lines.append("<h2>ESTADÍSTICAS</h2>")
        lines.append(f"<div>• Módulos ejecutados: {len(self.get_available_modules())}</div>")
        lines.append(f"<div>• Hallazgos totales: {len(self.log.findings)}</div>")
        lines.append(f"<div>• Tiempo total: {round(time.time() - self.log.start_time, 2)} segundos</div>")
        lines.append(f"<div>• Errores: {len(self.log.results['errores'])}</div>")
        lines.append("</div>")
        
        lines.append("</div>")
        lines.append("</body>")
        lines.append("</html>")
        
        # Guardar
        with open(html_path, 'w') as f:
            f.write('\n'.join(lines))

    async def run(self):
        """Ejecuta escaneo completo"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.WHITE}SPECTRE ENTERPRISE v7.0 TANQUE")
        print(f"{Fore.WHITE}OBJETIVO: {self.target}")

        modules = self.get_available_modules()
        total = len(modules)

        print(f"{Fore.WHITE}MÓDULOS: {total}")
        print(f"{Fore.WHITE}CONCURRENCIA: {CONFIG.get('concurrency', 10)}")
        print(f"{Fore.CYAN}{'='*70}\n")

        await self.setup()

        try:
            # Ejecutar módulos con semáforo
            tasks = [self.run_module(m) for m in modules]
            await asyncio.gather(*tasks)

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Escaneo interrumpido por usuario{Style.RESET_ALL}")
        except Exception as e:
            logger.error(f"Error en escaneo: {traceback.format_exc()}")
        finally:
            await self.cleanup()

        # Guardar resultados
        await self.save_results()

        # Mostrar resumen
        self.print_summary()

    async def save_results(self):
        """Guarda resultados a archivo"""
        results_dir = os.path.join(os.path.dirname(__file__), 'results')
        os.makedirs(results_dir, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = f"{self.domain.replace('.', '_')}_{timestamp}"
        
        # JSON
        json_path = os.path.join(results_dir, f"scan_{base_filename}.json")
        with open(json_path, 'w') as f:
            json.dump(self.log.results, f, indent=2, default=str)

        # TXT
        txt_path = os.path.join(results_dir, f"hallazgos_{base_filename}.txt")
        with open(txt_path, 'w') as f:
            f.write(f"SPECTRE SCAN - {self.domain}\n")
            f.write("=" * 50 + "\n\n")
            for finding in self.log.findings:
                f.write(f"[{finding['severidad']}] {finding['tipo']}\n")
                f.write(f"  {finding['mensaje']}\n")
                if finding.get('detalles'):
                    f.write(f"  Detalles: {finding['detalles']}\n")
                f.write("\n")

        # HTML
        html_path = os.path.join(results_dir, f"reporte_{base_filename}.html")
        self.generate_html_report(html_path)

        print(f"\n{Fore.GREEN}[STATS] Informe JSON: {json_path}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[STATS] Hallazgos TXT: {txt_path}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[STATS] Reporte HTML: {html_path}{Style.RESET_ALL}")
        
        # Abrir HTML automáticamente (opcional)
        try:
            import webbrowser
            webbrowser.open(f"file://{os.path.abspath(html_path)}")
        except:
            pass

    def print_summary(self):
        """Muestra resumen final"""
        elapsed = time.time() - self.log.start_time

        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.GREEN}ESCANEO COMPLETADO")
        print(f"{Fore.CYAN}{'='*70}")

        print(f"\n{Fore.WHITE}⏱️  Duración: {elapsed:.2f}s")
        print(f"{Fore.WHITE}[STATS] Hallazgos totales: {len(self.log.findings)}")
        print(f"{Fore.WHITE}❌ Errores: {len(self.log.results['errores'])}")

        # Resumen por severidad
        if self.log.findings:
            by_severity = {}
            for f in self.log.findings:
                sev = f['severidad']
                by_severity[sev] = by_severity.get(sev, 0) + 1

            print(f"\n{Fore.WHITE}📈 Por severidad:")
            for sev in ['CRITICO', 'ALTO', 'MEDIO', 'BAJO', 'INFO']:
                if sev in by_severity:
                    color = Fore.RED if sev == 'CRITICO' else Fore.YELLOW if sev == 'ALTO' else Fore.WHITE
                    print(f"{color}   {sev}: {by_severity[sev]}{Style.RESET_ALL}")

            # Top hallazgos críticos
            criticos = [f for f in self.log.findings if f['severidad'] == 'CRITICO']
            if criticos:
                print(f"\n{Fore.RED}[CRITICO] HALLAZGOS CRÍTICOS:{Style.RESET_ALL}")
                for f in criticos[:5]:
                    print(f"   • {f['tipo']}: {f['mensaje'][:100]}")

        print(f"\n{Fore.GREEN}{'='*70}\n")

# ============ ENTRY POINT ============
async def main():
    parser = argparse.ArgumentParser(description='SPECTRE CORE v7.0 TANQUE')
    parser.add_argument('-t', '--target', help='URL objetivo')
    parser.add_argument('--debug', action='store_true', help='Modo debug')
    parser.add_argument('--concurrency', type=int, help='Máximo módulos en paralelo')
    parser.add_argument('--timeout', type=int, help='Timeout global')

    args = parser.parse_args()

    # Override config con args
    if args.debug:
        CONFIG['debug'] = True
        logging.getLogger().setLevel(logging.DEBUG)
    if args.concurrency:
        CONFIG['concurrency'] = args.concurrency
    if args.timeout:
        CONFIG['timeout'] = args.timeout

    if args.target:
        target = args.target if args.target.startswith('http') else f"https://{args.target}"
        scanner = SpectreScanner(target)
        await scanner.run()
    else:
        parser.print_help()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Escaneo interrumpido por usuario.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error fatal: {traceback.format_exc()}")
        print(f"\n{Fore.RED}[!] Error fatal: {e}{Style.RESET_ALL}")
        sys.exit(1)

