import os, re, time, socket, requests, subprocess, json, threading, queue, random, base64, asyncio
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify
from playwright.sync_api import sync_playwright
import warnings
warnings.filterwarnings('ignore')

# ============================================
# IMPORTAR HERRAMIENTAS PROPIAS
# ============================================
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), 'tools'))

from smart_fuzzer import SmartFuzzer
from fast_port_scanner import AsyncPortScanner
from ultra_fast_scanner import UltraFastScanner
from waf_bypasser import WAFBypasser
from ultra_dns_enum import UltraDNSEnum
from vuln_scanner import VulnScanner

app = Flask(__name__)

# ============================================
# CONFIGURACIÓN
# ============================================
MAX_CONCURRENT_TOOLS = 2
tool_semaphore = threading.Semaphore(MAX_CONCURRENT_TOOLS)
task_results = {}
task_progress = {}
task_screenshots = {}

# Patrones de búsqueda
TELEGRAM_PATTERNS = [
    r't\.me/([a-zA-Z0-9_]+)',
    r'telegram\.org/([a-zA-Z0-9_]+)',
    r'@([a-zA-Z0-9_]{5,})',
    r'bot[0-9]+:[\w-]+',
    r'api\.telegram\.org/bot([0-9]+:[\w-]+)'
]

EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
API_KEY_PATTERNS = [
    r'api[_-]?key[\s]*[:=][\s]*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
    r'token[\s]*[:=][\s]*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
    r'secret[\s]*[:=][\s]*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
    r'AKIA[0-9A-Z]{16}',
    r'sk_live_[0-9a-zA-Z]{24}',
    r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}'
]

# ============================================
# EJECUTOR SEGURO (SOLO PARA NUESTRAS HERRAMIENTAS)
# ============================================
def run_cmd_safe(cmd_list, timeout=240):
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
        return result.stdout or result.stderr
    except subprocess.TimeoutExpired:
        return f"⏱️ Timeout después de {timeout}s"
    except Exception as e:
        return f"❌ Error: {str(e)}"

# ============================================
# DETECTOR DE WAF
# ============================================
def detect_waf(url):
    try:
        r = requests.get(url, timeout=5, verify=False)
        headers = str(r.headers).lower()

        waf_signatures = {
            'cloudflare': ['cloudflare', '__cfduid'],
            'vercel': ['vercel', 'x-vercel'],
            'aws': ['x-amz', 'aws'],
            'incapsula': ['incapsula', 'x-iinfo'],
            'sucuri': ['sucuri', 'x-sucuri'],
            'akamai': ['akamai', 'x-akamai'],
            'f5': ['bigip', 'f5'],
            'imperva': ['imperva', 'x-cdn']
        }

        for waf, sigs in waf_signatures.items():
            if any(sig in headers for sig in sigs):
                return waf

        server = r.headers.get('Server', '').lower()
        for waf, sigs in waf_signatures.items():
            if any(sig in server for sig in sigs):
                return waf

        return None
    except:
        return None

# ============================================
# EXTRACTOR DE INFO SENSIBLE
# ============================================
def extract_sensitive_info(text, url):
    findings = []

    for pattern in TELEGRAM_PATTERNS:
        matches = re.findall(pattern, text, re.I)
        for match in matches[:5]:
            findings.append(f"📱 TELEGRAM: {match}")

    emails = re.findall(EMAIL_PATTERN, text)
    for email in list(set(emails))[:10]:
        if not any(ignore in email for ignore in ['.png', '.jpg', '.css', '.js']):
            findings.append(f"📧 EMAIL: {email}")

    for pattern in API_KEY_PATTERNS:
        matches = re.findall(pattern, text, re.I)
        for key in matches[:5]:
            findings.append(f"🔑 KEY: {key[:30]}...")

    callbacks = re.findall(r'https?://[^\s\'"]+\.(php|asp|jsp|py)', text)
    for cb in list(set(callbacks))[:5]:
        findings.append(f"📡 CALLBACK: {cb}")

    return findings

# ============================================
# BYPASS WAF USANDO IP DIRECTA
# ============================================
def bypass_with_origin_ip(origin_ip, original_domain, paths):
    results = []

    headers_list = [
        {"Host": original_domain},
        {"Host": original_domain, "X-Forwarded-For": "127.0.0.1"},
        {"Host": original_domain, "X-Original-URL": "/"},
        {"Host": original_domain, "X-Rewrite-URL": "/"},
        {"Host": original_domain, "X-Forwarded-Host": original_domain},
        {"Host": original_domain, "CF-Connecting-IP": "127.0.0.1"},
        {"Host": original_domain, "True-Client-IP": "127.0.0.1"},
        {"Host": original_domain, "X-Real-IP": "127.0.0.1"},
    ]

    test_paths = paths[:10] if paths else [
        '/', '/admin', '/.env', '/api/v1', '/login',
        '/wp-admin', '/backup.zip', '/config.php'
    ]

    for path in test_paths:
        for headers in headers_list:
            try:
                url = f"http://{origin_ip}/{path.lstrip('/')}"
                r = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)

                if r.status_code == 200:
                    results.append(f"✅ BYPASS {url} con {headers} → {r.status_code}")
                    if len(r.text) < 500:
                        results.append(f"   📄 Preview: {r.text[:100]}...")
                    break
                elif r.status_code in [401, 403]:
                    results.append(f"🔐 {r.status_code} {url} (existe pero bloquea)")
                elif r.status_code in [301, 302]:
                    loc = r.headers.get('Location', '')
                    results.append(f"🔄 Redirect {url} → {loc[:50]}")
            except Exception as e:
                continue

    for path in test_paths:
        for headers in headers_list:
            try:
                url = f"https://{origin_ip}/{path.lstrip('/')}"
                r = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)

                if r.status_code == 200:
                    results.append(f"✅ BYPASS HTTPS {url} → {r.status_code}")
                    break
                elif r.status_code in [401, 403]:
                    results.append(f"🔐 {r.status_code} HTTPS {url}")
            except:
                continue

    return results

# ============================================
# WORKER DE ATAQUE COMPLETO (SOLO HERRAMIENTAS PROPIAS)
# ============================================
def attack_worker(task_id, url):
    task_progress[task_id] = "Iniciando ataque masivo..."
    results = {
        'task_id': task_id,
        'url': url,
        'domain': '',
        'ip': '',
        'waf': None,
        'finds': [],
        'endpoints': [],
        'sensitive': [],
        'telegram': [],
        'emails': [],
        'keys': [],
        'smart_fuzz': [],
        'ultra_dns': [],
        'waf_bypass': [],
        'vuln_scanner': [],
        'ultra_scan': [],
        'error': None
    }

    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        domain = parsed.netloc
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        results['domain'] = domain

        # ============================================
        # FASE 0: RECONOCIMIENTO VISUAL
        # ============================================
        task_progress[task_id] = "Fase 0: Capturando pantalla..."
        all_text = ""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
            page = browser.new_page()

            requests_captured = []
            page.on("request", lambda req: requests_captured.append(req.url))

            page.goto(base_url, timeout=60000, wait_until='networkidle')
            screenshot_bytes = page.screenshot()
            task_screenshots[task_id] = base64.b64encode(screenshot_bytes).decode('utf-8')

            page_text = page.content()
            all_text += page_text

            for req_url in requests_captured[:30]:
                if any(x in req_url for x in ['.php', '/api/', 'v1', 'v2', 'login', 'auth', 'admin', 'graphql', 'wp-']):
                    results['endpoints'].append(req_url)

            browser.close()

        # Extraer info sensible
        sensitive = extract_sensitive_info(all_text, base_url)
        results['sensitive'] = sensitive

        for item in sensitive:
            if 'TELEGRAM' in item:
                results['telegram'].append(item)
            elif 'EMAIL' in item:
                results['emails'].append(item)
            elif 'KEY' in item or 'TOKEN' in item:
                results['keys'].append(item)
            else:
                results['finds'].append(item)

        # Resolver IP
        try:
            results['ip'] = socket.gethostbyname(domain)
        except:
            results['ip'] = "No resuelta"

        # Detectar WAF
        results['waf'] = detect_waf(base_url)

        # ============================================
        # HERRAMIENTAS PROPIAS (ULTRA-RÁPIDAS)
        # ============================================

        # 1. SMART FUZZER
        task_progress[task_id] = "⚡ Ejecutando SmartFuzzer (anomalías)..."
        try:
            fuzzer = SmartFuzzer(base_url)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            fuzz_results = loop.run_until_complete(fuzzer.run())
            results['smart_fuzz'] = fuzz_results
        except Exception as e:
            results['smart_fuzz'] = f"Error: {e}"

        # 2. ULTRA DNS ENUM
        task_progress[task_id] = "⚡ Ejecutando UltraDNSEnum (ultra-rápido)..."
        try:
            ultra_dns = UltraDNSEnum(domain, workers=200)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            dns_ultra_results = loop.run_until_complete(ultra_dns.run())
            results['ultra_dns'] = dns_ultra_results
        except Exception as e:
            results['ultra_dns'] = f"Error: {e}"

        # 3. WAF BYPASSER
        task_progress[task_id] = "⚡ Ejecutando WAF Bypasser..."
        try:
            waf = WAFBypasser(base_url)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            waf_type = loop.run_until_complete(waf.detect())
            if waf_type:
                results['waf_detected'] = waf_type
                bypass_results = loop.run_until_complete(waf.bypass())
                results['waf_bypass'] = bypass_results
        except Exception as e:
            results['waf_bypass'] = f"Error: {e}"

        # 4. VULN SCANNER
        task_progress[task_id] = "⚡ Ejecutando Vuln Scanner..."
        try:
            vuln = VulnScanner(base_url)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            vuln_results = loop.run_until_complete(vuln.run())
            results['vuln_scanner'] = vuln_results
        except Exception as e:
            results['vuln_scanner'] = f"Error: {e}"

        # 5. ULTRA FAST SCANNER (escaneo de puertos) - WORKERS REDUCIDOS A 300
        task_progress[task_id] = "⚡ Ejecutando UltraFastScanner (puertos)..."
        try:
            if results['ip'] and results['ip'] != "No resuelta":
                ultra = UltraFastScanner(
                    target=results['ip'],
                    ports=range(1, 10001),
                    timeout=0.2,
                    workers=300  # REDUCIDO para evitar crash
                )
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                ultra_results = loop.run_until_complete(ultra.run())
                results['ultra_scan'] = ultra_results
        except Exception as e:
            results['ultra_scan'] = f"Error: {e}"

        # 6. BYPASS CON IP DIRECTA (si tenemos IP y WAF)
        if results['ip'] and results['ip'] != "No resuelta" and results['waf']:
            task_progress[task_id] = f"Fase 6: Bypass con IP directa ({results['ip']})..."
            interesting_paths = []
            if results['smart_fuzz'] and isinstance(results['smart_fuzz'], list):
                for item in results['smart_fuzz']:
                    if 'path' in item:
                        interesting_paths.append(item['path'])

            bypass_results = bypass_with_origin_ip(results['ip'], domain, interesting_paths)
            if bypass_results:
                results['finds'].extend(bypass_results)
                results['bypass_ip'] = bypass_results

        task_progress[task_id] = "✅ ATAQUE COMPLETADO"
        task_results[task_id] = results

    except Exception as e:
        results['error'] = str(e)
        task_results[task_id] = results
        task_progress[task_id] = f"❌ Error: {str(e)}"

# ============================================
# RUTAS
# ============================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/attack', methods=['POST'])
def attack():
    target = request.json.get('url')
    task_id = f"task_{int(time.time())}_{random.randint(1000,9999)}"
    threading.Thread(target=attack_worker, args=(task_id, target)).start()
    return jsonify({"status": "accepted", "task_id": task_id})

@app.route('/status/<task_id>', methods=['GET'])
def task_status(task_id):
    if task_id in task_results:
        result = task_results.pop(task_id)
        screenshot = task_screenshots.pop(task_id, None)
        return jsonify({"status": "completed", "data": result, "screenshot": screenshot})
    elif task_id in task_progress:
        return jsonify({"status": "running", "progress": task_progress[task_id]})
    return jsonify({"status": "not_found"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
