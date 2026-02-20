# SPECTRE ENTERPRISE v7.0Suite de auditoría de seguridad con **50+ módulos** para bug bounty y pentesting profesional.

Características:

50+ módulos especializados**: SQLi, XSS, Command Injection, SSRF, IDOR, Open Redirect, CRLF, Host Header, GraphQL, JWT, CORS, y más
Escaneo completo o por módulos**: Usa `spectre.py` para todo o cada módulo por separado
Anti-falsos positivos**: Detecta páginas de login y redirecciones automáticamente
Informes profesionales**: Genera HTML, JSON y TXT con hallazgos reales
Respetuoso**: Configurable para respetar rate limits (5 req/s)
Multiplataforma**: Probado en Kali Linux, Raspberry Pi, Ubuntu
Instalación rápida

bash
# Clonar repositorio
git clone https://github.com/Danimlzg/spectretools.git
cd spectretools

# Instalar dependencias
pip install -r requirements.txt

# Opcional: para endpoint_harvester (requiere navegador)
playwright install chromium
