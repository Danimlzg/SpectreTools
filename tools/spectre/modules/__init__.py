import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulos de Spectre Enterprise
"""

__version__ = '6.0'
__author__ = 'Dani'

# Exportar módulos principales
from . import bypass_403
from . import cloudflare_bypass
from . import endpoint_harvester
from . import header_rotator
from . import origin_ip_finder
from . import proxy_rotator
from . import simple_dns_enum
from . import smart_fuzzer
from . import subdomain_bruteforcer
from . import technology_detector
from . import ultra_fast_scanner
from . import url_extractor
from . import version_detector
from . import vuln_scanner_optimized
from . import waf_tools
from . import library_scanner
from . import spectre_scanner

# Lista de módulos disponibles
__all__ = [
    'bypass_403',
    'cloudflare_bypass',
    'endpoint_harvester',
    'header_rotator',
    'origin_ip_finder',
    'proxy_rotator',
    'simple_dns_enum',
    'smart_fuzzer',
    'subdomain_bruteforcer',
    'technology_detector',
    'ultra_fast_scanner',
    'url_extractor',
    'version_detector',
    'vuln_scanner_optimized',
    'waf_tools',
    'library_scanner',
    'spectre_scanner'
]
