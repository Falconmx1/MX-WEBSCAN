# 🔥 MX-WEBSCAN - Escáner de Seguridad Web Automatizado

[![GitHub license](https://img.shields.io/github/license/Falconmx1/MX-WEBSCAN)](https://github.com/Falconmx1/MX-WEBSCAN/blob/main/LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**MX-WEBSCAN** es una herramienta ofensiva diseñada para identificar vulnerabilidades web del **OWASP Top 10** en entornos hispanohablantes. Desarrollada por **Falconmx1** 🇲🇽 para la comunidad de ciberseguridad.

![MX-WEBSCAN Demo](https://via.placeholder.com/800x400?text=MX-WEBSCAN+Demo)

## ⚡ Características Principales

- 🎯 **Detección automática** de SQLi, XSS, LFI y SSRF
- 🚀 **Multi-hilo** para escaneos rápidos
- 📊 **Reportes detallados** en TXT y JSON
- 🔄 **Soporte de proxies** y headers personalizados
- 🎨 **Interfaz colorida** y fácil de usar
- 📝 **Evidencia técnica** de cada vulnerabilidad

## 🛠️ Instalación

```bash
# Clonar el repositorio
git clone https://github.com/Falconmx1/MX-WEBSCAN.git
cd MX-WEBSCAN

# Instalar dependencias
pip install -r requirements.txt

# Dar permisos de ejecución (Linux/Mac)
chmod +x mx-webscan.py

🚀 Uso
Escaneo básico
python mx-webscan.py -u "http://testphp.vulnweb.com/artists.php?artist=1"

Con proxy (Burp Suite para análisis manual)
python mx-webscan.py -u "http://target.com/page.php?id=1" --proxy http://127.0.0.1:8080

Headers personalizados (autenticación)
python mx-webscan.py -u "http://target.com/api?user=1" --header "Authorization: Bearer token123"

Timeout personalizado
python mx-webscan.py -u "http://target.com/search?q=test" --timeout 10
