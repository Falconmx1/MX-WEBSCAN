# 🔥 MX-WEBSCAN - Escáner de Seguridad Web Automatizado

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2FFalconmx1%2FMX-WEBSCAN&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=visitas&edge_flat=false)](https://hits.seeyoufarm.com)

**MX-WEBSCAN** es una herramienta ofensiva para pentesters y admins de seguridad, enfocada en detectar vulnerabilidades del **OWASP Top 10** en aplicaciones web. Desarrollada con ❤️ en México 🇲🇽.

## ⚡ Características

- ✅ **SQL Injection (SQLi)** - Basado en errores, time-based y boolean
- ✅ **Cross-Site Scripting (XSS)** - Reflejado y almacenado
- ✅ **Local File Inclusion (LFI)** - Lectura de archivos del sistema
- ✅ **Server-Side Request Forgery (SSRF)** - Acceso a servicios internos
- 📊 **Reportes en TXT y JSON** con evidencia técnica
- 🚀 **Multihilo implícito** para escaneos rápidos
- 🔧 **Soporte de proxies** (Burp, OWASP ZAP, etc.)
- 🎨 **Interfaz colorida** en terminal

## 📦 Instalación

```bash
# Clonar repositorio
git clone https://github.com/Falconmx1/MX-WEBSCAN.git
cd MX-WEBSCAN

# Instalar dependencias
pip install -r requirements.txt

# (Opcional) Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
