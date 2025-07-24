# NetTest – Advanced WiFi Auditing Tool

**Author:** OblivionDH  
**Date:** 2024-06-20  
**Version:** 1.0  

NetTest es una herramienta avanzada y modular para **auditorías WiFi** desarrollada en Python, diseñada para profesionales de ciberseguridad. Combina captura de handshakes, ataques de desautenticación y generación de reportes automáticos en múltiples formatos, con soporte para ejecución en paralelo y monitorización en tiempo real.

---

## ✨ Características

- **Detección automática** de interfaces inalámbricas con soporte multi-interfaz.
- **Channel hopping** y escaneo pasivo con `scapy`.
- **Captura de handshakes WPA/WPA2** en paralelo con ataques de deauth.
- **Detección en tiempo real** de handshakes usando `scapy`.
- **Ataques adaptativos de deauth** con reintentos hasta capturar el handshake.
- **Soporte preliminar para captura de PMKID** (placeholder).
- **Cracking automático** de contraseñas usando `aircrack-ng` y listas de palabras personalizadas.
- **Reportes detallados** en formatos **JSON**, **CSV** y **HTML**.
- **Logging rotativo** con timestamps, niveles y detalle por hilo.
- **Ejecución concurrente** optimizada con `ThreadPoolExecutor`.
- **Envío de resultados por email** con adjuntos y autenticación SMTP.
- **Modo interactivo** con actualizaciones en vivo y limpieza segura al finalizar.

---

## 📦 Dependencias

- Python 3.8+
- [scapy](https://scapy.net/)  
- `aircrack-ng` suite:  
  - `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`
- `concurrent.futures`, `argparse`, `logging`, `smtplib`, `jinja2` (opcional para reportes HTML)

Instala dependencias de Python con:
```bash
pip install scapy jinja2
````

---

## ⚙️ Uso

Ejecuta con privilegios de superusuario:

```bash
sudo python3 nettest.py -w /ruta/a/wordlist.txt -e tu_email@dominio.com [opciones]
```

### Opciones principales

| Opción                | Descripción                                               |
| --------------------- | --------------------------------------------------------- |
| `-b`, `--bssid`       | BSSID objetivo.                                           |
| `-B`, `--bssid-list`  | Archivo con lista de BSSIDs y canales.                    |
| `-c`, `--channel`     | Canal de la red objetivo.                                 |
| `-i`, `--interface`   | Interfaz inalámbrica (auto-detección por defecto).        |
| `-w`, `--wordlist`    | Lista de palabras para cracking (obligatorio).            |
| `-d`, `--deauth`      | Nº de paquetes de deauth por repetición (default: 10).    |
| `-r`, `--repetitions` | Nº de repeticiones de deauth (default: 3).                |
| `-t`, `--timeout`     | Timeout para captura de handshake (default: 60s).         |
| `-n`, `--concurrency` | Nº de hilos concurrentes (default: 4).                    |
| `-o`, `--output-dir`  | Carpeta para reportes y logs (default: `nettest_output`). |
| `-v`, `--verbose`     | Modo verbose.                                             |
| `-D`, `--debug`       | Modo debug.                                               |

Ejemplo de ejecución básica:

```bash
sudo python3 nettest.py -b 00:11:22:33:44:55 -c 6 -w rockyou.txt -e results@obliviondh.com
```

---

## 🧩 Estructura de reportes

* `nettest_report.json` – Reporte en JSON estructurado.
* `nettest_report.csv` – Reporte tabular para análisis rápido.
* `nettest_report.html` – Reporte visual (si `jinja2` está instalado).
* `nettest.log` – Log rotativo con todos los eventos y resultados.

---

## 🚨 Aviso legal

Esta herramienta está diseñada **únicamente para auditorías en redes propias** o con autorización explícita. El uso no autorizado puede violar leyes locales e internacionales.

---

## 🤝 Autor

**OblivionDH** – *Cybersecurity & Development Experts*
[https://obliviondh.com](https://obliviondh.com)
