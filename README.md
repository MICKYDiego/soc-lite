># 🛡️ SOC-LITE — Laboratorio de Ciberseguridad Básico

**Autor:** Micky  
**Sistema:** Debian (Servidor SOC) + Kali Linux (Atacante)  
**Propósito:** Simular un entorno SOC básico donde se detectan y bloquean intentos de ataque SSH provenientes de un atacante interno (Kali) hacia un servidor (Debian).

---

## 🎯 Objetivo del proyecto

Implementar un laboratorio funcional de **detección y respuesta ante incidentes** sin necesidad de instalar un SIEM completo (como Wazuh o Splunk).  
En su lugar, se utiliza **rsyslog + bash scripting + iptables/ipset** para:

- Monitorear intentos de autenticación SSH fallidos.
- Identificar direcciones IP con intentos repetidos.
- Bloquear automáticamente esas IP en tiempo real.
- Registrar evidencia de detección y mitigación.

---

## 🧱 Arquitectura del laboratorio
    ┌───────────────┐        Ataques SSH (Brute Force)
    │     Kali      │  -----------------------------▶  │    Debian SOC     │
    │ (Atacante)    │                                 │ (Detector + Firewall)
    └───────────────┘                                 └────────────────────┘
       IP: 192.168.100.12                                IP: 192.168.100.10


- **Kali Linux:** Genera intentos fallidos de conexión SSH al servidor.  
- **Debian:** Detecta, registra y bloquea al atacante usando `journalctl`, `rsyslog`, `ipset` y `iptables`.

---

## ⚙️ Configuración básica

### 1️⃣ Red y conectividad
Ambas VMs en **VirtualBox**, red **"Red interna"** llamada `SOC_NET`.  
Comprobación:
```bash
ip -4 addr show
ping 192.168.100.12   # desde Debian hacia Kali
ping 192.168.100.10   # desde Kali hacia Debian

2️⃣ Configurar recepción y monitoreo de logs (Debian)

rsyslog monitorea /var/log/auth.log y journalctl -u ssh para registrar eventos SSH.

3️⃣ Script de detección automática

Ruta: ~/soc-lite/scripts/detect_and_ipset_block.sh

Funciones principales:

Detecta fallos SSH (Invalid user o Failed password).

Cuenta intentos por IP.

Marca como intruso si supera un umbral (20 intentos por defecto).

Añade la IP a un conjunto ipset y crea una regla iptables para bloquearla.

Genera evidencia en ~/soc-lite/evidence/.

Ejemplo de ejecución:~/soc-lite/scripts/detect_and_ipset_block.sh

📄 Evidencia del laboratorio

Archivos sanitizados (sin IP reales) disponibles en:
reports/sanitized/
├── intruder_ips_count_sanitized.txt
├── intruder_ips_flagged_sanitized.txt
├── ipset_list_sanitized.txt
├── iptables_brutelist_sanitized.txt
├── ssh_bruteforce_report_sanitized.txt
└── journal_ssh_sanitized.txt
Ejemplo de detección:
[2025-11-10 21:05:48] MARCADA: 192.168.100.12 intentos=24
[2025-11-10 21:05:48] Ejecución finalizada. Archivos generados en /soc-lite/logs/
Resultado del bloqueo:
sudo ipset list brute_blacklist
sudo iptables -L INPUT -n --line-numbers | grep brute_blacklist
🧠 Conceptos aplicados

Proceso vs Servicio:
Un proceso es una instancia en ejecución de un programa.
Un servicio es un proceso que corre en segundo plano (daemon), como sshd o rsyslogd.

Protocolo SSH:
Protocolo seguro para conexión remota. Vulnerable a ataques de fuerza bruta si no se limita el acceso.

TCP vs UDP:
TCP garantiza entrega y control de conexión (usado por SSH).
UDP es rápido, sin control de sesión (usado por DNS, streaming, etc).

Privilegios root:
El script usa privilegios elevados para poder modificar iptables y ipset.
🧩 Posibles mejoras

Implementar detección de intentos distribuidos (varias IPs atacantes).

Integrar un dashboard ligero (por ejemplo Grafana + Loki).

Automatizar reportes HTML o PDF con los resultados.

Añadir alertas vía correo o Discord Webhook.
🧾 Estructura final del proyecto
soc-lite/
├── scripts/
│   └── detect_and_ipset_block.sh
├── reports/
│   └── sanitized/
├── capturas/
│   └── *.txt   (evidencias)
├── docs/
├── README.md
└── .gitignore

🧰 Herramientas utilizadas
Herramienta	Rol	VM
rsyslog	Recepción y análisis de logs SSH	Debian
journalctl	Fallback si no existe auth.log	Debian
iptables / ipset	Bloqueo de IPs maliciosas	Debian
sshpass, nmap	Generación de intentos desde Kali	Kali
bash scripting	Automatización de detección	Debian

👨💻 Autor
Micky / Diego Bisesti
