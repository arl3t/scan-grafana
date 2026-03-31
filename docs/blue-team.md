# Blue Team — Guías de laboratorio

Documentación de apoyo para **simulación controlada**, **captura de tráfico** y **evaluación de vulnerabilidades** en entornos **autorizados**. No ejecutes estas técnicas contra sistemas sin permiso explícito.

---

## Atomic Red Team — Instalación y uso

Biblioteca de tests portátiles mapeados al framework **MITRE ATT&CK®** para validar defensas (EDR, SIEM, registro, reglas, etc.).

**Repositorio oficial:** [redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)  
**Invoke-AtomicRedTeam:** [redcanaryco/invoke-atomicredteam](https://github.com/redcanaryco/invoke-atomicredteam)

### Tabla de contenidos

- [Windows](#instalación-en-windows)
- [Linux (Debian / Ubuntu)](#instalación-en-linux-debian--ubuntu)
- [Ejecución manual sin Invoke](#ejecución-manual-sin-invoke-atomicredteam)
- [Invoke-AtomicRedTeam (recomendado)](#invoke-atomicredteam-recomendado)
- [Ejemplos](#ejemplos)
- [Notas importantes](#notas-importantes)

### Instalación en Windows

#### Opción recomendada (Invoke-AtomicRedTeam)

1. Abre **PowerShell como administrador**.
2. Instala el framework:

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

3. Importa el módulo (ajusta la ruta si instalaste en otro sitio):

```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

#### Desde PowerShell Gallery (alternativa)

```powershell
Install-Module -Name invoke-atomicredteam, powershell-yaml -Scope CurrentUser -Force
```

### Instalación en Linux (Debian / Ubuntu)

**Ubicación de referencia en este despliegue:** los repositorios viven bajo **`/home/horus/Blue-Team/AtomicRedTeam`** (usuario **horus**). Si tu usuario u organización de carpetas es distinta, sustituye por **`$HOME/Blue-Team/AtomicRedTeam`** o la ruta que uses.

#### Paso 1 — PowerShell Core (`pwsh`)

```bash
sudo apt-get update
sudo apt-get install -y wget apt-transport-https software-properties-common

wget -q "https://packages.microsoft.com/config/debian/$(lsb_release -rs)/packages-microsoft-prod.deb" -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm -f packages-microsoft-prod.deb

sudo apt-get update
sudo apt-get install -y powershell
```

#### Paso 2 — Clonar repositorios

```bash
mkdir -p /home/horus/Blue-Team/AtomicRedTeam
cd /home/horus/Blue-Team/AtomicRedTeam
git clone https://github.com/redcanaryco/atomic-red-team.git
git clone https://github.com/redcanaryco/invoke-atomicredteam.git
```

*(Ejecuta como usuario **horus** en su `$HOME`, o usa `mkdir -p "$HOME/Blue-Team/AtomicRedTeam"` en otro usuario.)*

#### Paso 3 — Módulo en PowerShell

Abre `pwsh` y ejecuta **una** de estas opciones:

```powershell
Install-Module -Name invoke-atomicredteam, powershell-yaml -Scope CurrentUser -Force
```

O instalación asistida (misma base que el clon manual):

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -InstallPath /home/horus/Blue-Team/AtomicRedTeam -getAtomics
```

#### Paso 4 — Importar el módulo

Ruta alineada con la carpeta anterior:

```powershell
Import-Module "/home/horus/Blue-Team/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1" -Force
```

Equivalente portable con `$HOME`:

```powershell
Import-Module "$HOME/Blue-Team/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1" -Force
```

### Ejecución manual (sin Invoke-AtomicRedTeam)

1. Entra en el directorio de la técnica (ruta de referencia en este despliegue):

**Ruta:** `/home/horus/Blue-Team/AtomicRedTeam/atomic-red-team/atomics/T1059.003`

```bash
cd /home/horus/Blue-Team/AtomicRedTeam/atomic-red-team/atomics/T1059.003
```

2. Abre el `.md` del test (p. ej. `T1059.003.md` en esa carpeta) y localiza **Atomic Test #N** para tu SO.
3. Ejecuta los comandos indicados **solo** en máquinas de laboratorio autorizadas.

### Invoke-AtomicRedTeam (recomendado)

```powershell
# Listar / explorar técnicas (según versión del módulo)
Get-AtomicTechnique

# Un test concreto
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Todos los tests de una técnica
Invoke-AtomicTest T1059.001

# Prerrequisitos
Invoke-AtomicTest T1059.001 -GetPreReqs

# Limpieza tras el test
Invoke-AtomicTest T1059.001 -Cleanup
```

**Opciones útiles:**

| Parámetro | Uso |
|-----------|-----|
| `-ExecutionLogPath /tmp/art.log` | Guardar log de ejecución |
| `-ShowDetails` | Ver detalles antes de ejecutar |
| `-TimeoutSeconds 300` | Tiempo máximo por test |

### Ejemplos

```powershell
# Descubrimiento de usuario (varía según plataforma)
Invoke-AtomicTest T1033 -TestNumbers 1

# Ejecución vía shell (ejemplo Linux; revisa el test concreto)
Invoke-AtomicTest T1059.004 -TestNumbers 1
```

### Notas importantes

- Usa **solo** laboratorios aislados o hosts con **autorización por escrito**.
- Algunos tests modifican el sistema, crean usuarios o persistencia: planifica **rollback** y **snapshots**.
- Correlaciona con SIEM / EDR: el objetivo es **validar detección**, no “pasar desapercibido”.
- Mantén **Atomic Red Team** y **Invoke-AtomicRedTeam** actualizados (`git pull`).

### Recursos oficiales

- [Atomic Red Team (GitHub)](https://github.com/redcanaryco/atomic-red-team)
- [Invoke-AtomicRedTeam (GitHub)](https://github.com/redcanaryco/invoke-atomicredteam)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

## Wireshark — Captura y filtros para prácticas de detección

**Wireshark** (y **tshark** en línea de comandos) permiten analizar tráfico y afinar reglas o hipótesis de detección.

### Instalación (ejemplos)

**Ubuntu / Debian**

```bash
sudo apt-get update
sudo apt-get install -y wireshark tshark
# Captura en interfaces: puede requerir grupo wireshark o sudo
sudo usermod -aG wireshark "$USER"
```

**macOS (Homebrew)**

```bash
brew install --cask wireshark
```

### Nota previa (Debian / Ubuntu)

- Sustituye **`eth0`** por tu interfaz real (`ip link`, p. ej. `enp0s3`, `wlan0`).
- La captura en bruto suele requerir **`sudo`** o pertenecer al grupo **`wireshark`**.
- Los ejemplos valen para **Wireshark (GUI)** y **`tshark` (terminal)**. En GUI: elige la interfaz → **Start**; los **Display filters** se escriben en la barra superior.

---

### 1. Captura general de tráfico (todo lo que pasa por la interfaz)

**Objetivo:** volcar el tráfico para análisis posterior.

**Wireshark (GUI):** abre Wireshark → selecciona la interfaz → **Start**.

**tshark:**

```bash
# Todo el tráfico a fichero (recomendado)
sudo tshark -i eth0 -w /tmp/trafico_general.pcap

# Solo los primeros 500 paquetes
sudo tshark -i eth0 -c 500 -w /tmp/trafico_general.pcap
```

Detén la captura con **Ctrl+C**.

---

### 2. Captura orientada a credenciales en texto plano

**Objetivo:** localizar sesiones **sin cifrar** (HTTP POST, FTP, Telnet, SMTP, POP, IMAP, etc.). Solo en **laboratorio autorizado**.

**Display filters** (barra de filtros de Wireshark, o al revisar el pcap):

```text
frame contains "password" or frame contains "passwd" or frame contains "user" or frame contains "login"
```

Protocolos clásicos inseguros:

```text
http.request or ftp or telnet or smtp or pop or imap
```

HTTP con credenciales en claro (formulario / básico):

```text
http contains "password=" or http.authbasic
```

**Captura con `tshark` (ejemplo):**

```bash
sudo tshark -i eth0 -Y 'http.request or ftp or telnet' -w /tmp/credenciales.pcap
```

Tras capturar, abre el fichero y aplica por ejemplo:

```text
frame contains "password"
```

**Blue Team:** usa **Follow → TCP Stream** (Wireshark) para ver la conversación completa.

---

### 3. Captura de ARP

**Objetivo:** ver solicitudes/respuestas **ARP** (resolución MAC).

| Tipo | Filtro |
|------|--------|
| Display | `arp` |
| Capture (BPF) | `arp` |

**tshark:**

```bash
sudo tshark -i eth0 -f "arp" -w /tmp/captura_arp.pcap
```

---

### 4. LLMNR, DNS y DHCP (y combinado con ARP)

**Objetivo:** resolución de nombres y asignación de IPs (útil ante **spoofing**, **LLMNR poisoning**, etc.).

| Protocolo | Display filter (ejemplos) |
|-----------|---------------------------|
| LLMNR | `llmnr` o `udp.port == 5355` |
| DNS | `dns` |
| DHCP / BOOTP | `dhcp` o `bootp` |

**Display filter combinado (ARP + nombre + DHCP):**

```text
arp or llmnr or dns or dhcp
```

**tshark** — un solo fichero con captura BPF acotada:

```bash
sudo tshark -i eth0 -f "arp or udp port 5355 or port 53 or port 67 or port 68" \
  -w /tmp/protocolos_nombre_dhcp.pcap
```

(Puertos habituales: DNS **53**, DHCP **67/68**, LLMNR **5355/udp**.)

Al analizar el pcap, puedes usar el display filter:

```text
arp or llmnr or dns or dhcp
```

---

### 5. Captura combinada avanzada (Blue Team)

**Objetivo:** reducir ruido en disco con **capture filter** (`-f`) y focalizar la vista con **display filter** (`-Y`).  
*Nota:* lo que se **guarda** en el `.pcap` lo determina sobre todo **`-f`**; **`-Y`** afecta sobre todo a lo que **ves** en consola mientras capturas (según versión de `tshark`).

```bash
sudo tshark -i eth0 \
  -f "arp or udp port 5355 or port 53 or port 67 or port 68 or port 80 or port 21 or port 23" \
  -Y 'arp or llmnr or dns or dhcp or http or ftp or telnet or frame contains "password"' \
  -w /tmp/captura_blue_team.pcap
```

Resumen:

| Opción | Rol |
|--------|-----|
| `-f "..."` | Filtro **BPF** en captura (menos tráfico grabado) |
| `-Y '...'` | Filtro de **visualización** (consola / análisis en vivo) |

---

### Referencia rápida: leer un pcap ya guardado

```bash
tshark -r /tmp/trafico_general.pcap -Y "dns" -T fields -e frame.time -e dns.qry.name
```

Otros display filters útiles en laboratorio:

| Objetivo | Filtro |
|----------|--------|
| SMB2 | `smb2` |
| TLS Client Hello | `tls.handshake.type == 1` |
| ICMP | `icmp` |
| Una IP | `ip.addr == 192.168.1.10` |

---

## OpenVAS / Greenbone — Escaneo de vulnerabilidades

**OpenVAS** es el motor de escaneo; en la práctica actual suele desplegarse con **Greenbone Community Edition** (interfaz web, feed de pruebas).

### Enfoques habituales

1. **Appliance / ISO oficial** — [Greenbone Community Edition](https://www.greenbone.net/en/testnow/) (revisa licencia y uso).
2. **Contenedores** — imágenes mantenidas por Greenbone o comunidad; adecuado para laboratorio.
3. **Paquetes en Linux** — disponibilidad variable según distribución; valida versión y feeds.

### Buenas prácticas (Blue Team / lab)

- Aísla la red de escaneo; los escaneos activos pueden ser **intrusivos**.
- Documenta **alcance** y **ventanas** de prueba.
- Cruza resultados con **inventario** (por ejemplo datos de Nmap/SQLite/Grafana de este repo) para priorizar exposición real.

**Documentación:** [Greenbone docs](https://docs.greenbone.net/)

---

## Relación con esta consola (scan-grafana)

Esta aplicación se centra en **inventario con Nmap → SQLite → Grafana**. Las secciones anteriores son **complementarias** para laboratorio Blue Team: no están integradas en el pipeline de escaneo de la web.
