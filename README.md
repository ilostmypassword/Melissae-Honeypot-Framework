# Melissae

<p align="center">
  <img src="https://github.com/user-attachments/assets/99609143-d9df-43f9-a824-befd98895cb9" alt="Melissae Logo" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=white" alt="React" />
  <img src="https://img.shields.io/badge/Vite-6-646CFF?style=flat-square&logo=vite&logoColor=white" alt="Vite" />
  <img src="https://img.shields.io/badge/Tailwind-3.4-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white" alt="Tailwind" />
  <img src="https://img.shields.io/badge/Flask-3-000000?style=flat-square&logo=flask&logoColor=white" alt="Flask" />
  <img src="https://img.shields.io/badge/MongoDB-4.4-47A248?style=flat-square&logo=mongodb&logoColor=white" alt="MongoDB" />
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/Nginx-Alpine-009639?style=flat-square&logo=nginx&logoColor=white" alt="Nginx" />
  <img src="https://img.shields.io/badge/Python-3-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python" />
</p>

---

Melissae is a modular, containerized honeypot framework built to emulate real-world network services. It is designed for cybersecurity researchers, analysts, and SOC teams to detect, analyze, and better understand malicious activity on their infrastructure.

Each service module runs in its own container, allowing flexible deployment and isolated execution. Collected logs are centralized in MongoDB via a dedicated pipeline (see [workflow](#workflow) for more details), and exposed through a Flask API consumed by the dashboard.

The project includes a fully functional dashboard offering real-time visibility into attacker behavior, threat scoring, and IOC export, making Melissae not just a honeypot, but a lightweight threat intelligence platform.

---

## Table of Contents

1. [Overview](#overview) 
    - [Key Features](#key-features)
    - [Screenshots](#screenshots)
2. [Infrastructure](#infrastructure)
    - [Schema](#schema)
    - [Workflow](#workflow)
    - [Scheduled Jobs](#scheduled-jobs)
3. [Modules](#modules)
    - [Web](#web) 
    - [SSH](#ssh) 
    - [FTP](#ftp)
    - [Modbus](#modbus)
    - [MQTT](#mqtt)
    - [Telnet](#telnet)
    - [CVE Modules](#cve-modules)
4. [Dashboard](#dashboard)
    - [Overview Dashboard](#overview-dashboard)
    - [GeoIP Attack Map](#geoip-attack-map)
    - [Search Engine](#search-engine)
    - [Threat Intelligence](#threat-intelligence)
5. [Scoring](#scoring)
    - [Scale & Verdicts](#scale--verdicts)
    - [Scoring Signals](#scoring-signals)
    - [Confidence](#confidence)
6. [Getting Started](#getting-started)
    - [Installation](#installation)
    - [Starting the Stack](#starting-the-stack)
    - [Accessing the Dashboard](#accessing-the-dashboard)
    - [List Deployed Modules](#list-deployed-modules)
    - [Destroy the Stack](#destroy-the-stack)
7. [CLI Reference](#cli-reference)
8. [Contributing](#contributing)
9. [Credits](#credits)

---

## Overview

### Key Features

**Modular Service Support**: Configure Melissae to expose between 1 and 6+ services simultaneously, allowing for flexible deployment scenarios tailored to your specific security needs. In addition to native honeypot modules, Melissae supports **CVE-specific modules**, purpose-built containers that reproduce real vulnerabilities to catch exploitation attempts in the wild. See [contributing](#contributing) if you're interested in developing new modules.  
  
**Centralized Management Dashboard**: Monitor and manage your honeypot through a modern dashboard, which offers:
- **Statistical Analysis**: Visualize attack patterns, trends, and frequency with interactive charts (Chart.js).
- **Log Search**: Use the Melissae Query Language (MQL), a simple query language (that will be developed more in the future), to perform searches within the captured logs.
- **Logs Export**: Export logs in JSON format, filtered according to specific criteria such as time, service type, IP...
- **Threat Scoring**: Continuous 0-100 scoring engine with multi-factor confidence assessment.
- **GeoIP Attack Map**: Interactive world map showing attack origins with threat markers colored by verdict and sized by score. Supports hybrid deployments (internal + external networks).
- **GeoIP Enrichment**: Automatic geolocation of public IPs via ip-api.com batch API, with results cached in MongoDB.
- **STIX 2 Export**: Export Threat Intelligence IOCs as STIX 2.1 indicators (one per IP) directly from the dashboard.
- **Killchain View**: Click any IP in Threat Intelligence to open an attack killchain timeline grouped by protocol with start/end timestamps, ordered from oldest to newest, and jump to full logs from the same pivot.
- **Automated Hygiene**: A purge removes benign IoCs unseen for 1h and their associated logs to keep the dataset lean.

### Screenshots

<div style="display: flex; flex-wrap: wrap; justify-content: space-around;">
  <img width="300" height="auto" alt="screenshot_17022026_093604" src="https://github.com/user-attachments/assets/24b1101b-5360-4166-9c74-b13c459568aa" />
  <img width="300" height="auto" alt="screenshot_17022026_093642" src="https://github.com/user-attachments/assets/2eda0491-d2b4-4ffc-bc5f-0060878f03d3" />
  <img width="300" height="auto" alt="screenshot_17022026_093708" src="https://github.com/user-attachments/assets/ee49fa9a-bafb-4885-9e69-c7fafc7b121d" />
  <img width="300" height="auto" alt="screenshot_17022026_093731" src="https://github.com/user-attachments/assets/c7d6bc68-8f2f-43bf-8bda-0c33e50d95ea" />
  <img width="300" height="auto" alt="screenshot_17022026_093808" src="https://github.com/user-attachments/assets/7032151e-829c-428c-a9ff-621cb7fdc41b" />
  <img width="300" height="auto" alt="screenshot_17022026_093836" src="https://github.com/user-attachments/assets/88e8264a-9316-4cbe-8680-5d145729c5a1" />
  <img width="300" height="auto" alt="screenshot_17022026_093900" src="https://github.com/user-attachments/assets/71742a97-e00b-4cbb-b938-8578c7612f49" />
  <img width="300" height="auto" alt="screenshot_17022026_094013" src="https://github.com/user-attachments/assets/2a833ee5-7c64-4219-aee3-3fa98dab090c" />
</div>



---

## Infrastructure

> [!WARNING]  
> Please use this tool with care, and remember to use it on a dedicated secure server that is properly isolated from your infrastructure.

The infrastructure is fully containerized with Docker, and modules can be deployed on demand. The dashboard, the API and MongoDB are always deployed locally. The dashboard is accessible via SSH port forwarding (see [Accessing the Dashboard](#accessing-the-dashboard) for details).

### Schema

<img width="1311" height="822" alt="archi" src="https://github.com/user-attachments/assets/4ec07339-e395-4467-8945-6bcaf80ef6da" />

### Workflow

- Honeypots write raw logs to their volumes.
- `scripts/logParser.py` performs **incremental ingestion**: it keeps per-file offsets/mtimes in Mongo (`ingestion_state`), reads only new log lines, deduplicates with deterministic IDs, and upserts into Mongo (`logs`).
- `scripts/threatIntel.py` computes verdicts and writes into Mongo (`threats`).
- The Flask API in `api/api.py` exposes `/api/logs` and `/api/threats` (loopback + restricted CORS).
- Nginx (dashboard) proxies `/api` and serves the UI; access via basic auth and SSH port-forward.

<img width="1311" height="822" alt="archi2" src="https://github.com/user-attachments/assets/10c357e6-7058-42a8-845e-f5f191011276" />

### Scheduled Jobs

- Every minute: [scripts/logParser.py](scripts/logParser.py) normalizes raw module logs into Mongo `logs`.
- Every minute: [scripts/threatIntel.py](scripts/threatIntel.py) recalculates verdicts into Mongo `threats`.
- Every 3 hours: [scripts/purgeLogs.py](scripts/purgeLogs.py) removes benign IoCs unseen for 1h and deletes their associated logs.

These cron entries are added while installing.

---

## Modules

The choice of modular, containerized deployment means that contributors can easily develop new modules. There are currently 6 native honeypot modules, 1 CVE module, and 3 system services. 

> **Port conflict rule**: Modules that bind the same host port cannot be deployed together. For example, `telnet` and `cve-2026-24061` both use port 23 — the CLI will reject conflicting combinations.

**Summary table**

| Type     | Service - Container                               | Port(s)            | Exposure           | Notes |
|----------|--------------------------------------------------|--------------------|--------------------|-------|
| Honeypot | melissae_proxy, melissae_apache1, melissae_apache2 | 80                 | Public             | Web stack via Nginx + Apache |
| Honeypot | melissae_ssh                                     | 22                 | Public             | Weak creds by design |
| Honeypot | melissae_ftp                                     | 21                 | Public             | Weak creds by design |
| Honeypot | melissae_modbus                                  | 502                | Public             | PLC emulation |
| Honeypot | melissae_mqtt                                    | 1883               | Public             | Mosquitto |
| Honeypot | melissae_telnet                                  | 23                 | Public             | Weak creds by design |
| CVE      | melissae_cve_2026_24061                          | 23                 | Public             | CVE-2026-24061 Telnet auth bypass |
| System   | melissae_mongo                                   | 127.0.0.1:27017    | Local      | Data store |
| System   | melissae_api                        | 127.0.0.1:5000     | Local      | Flask API |
| System   | melissae_dashboard                     | 127.0.0.1:9999     | Local      | Dashboard |

### Web

| Type | Image | Container Name |
| :---: | :---: | :---: |
| Proxy | nginx:latest | melissae_proxy |
| Web Server | httpd:2.4-alpine | melissae_apache1 |
| Web Server | httpd:2.4-alpine | melissae_apache2 |

- Logs format

```json
[
  {
    "protocol": "http",
    "date": "2025-04-16",
    "hour": "11:47:08",
    "ip": "192.168.X.X",
    "action": "GET",
    "path": "/",
    "user-agent": "Mozilla/5.0"
  }
]
```

- Usage
  - By default, Melissae provides you a basic configuration for both proxy and web servers containers, those configurations are located in `modules/web/conf`.
  - Add the files you need for the website to be exposed via honeypot in `modules/web/server`.

### SSH

| Type | Image | Container Name |
| :---: | :---: | :---: |
| SSH Server | ubuntu:latest + openssh | melissae_ssh |

- Logs format

```json
[
  {
    "protocol": "ssh",
    "date": "2025-04-16",
    "hour": "11:48:09",
    "ip": "192.168.X.X",
    "action": "Login failed with invalid user",
    "user": "test"
  }
]
```

- Usage
  - You can modify your module credentials here: `modules/ssh/Dockerfile` (default: `user:admin`).

### FTP

| Type | Image | Container Name |
| :---: | :---: | :---: |
| FTP Server | fauria/vsftpd | melissae_ftp |

- Logs format

```json
[
  {
    "protocol": "ftp",
    "date": "2025-04-16",
    "hour": "11:48:37",
    "ip": "192.168.X.X",
    "action": "Login failed",
    "user": "test"
  }
]
```

- Usage
  - The shared repository with the ftp container is `modules/ftp/server`.
  - You can modify your module credentials here: `docker-compose.yml` (default: `ftpuser:ftppass`).

### Modbus

| Type | Image | Container Name |
| :---: | :---: | :---: |
| Modbus TCP Server | python:3.11-slim | melissae_modbus |

- Logs format

```json
[
  {
    "protocol": "modbus",
    "date": "2025-05-30",
    "hour": "10:38:23",
    "ip": "192.168.X.X",
    "action": "Read request - Read Holding Registers"
  },
  {
    "protocol": "modbus",
    "date": "2025-05-30", 
    "hour": "10:41:22",
    "ip": "192.168.X.X",
    "action": "Write attempt - Write Multiple Registers"
  }
]
```

- Features
  - **Industrial PLC Emulation**: Simulates Siemens S7-1200 and Schneider Electric M340 PLCs.
  - **Randomized Device Identifiers**: Generates unique serial numbers and firmware versions on each startup.
  - **Protocol Detection**: Logs all Modbus function codes (read/write operations).
  - **Threat Escalation**: Write attempts trigger high-severity threat alerts.

- Usage
  - **Default Profile**: Siemens S7-1200 (modify in `modules/modbus/Dockerfile` to use `schneider` profile).
  - **Port**: Standard Modbus TCP port 502.
  - **Device Profiles**:
    - **Siemens**: S7-xxxxxx serials, V3.x-V4.x firmware, 1000 registers.
    - **Schneider**: M340-xxxxx-X serials, V2.x-V3.x firmware, 2000 registers.

### MQTT

| Type | Image | Container Name |
| :---: | :---: | :---: |
| Mosquitto Server | eclipse-mosquitto:latest | melissae_mqtt |

- Logs format

```json
[
  {
    "protocol": "mqtt",
    "date": "2025-09-12",
    "hour": "08:56:25",
    "ip": "192.168.X.X",
    "action": "Client connected"
  },
  {
    "protocol": "mqtt",
    "date": "2025-09-12",
    "hour": "08:57:17",
    "ip": "192.168.X.X",
    "action": "Subscribe",
    "user": "auto-XX"
  }
]
```

### Telnet

| Type | Image | Container Name |
| :---: | :---: | :---: |
| Telnet Server | ubuntu:24.04 + inetutils-telnetd | melissae_telnet |

- Logs format

```json
[
  {
    "protocol": "telnet",
    "date": "2026-02-15",
    "hour": "09:12:34",
    "ip": "192.168.X.X",
    "action": "Connection established"
  },
  {
    "protocol": "telnet",
    "date": "2026-02-15",
    "hour": "09:12:41",
    "ip": "192.168.X.X",
    "action": "Login failed",
    "user": "admin"
  },
  {
    "protocol": "telnet",
    "date": "2026-02-15",
    "hour": "09:13:02",
    "ip": "192.168.X.X",
    "action": "Login successful",
    "user": "admin"
  }
]
```

- Usage
  - Modify credentials in `modules/telnet/Dockerfile` (default: `admin:telnet`).
  - Logs are stored in `modules/telnet/logs/auth.log`.

### CVE Modules

CVE modules are a dedicated category of honeypots that reproduce **specific, real-world vulnerabilities**. Unlike generic protocol honeypots, they are designed to attract and detect exploitation attempts targeting known CVEs.

Each CVE module lives under `modules/cve/<CVE-ID>/` and follows a standard structure:

```bash
modules/cve/CVE-YYYY-XXXXX/
    |-- Dockerfile
    |-- startup.sh
    |-- logs/
```

Log entries from CVE modules include a `cve` field in addition to the standard fields, enabling CVE-specific filtering in the dashboard search engine (e.g. `cve:CVE-2026-24061`).

#### CVE-2026-24061 — Telnet Auth Bypass

| Property | Value |
|----------|-------|
| CVE | [CVE-2026-24061](https://nvd.nist.gov/vuln/detail/CVE-2026-24061) |
| CVSS | 9.8 CRITICAL |
| CWE | CWE-88 Improper Neutralization of Argument Delimiters in a Command |
| Affected | GNU Inetutils telnetd ≤ 2.7 |
| Container | melissae_cve_2026_24061 |
| Port | 23 (Telnet) |
| Image | Ubuntu 24.04 + inetutils-telnetd 2:2.5-3ubuntu4 |

**Vulnerability**: The `-f` flag in GNU inetutils `telnetd` allows an attacker to bypass authentication entirely by injecting `-froot` as the `USER` environment variable during connection. The flag is interpreted by `login` as "pre-authenticated", granting immediate root access without credentials.

- Logs format

```json
[
  {
    "protocol": "telnet",
    "date": "2026-01-15",
    "hour": "14:32:08",
    "ip": "192.168.X.X",
    "action": "Connection opened",
    "cve": "CVE-2026-24061"
  },
  {
    "protocol": "telnet",
    "date": "2026-01-15",
    "hour": "14:32:12",
    "ip": "192.168.X.X",
    "action": "Root login successful",
    "user": "root",
    "cve": "CVE-2026-24061"
  }
]
```

- Usage
  - No configuration needed — the module runs with default settings.

---

## Dashboard

### Overview Dashboard

The main view shows some stat cards (total events, per-protocol breakdowns, verdict counts), an activity timeline chart, a protocol distribution doughnut, and a top attacking IPs chart.

**Critical Events Section**: When security-critical events are detected (CVE exploits, successful logins on Telnet/SSH/FTP, Modbus write attempts), a highlighted alert section appears with red-themed cards showing the counts. These events warrant immediate investigation.

### GeoIP Attack Map

The `/map` page automatically adapts its display based on the types of IPs detected:

| IP mix | Display |
|--------|---------|
| All private IPs | Summary stats + Internal Network Threats table |
| All public IPs | Summary stats + Interactive world map + Country breakdown + Geolocated threats table |

The detection is automatic — public IPs are geolocated and shown on the map, private IPs are listed in a separate table. No configuration needed.

**GeoIP Enrichment**: Public IPs are geolocated via [ip-api.com](https://ip-api.com/) batch API (free tier, no API key). Results are cached in MongoDB, coordinates validated, and all fields sanitized before storage.

<!-- TODO: Add map screenshot -->

### Search Engine

**Features**

- **Backed by the API**: Logs are loaded from `/api/logs` (MongoDB).
- **Search with logical operators**: Use operators to combine multiple criteria in your search.
- **Field-specific filters**: Search within specific fields like user, ip, protocol, date, hour, action, user-agent, path, or cve using the syntax field:value.
- **Export results**: A button allows exporting the filtered logs.

**Operators**

`AND / and`
`OR / or`
`NOT / not / !`

**Examples**

```
user:root and protocol:ssh
ip:192.168.X.X or ip:192.168.X.Y or ip:192.168.X.Z
protocol:http and not action:success
protocol:modbus and action:write
user:admin or not path:/login
!ip:192.168.X.X and action:failed
protocol:modbus and action:read
cve:CVE-2026-24061
protocol:telnet and action:successful
```

<!-- TODO: Add search screenshot -->

### Threat Intelligence

The Threat Intelligence page lists all scored IPs with verdict tags, scores, and confidence levels. Each row offers:
- **Details panel**: Modal showing IP, verdict, score/100, confidence, timestamps, and rule reasons.
- **Killchain timeline**: Events grouped by protocol with start/end timestamps, ordered from oldest to newest.
- **STIX 2.1 Export**: Download a STIX 2.1 bundle (one indicator per IP) for selected or all threats.

---

## Scoring

### Scale & Verdicts

Scores use a **continuous 0-100 scale** with additive weighted signals and log-scaling for volume-dependent indicators.

| Range | Verdict | Description |
|-------|---------|-------------|
| 0-29 | Benign | Passive noise, single low-value connections |
| 30-69 | Suspicious | Active scanning, failed auth, reconnaissance |
| 70-100 | Malicious | Compromise, post-exploitation, ICS tampering |

### Scoring Signals

| Category | Signals | Max Points |
|----------|---------|-----------|
| Reconnaissance | HTTP requests (log-scaled), MQTT events | ~20 |
| Scanning | Sensitive HTTP paths, HTTP burst (>20/5min) | ~35 |
| Auth attacks | Brute-force (SSH/FTP/Telnet failures), SSH/FTP/Telnet bursts | ~35 |
| Compromise | Successful SSH/FTP login, FTP file transfers | ~40 |
| CVE exploitation | Telnet activity (deprecated protocol), successful Telnet login (CVE exploit) | ~60 |
| Post-exploit | Sensitive SSH commands (sudo, wget, curl...) | ~45 |
| ICS/SCADA | Modbus read/write operations | ~50 |
| Compounding | Multi-protocol activity, multiple services compromised, ICS + credentials, Telnet + other compromises | ~25 |

### Confidence

Confidence is a weighted combination of 5 factors (0.10 – 1.00):

| Factor | Weight | Based on |
|--------|--------|----------|
| Volume | 20% | Log-scaled event count |
| Signal diversity | 25% | Number of distinct scoring reasons |
| Protocol breadth | 10% | Number of protocols seen |
| Time spread | 15% | Observation duration (up to 24h) |
| Indicator certainty | 30% | High-confidence signals (login, post-exploit, ICS writes, telnet CVE exploitation) |

---

## Getting Started

### Installation

Clone the repository:

```bash
git clone https://github.com/ilostmypassword/Melissae.git
```

Give execution rights to the script:

```bash
cd Melissae/
chmod +x melissae.sh
```

Install Melissae :

> [!CAUTION]
> Your SSH port will be modified and given to you at the end of the installation script. Note it carefully.

Enter the interactive console and run `install`:

```bash
./melissae.sh
melissae [0 active] > install
```

The installer will prompt you to set dashboard basic-auth credentials (stored hashed with bcrypt in `dashboard/conf/htpasswd`). 
Keep these for UI/API access via the dashboard.

Add your user in the docker group :

```bash
sudo su
usermod -aG docker your_username
```

> [!IMPORTANT]  
> After adding the user to the Docker group, you will need to reconnect via SSH using the generated port. See [Accessing the Dashboard](#accessing-the-dashboard) for the connection command.

### Starting the Stack

Before launching your stack, check the module configurations in the [Modules](#modules) section.

**Start your stack**

Enter the interactive console and use `start`:

```bash
./melissae.sh
melissae [0 active] > start web ssh modbus
```

Available modules: `all`, `web`, `ssh`, `ftp`, `modbus`, `mqtt`, `telnet`, `cve-2026-24061`

> **Note**: `all` starts all standard honeypot modules (including `telnet`) but **not** CVE modules, since they may conflict on the same port. Start CVE modules explicitly by name.

Examples:
```
melissae [0 active] > start all

melissae [0 active] > start web ssh modbus

melissae [0 active] > start ssh cve-2026-24061
```

Your stack is now deployed. The helper script automatically brings up the dashboard, MongoDB, and the API alongside any honeypot modules you select.

If port forwarding is active, access the dashboard at `http://localhost:8080`. Otherwise, see [Accessing the Dashboard](#accessing-the-dashboard).

### Accessing the Dashboard

Connect to your server with SSH port forwarding (dashboard listens on `127.0.0.1:9999` inside the server): 

```bash
ssh -L 8080:localhost:9999 user@server -p new_port
```

[Start the stack](#starting-the-stack) and access the dashboard at `http://localhost:8080/`. Use the credentials you set during installation.

<!-- TODO: Add dashboard screenshots -->

### List Deployed Modules

Use `status` in the interactive console:

```
melissae [3 active] > status

Module       Service                State   
---------------------------------------------
mqtt         melissae_mqtt          ❌     
web          melissae_apache1       ❌     
web          melissae_apache2       ❌     
web          melissae_proxy         ❌     
ssh          melissae_ssh           ✅     
ftp          melissae_ftp           ✅     
modbus       melissae_modbus        ❌     
telnet       melissae_telnet        ✅     

[*] CVE modules

Module              Service                      State   
----------------------------------------------------------
cve-2026-24061      melissae_cve_2026_24061      ✅     

[*] System modules

Module       Service                State   
---------------------------------------------
mongodb      melissae_mongo         ✅     
api          melissae_api           ✅     
dashboard    melissae_dashboard     ✅
```

### Destroy the Stack

Use `destroy` in the interactive console:

```
melissae [6 active] > destroy
```

---

## CLI Reference

**Interactive Mode**

Melissae uses an interactive console:

```bash
$ ./melissae.sh

melissae [0 active] >
```

**Available Commands**

| Category | Command | Description |
|----------|---------|-------------|
| **Core** | `status` | Show all modules and their status |
| | `start <module\|all>` | Start module(s) |
| | `stop [module\|all]` | Stop module(s) or all if none specified |
| | `restart <module\|all>` | Restart module(s) |
| | `build <module\|all>` | Rebuild container(s) |
| **Monitoring** | `logs <module> [lines]` | Show logs for a module (default: 50 lines) |
| | `tail <module>` | Follow logs in real-time (Ctrl+C to stop) |
| | `stats` | Show attack statistics from database |
| | `threats` | Show top threat IPs with scores |
| | `events [count]` | Show recent events (default: 20) |
| **Management** | `install` | Install dependencies and configure system |
| | `destroy` | Stop and remove all containers |
| | `purge` | Clear all logs (requires confirmation) |
| **Shell** | `clear` | Clear screen |
| | `banner` | Show banner |
| | `version` | Show version |
| | `exit`, `quit` | Exit console |

---

## Contributing

This project is open to contributions, and there are several areas of work to be developed. Join the Discord server to get involved:

**Discord**: https://discord.gg/RXWn85cnYm

### Roadmap

- [x] **Modbus Industrial Honeypot Module** — Complete TCP honeypot with PLC emulation
- [x] **React Dashboard Redesign** — Modern SPA with React 19, Vite, Tailwind CSS
- [x] **Continuous Scoring Engine** — 0-100 scale with multi-factor confidence
- [x] **GeoIP Attack Map** — Interactive world map with ip-api.com enrichment
- [x] **Hybrid Deployment** — Support for internal, external, and mixed networks
- [x] **CVE Module Framework** — Dedicated category for vulnerability-specific honeypots
- [x] **Telnet Honeypot Module** — Standard telnet honeypot with weak credentials
- [x] **Interactive Shell**
- [x] **Critical Events Dashboard** — Highlighted alerts for security-critical events
- [ ] Improve MQTT module
- [ ] Develop new CVE modules
- [ ] Develop new modules (SNMP, etc.)
- [ ] Improve the search engine
- [ ] MITRE ATT&CK mapping for threat events
- [ ] Automated PDF/HTML reports
- [ ] Behavioral clustering (attack pattern grouping)
- [ ] Adaptive deception (dynamic honeypot responses)
- [ ] Multi-instance capabilities
- [ ] Rules UI to tune thresholds without redeploying

---

## Credits

Thank you to all contributors for helping the project move forward.

- [summoningshells](https://github.com/summoningshells)
