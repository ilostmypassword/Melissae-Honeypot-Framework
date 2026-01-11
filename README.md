# Melissae

![logo](https://github.com/user-attachments/assets/99609143-d9df-43f9-a824-befd98895cb9)

---

Melissae is a modular, containerized honeypot framework built to emulate real-world network services. It is designed for cybersecurity researchers, analysts, and SOC teams to detect, analyze, and better understand malicious activity on their infrastructure.

Each service module runs in its own container, allowing flexible deployment and isolated execution. Collected logs are centralized in MongoDB via a dedicated pipeline (see [workflow](#workflow) for more details), and exposed through a Flask API consumed by the dashboard.

The project includes a fully functional dashboard offering real-time visibility into attacker behavior, threat scoring, and IOC export, making Melissae not just a honeypot, but a lightweight threat intelligence platform.

---

## Table of Contents

1. [Overview](#overview) 
    - [Key Features](#key-features) 
2. [Infrastructure](#infrastructure)
    - [Schema](#schema)
    - [File Tree](#file-tree)
    - [Workflow](#workflow)
    - [Scheduled Jobs](#scheduled-jobs)
3. [Modules](#modules)
    - [Web](#web) 
    - [SSH](#ssh) 
    - [FTP](#ftp)
    - [Modbus](#modbus)
    - [MQTT](#mqtt)
4. [Search Engine](#search-engine)
5. [Threat Intelligence](#threat-intelligence)
    - [Scoring](#scoring)
    - [STIX2 Export](#stix2-export)
    - [Killchain Timeline](#killchain-timeline)
6. [Getting Started](#getting-started)
    - [Installation](#installation)
    - [Starting up the Stack](#starting-up-the-stack)
    - [Accessing the Dashboard](#accessing-the-dashboard)
    - [List deployed modules](#list-deployed-modules)
    - [Destroy the Stack](#destroy-the-stack)
7. [CLI Reference](#cli-reference)
8. [Contributing](#contributing)
9. [Credits](#credits)

---

## Overview

#### Key Features

**Modular Service Support**: Configure Melissae to expose between 1 and 5 services simultaneously, allowing for flexible deployment scenarios tailored to your specific security needs. See [contributing](#contributing) if you're interested in developing new modules.  
  
**Centralized Management Dashboard**: Monitor and manage your honeypot through a web-based dashboard, which offers:
- **Statistical Analysis**: Visualize attack patterns, trends, and frequency.
- **Log Search**: Use the Melissae Query Language (MQL), a simple query language (that will be developed more in the future), to perform searches within the captured logs.
- **Logs Export**: Export logs in JSON format, filtered according to specific criteria such as time, service type, IP...
- **Threat Scoring**: Assess attacker danger levels with a built-in scoring system, categorizing threats by severity.
- **STIX 2 Export**: Export Threat Intelligence IOCs as STIX 2.1 indicators (one per IP) directly from the dashboard.
- **Killchain View**: Click any IP in Threat Intelligence to open an attack killchain timeline grouped by protocol with start/end timestamps, ordered from oldest to newest, and jump to full logs from the same pivot.
- **Automated Hygiene**: A nightly purge removes benign IoCs unseen for 24h and their associated logs to keep the dataset lean.

---

## Infrastructure

> [!WARNING]  
> Please use this tool with care, and remember to use it on a dedicated secure server that is properly isolated from your infrastructure.

The infrastructure is fully containerized with docker, and modules can be deployed on demand. The dashboard, the API and MongoDB are always deployed locally. The dashboard is accessible by ssh port forwarding (see [accessing the dashboard](#accessing-the-dashboard) for details).

#### Schema

<img width="1311" height="822" alt="NewDiagram" src="https://github.com/user-attachments/assets/4f1426ef-0354-4c06-93ca-85d9f2aafd53" />


#### File Tree

```bash
-- Melissae
    |-- README.md
    |-- api
    |   |-- api.py
    |   |-- Dockerfile
    |-- dashboard
    |   |-- conf
    |   |   |-- dashboard.conf
    |   |-- css
    |   |   |-- styles.css
    |   |   |-- threat-intel.css
    |   |-- dashboard.html
    |   |-- img
    |   |   |-- favicon.ico
    |   |   |-- logo.png
    |   |-- js
    |   |   |-- backgroundDisplay.js
    |   |   |-- dashboardDisplay.js
    |   |   |-- main.js
    |   |   |-- searchDisplay.js
    |   |   |-- searchEngine.js
    |   |   |-- threatintelDisplay.js
    |   |-- search.html
    |   |-- threat-intel.html
    |-- docker-compose.yml
    |-- melissae.sh
    |-- modules
    |   |-- ftp
    |   |   |-- logs
    |   |       |-- vsftpd.log
    |   |   |-- server
    |   |       |-- ftpuser
    |   |           |-- test.txt
    |   |-- ssh
    |   |   |-- Dockerfile
    |   |   |-- logs
    |   |       |-- commands.log
    |   |       |-- sshd.log
    |   |-- mqtt
    |   |   |-- logs
    |   |       |-- mosquitto.log
    |   |   |-- conf
    |   |       |-- mosquitto.conf
    |   |-- modbus
    |   |   |-- Dockerfile
    |   |   |-- server
    |   |       |-- server.py
    |   |   |-- logs
    |   |       |-- modbus.log
    |    -- web
    |       |-- Dockerfile
    |       |-- conf
    |       |   |-- web.conf
    |       |   |-- proxy.conf
    |       |-- logs
    |       |   |-- access.log
    |       |   |-- error.log
    |       |-- server
    |           |-- index.html
    |-- scripts
      |-- logParser.py
      |-- threatIntel.py
      |-- purgeLogs.py
```

#### Workflow

- Honeypots write raw logs to their volumes.
- `scripts/logParser.py` performs **incremental ingestion**: it keeps per-file offsets/mtimes in Mongo (`ingestion_state`), reads only new log lines, deduplicates with deterministic IDs, and upserts into Mongo (`logs`).
- `scripts/threatIntel.py` computes verdicts and writes into Mongo (`threats`).
- The Flask API in `api/api.py` exposes `/api/logs` and `/api/threats` (loopback + restricted CORS).
- Nginx (dashboard) proxies `/api` and serves the UI; access via basic auth and SSH port-forward.

<img width="1311" height="822" alt="Workflow" src="https://github.com/user-attachments/assets/ef13d9c0-c153-4265-8a4f-7f0245677dbb" />


#### Scheduled jobs

- Every minute: [scripts/logParser.py](scripts/logParser.py) normalizes raw module logs into Mongo `logs`.
- Every minute: [scripts/threatIntel.py](scripts/threatIntel.py) recalculates verdicts into Mongo `threats`.
- Daily at 00:00: [scripts/purgeLogs.py](scripts/purgeLogs.py) removes benign IoCs unseen for 24h and deletes their associated logs.

These cron entries are added by `./melissae.sh install`.

---

## Modules
The choice of modular, containerized deployment means that contributors can easily develop new modules. 
There are currently 5 native honeypot modules and 3 system services. 

**Summary table**

| Type     | Service - Container                               | Port(s)            | Exposure           | Notes |
|----------|--------------------------------------------------|--------------------|--------------------|-------|
| Honeypot | melissae_proxy, melissae_apache1, melissae_apache2 | 80                 | Public             | Web stack via Nginx + Apache |
| Honeypot | melissae_ssh                                     | 22                 | Public             | Weak creds by design |
| Honeypot | melissae_ftp                                     | 21                 | Public             | Weak creds by design |
| Honeypot | melissae_modbus                                  | 502                | Public             | PLC emulation |
| Honeypot | melissae_mqtt                                    | 1883               | Public             | Mosquitto |
| System   | melissae_mongo                                   | 127.0.0.1:27017    | Local      | Data store |
| System   | melissae_api                        | 127.0.0.1:5000     | Local      | Flask API |
| System   | melissae_dashboard                     | 127.0.0.1:9999     | Local      | Dashboard |

#### Web

| Type | Image | Container name|
| :-------------------: | :----------: | :----------: |
| Proxy     | nginx:latest     | melissae_proxy       |
| Web Server             | httpd:2.4-alpine with apache2    | melissae_apache1  |
| Web Server               | httpd:2.4-alpine with apache2     | melissae_apache2       |

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

#### SSH

| Type | Image | Container name|
| :-------------------: | :----------: | :----------: |
| SSH Server            | ubuntu:latest with openssh     | melissae_ssh       |


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
  - You need to modify your module credentials here : `modules/ssh/Dockerfile` (Default : `user:admin`).

#### FTP

| Type | Image | Container name|
| :-------------------: | :----------: | :----------: |
| FTP Server            | fauria/vsftpd     | melissae_ftp      |

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
  - You need to modify your module credentials here : `docker-compose.yml` (Default `ftpuser:ftppass`).

#### Modbus

| Type | Image | Container name|
| :-------------------: | :----------: | :----------: |
| Modbus TCP Server     | python:3.11-slim with custom modbus server | melissae_modbus |

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

#### MQTT

| Type | Image | Container name|
| :-------------------: | :----------: | :----------: |
| Mosquitto Server            | eclipse-mosquitto:latest     | melissae_mqtt     |

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

---

## Threat Intelligence

The Threat Intelligence section of the dashboard provides a simple visual overview of detected threats backed by MongoDB data served from `/api/threats`.  
(Really) basic scoring rules have been implemented, but they are intended to be improved in the future.
See [contributing](#contributing) if you're interested in developing the threat intelligence.

#### Scoring

There are 3 levels of verdicts (Benign, Suspicious, Malicious) with a blended heuristic:

- **Benign**: Default when no important signals are triggered.
- **Suspicious**: Moderate signals such as auth failures, HTTP/MQTT/Modbus reconnaissance, or bursty web hits.
- **Malicious**: Strong signals such as successful SSH/FTP, Modbus writes, sensitive HTTP paths, post-compromise SSH tooling, or combined multi-protocol intrusion patterns.

Each IP also carries a **protocol-score** and a **confidence** value between 0.20 and 1.00. Confidence scales with the number of distinct signals observed.

<img width="1871" height="975" alt="Threat1" src="https://github.com/user-attachments/assets/5c7b1711-0292-489b-afe8-c0e37ffddcf2" />


#### STIX2 Export

- Threat list includes an **Export STIX 2** button.
- Generates a STIX 2.1 bundle with one indicator per IP (`[ipv4-addr:value = '<ip>']`), carrying verdict and score as custom fields.

#### Killchain timeline

- Click any IP in the Threat list to open a killchain panel.
- Events are grouped by protocol and summarized with start/end timestamps to keep long attacks readable.
- Protocol blocks are ordered from oldest to newest using each protocol's last-seen time (or first-seen when only one event exists).
- Quick actions let you jump to the Search view to inspect the same IP's raw logs.

<img width="1865" height="964" alt="Killchain" src="https://github.com/user-attachments/assets/5567c878-35b8-4633-8ac8-8dc0d786e9f5" />


#### Details panel

- In the Threats list, the "Details" button opens a modal showing IP, verdict, score, confidence, timestamps, and the rule reasons from `scripts/threatIntel.py`.

<img width="1868" height="981" alt="Details" src="https://github.com/user-attachments/assets/b60325fe-239b-455b-9e4c-1d120491d036" />


**IoC Format (STIX2)**

```json
{
  "type": "bundle",
  "id": "bundle--f76e87a3-e0eb-4e93-a030-2322cc220176",
  "objects": [
    {
      "type": "identity",
      "spec_version": "2.1",
      "id": "identity--1f4b8511-5ffe-4dae-b00c-360a23d427df",
      "created": "2026-01-07T13:36:58.169Z",
      "modified": "2026-01-07T13:36:58.169Z",
      "name": "Melissae",
      "identity_class": "organization"
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--489ec158-0a7d-402e-be14-515382184c75",
      "created": "2026-01-07T13:36:58.169Z",
      "modified": "2026-01-07T13:36:58.169Z",
      "name": "Melissae IOC X.X.X.X",
      "description": "malicious IP detected on a Melissae honeypot endpoint with a score of 4",
      "labels": [
        "malicious-activity",
        "malicious"
      ],
      "pattern_type": "stix",
      "pattern": "[ipv4-addr:value = 'X.X.X.X']",
      "valid_from": "2026-01-07T13:36:58.169Z",
      "created_by_ref": "identity--1f4b8511-5ffe-4dae-b00c-360a23d427df",
      "x_melissae_verdict": "malicious",
      "x_melissae_score": 4
    }
  ]
}
```

---

## Search Engine

#### Main Features

- **Backed by the API**: Logs are loaded from `/api/logs` (MongoDB).
- **Search with logical operators**: Use operators to combine multiple criteria in your search.
- **Field-specific filters**: Search within specific fields like user, ip, protocol, date, hour, action, user-agent, or path using the syntax field:value.
- **Global search**: If no field is specified, the search applies to all log fields.
- **Export results**: A button allows exporting the filtered logs.

#### Operators

`AND / and`
`OR / or`
`NOT / not / !`

#### Examples

```
user:root and protocol:ssh
ip:192.168.X.X or ip:192.168.X.Y or ip:192.168.X.Z
protocol:http and not action:success
protocol:modbus and action:write
user:admin or not path:/login
!ip:192.168.X.X and action:failed
protocol:modbus and action:read
```

<img width="1864" height="986" alt="Logs1" src="https://github.com/user-attachments/assets/fd4447a1-56f1-4b34-8b66-bbabd1ff6a34" />

<img width="1863" height="976" alt="Logs2" src="https://github.com/user-attachments/assets/c9374c52-56bb-4b62-b68f-d56ac5bff6ee" />


#### Limitations

Currently, the search engine supports only a few operations at a time. See [contributing](#contributing) if you're interested in developing the search engine.

---

## Getting Started

#### Installation

Clone the repository :
`git clone https://github.com/ilostmypassword/Melissae.git`

Give execution rights to the script :

```bash
cd Melissae/
chmod +x melissae.sh
```

Install Melissae :

> [!CAUTION]
> Your SSH port will be modified and given to you at the end of the installation script. Note it carefully.

```bash
./melissae.sh install
```

The installer will prompt you to set dashboard basic-auth credentials (stored hashed with bcrypt in dashboard/conf/htpasswd and). 
Keep these for UI/API access via the dashboard.

It also seeds cron entries for data hygiene: `scripts/logParser.py` and `scripts/threatIntel.py` run every minute, and `scripts/purgeLogs.py` runs daily at 00:00. Adjust with `crontab -e` if you want different cadences.

Add your user in the docker group :

```bash
sudo su
usermod -aG docker your_username
```

> [!IMPORTANT]  
> After adding the user to the docker group, you will likely need to reconnect via SSH using the generated port that was provided to you. You can connect directly with the command provided in "[accessing the Dashboard](#accessing-the-dashboard)".

#### Starting up the stack

Before launching your stack, don't forget to check the modules usage here : [Modules](#modules).

**Start your stack**

```bash
./melissae.sh start [module 1] [module 2] [...]
```

Available modules: `all`, `web`, `ssh`, `ftp`, `modbus`, `mqtt`

Examples:
```bash
# Start all modules
./melissae.sh start all

# Start specific modules
./melissae.sh start web ssh modbus

# Start only Modbus honeypot
./melissae.sh start modbus
```
    
Your stack should now be deployed. The helper script automatically brings up the dashboard, MongoDB and the API alongside any honeypot modules you select.
If you are already connected with the port forwarding activated, your dashboard is accessible on : 

`http://localhost:8080`

If not, see "[Accessing the Dashboard](#accessing-the-dashboard)" to enable SSH port forwarding.

#### Accessing the dashboard

Connect to your server with this command and the newly generated port. 
This command will allow you to forward the dashboard to your localhost (dashboard listens on 127.0.0.1:9999 inside the server; adjust the local port if 8080 is already in use). 

```bash
ssh -L 8080:localhost:9999 user@server -p new_port
```

[Start the stack](#starting-up-the-stack) and access the dashboard in your browser :

`http://localhost:8080/`

Use the credentials you set during installation when prompted by the browser.

<img width="1873" height="978" alt="Dashboard1" src="https://github.com/user-attachments/assets/75eee721-3f96-4376-94c9-0b3b306b8a32" />

<img width="1867" height="979" alt="Dashboard2" src="https://github.com/user-attachments/assets/d4c79418-ed82-44c8-a088-50205e71d92c" />


#### List deployed modules

You can list deployed modules with :

```bash
./melissae.sh list

[*] Honeypot modules

Module       Service                State   
---------------------------------------------
mqtt         melissae_mqtt          ❌     
web          melissae_apache1       ❌     
web          melissae_apache2       ❌     
web          melissae_proxy         ❌     
ssh          melissae_ssh           ✅     
ftp          melissae_ftp           ✅     
modbus       melissae_modbus        ❌     

[*] System modules

Module       Service                State   
---------------------------------------------
mongodb      melissae_mongo         ✅     
api          melissae_api           ✅     
dashboard    melissae_dashboard     ✅
```

#### Destroy the stack

You can destroy your stack easily with :

```bash
./melissae.sh destroy
```
#### CLI reference

- `./melissae.sh install`: Install prerequisites, Docker stack, cron jobs, and dashboard auth.
- `./melissae.sh start [modules]`: Start selected modules (`all`, `web`, `ssh`, `ftp`, `modbus`, `mqtt`).
- `./melissae.sh list`: Show running/deployed modules and status.
- `./melissae.sh destroy`: Stop and remove containers.

---

## Contributing

This project is of course open to contributions, and there are a number of areas of work to be developed. For those who wish to contribute, you can join the discord server :

Discord : https://discord.gg/RXWn85cnYm

Priority Tasks :

 - [x] **Modbus Industrial Honeypot Module** - Complete TCP honeypot with PLC emulation
 - [ ] Improve MQTT module
 - [ ] Develop new modules (SNMP, etc.)
 - [ ] Improve the search engine
 - [ ] Improve the Threat Intel pipeline (enrichment from threat intel feeds for example)
 - [ ] Develop multi-instance capabilities
 - [ ] Build a lightweight rules UI to tune thresholds (HTTP burst, auth failures, Modbus writes) without redeploying.

---

## Credits

Thank you to all contributors for helping the project move forward.

- summoningshells (https://github.com/summoningshells)
