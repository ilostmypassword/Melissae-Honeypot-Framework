# Melissae Honeypot Framework

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
  <img src="https://img.shields.io/badge/Nginx-mTLS-009639?style=flat-square&logo=nginx&logoColor=white" alt="Nginx mTLS" />
  <img src="https://img.shields.io/badge/Python-3-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/mTLS-ECDSA%20P--384-FF6F00?style=flat-square&logo=letsencrypt&logoColor=white" alt="mTLS" />
</p>

---

<p align="center">
  <a href="https://melissae-documentation.readthedocs.io"><strong>📖 Documentation</strong></a> &nbsp;·&nbsp; <a href="https://discord.gg/RXWn85cnYm"><strong>💬 Discord</strong></a>
</p>

---

Melissae is a distributed, modular honeypot framework designed to emulate real-world network services and collect intelligence on attacker behavior. It follows a **manager/agent architecture** where lightweight agents deploy containerized honeypot modules across multiple machines, while a central manager aggregates, scores, and visualizes all captured data.

All communications between agents and the manager are authenticated and encrypted using **mutual TLS (mTLS)** with an embedded PKI based on ECDSA P-384 certificates. Agent enrollment is handled through one-time tokens. Each agent parses logs locally, buffers them in SQLite, and pushes normalized JSON to the manager over the secured channel.

The framework ships with **7 honeypot modules** : Web (Nginx + Apache), SSH, FTP, Modbus/ICS, MQTT, Telnet. As well as **CVE-specific modules** that reproduce real vulnerabilities to detect targeted exploitation. Modules run in isolated Docker containers and can be enabled or disabled per agent through the interactive CLI or the configuration file.

On the manager side, a **continuous scoring engine** evaluates each observed IP on a 0–100 scale using weighted signals (brute-force attempts, successful logins, post-exploitation commands, ICS write operations, CVE exploitation) combined with a multi-factor confidence model. Results are exposed through an interactive **React dashboard** offering real-time statistics, trend detection, a GeoIP attack map, a log search engine with logical operators, agent health monitoring, and STIX 2.1 IOC export.

<br>

<details open>
<summary><strong>📊 Overview Dashboard</strong></summary>
<br>
<p align="center">
  <img width="720" alt="Dashboard overview" src="https://github.com/user-attachments/assets/24b1101b-5360-4166-9c74-b13c459568aa" />
</p>
</details>

<details>
<summary><strong>📈 Statistics & Charts</strong></summary>
<br>
<p align="center">
  <img width="720" alt="Dashboard statistics" src="https://github.com/user-attachments/assets/2eda0491-d2b4-4ffc-bc5f-0060878f03d3" />
</p>
</details>

<details>
<summary><strong>🖥️ Agents Management</strong></summary>
<br>
<p align="center">
  <img width="720" alt="Agents page" src="https://github.com/user-attachments/assets/c7d6bc68-8f2f-43bf-8bda-0c33e50d95ea" />
</p>
</details>

<details>
<summary><strong>🌍 GeoIP Attack Map</strong></summary>
<br>
<p align="center">
  <img width="720" alt="GeoIP map" src="https://github.com/user-attachments/assets/7032151e-829c-428c-a9ff-621cb7fdc41b" />
</p>
</details>

<details>
<summary><strong>🔎 Search Engine</strong></summary>
<br>
<p align="center">
  <img width="720" alt="Search engine" src="https://github.com/user-attachments/assets/88e8264a-9316-4cbe-8680-5d145729c5a1" />
</p>
</details>

<details>
<summary><strong>🎯 Threat Intelligence</strong></summary>
<br>
<p align="center">
  <img width="720" alt="Threat intelligence" src="https://github.com/user-attachments/assets/71742a97-e00b-4cbb-b938-8578c7612f49" />
</p>
</details>

---

## Quick Start

**Manager Installation**
```bash
$ git clone https://github.com/ilostmypassword/Melissae.git
$ cd Melissae/manager/ && chmod +x melissae-manager.sh
$ ./melissae-manager.sh
$ manager [0 active] > install

# Add your user to the docker group and reconnect to your server with the new ssh port, then :

$ manager [0 active] > start
$ manager [3 active] > enroll my-agent <agent-ip>
```

**Agent Installation**
> [!IMPORTANT]  
> Deploy agents on dedicated servers, properly isolated from your production infrastructure.
```bash
$ git clone https://github.com/ilostmypassword/Melissae.git
$ cd Melissae/agent/ && chmod +x melissae-agent.sh
$ ./melissae-agent.sh
$ agent:? [0 active] > install https://<manager-ip>:8443 <token>

# Add your user to the docker group and reconnect to your server with the new ssh port, then :

$ agent:my-agent [0 active] > list # To list modules
$ agent:my-agent [0 active] > enable/disable <module> # To configure modules
$ agent:my-agent [0 active] > start
```

**Full installation guide [**here**](https://melissae-documentation.readthedocs.io/en/latest/getting-started.html).**

**Accessing the Dashboard**
```
https://<manager-ip>
```
---

## Documentation

The complete documentation is hosted on Read the Docs.

| | Section | |
|:---:|---------|---------|
| 📋 | [Overview](https://melissae-documentation.readthedocs.io/en/latest/overview.html) | Features, capabilities, and screenshots |
| 🏗️ | [Architecture](https://melissae-documentation.readthedocs.io/en/latest/architecture.html) | Manager/agent model, mTLS, PKI, workflow |
| 📦 | [Modules](https://melissae-documentation.readthedocs.io/en/latest/modules.html) | Honeypot modules, log formats, configuration |
| 📊 | [Dashboard](https://melissae-documentation.readthedocs.io/en/latest/dashboard.html) | Dashboard pages, search engine, threat intelligence |
| 🎯 | [Scoring](https://melissae-documentation.readthedocs.io/en/latest/scoring.html) | Threat scoring signals, verdicts, confidence |
| 🚀 | [Getting Started](https://melissae-documentation.readthedocs.io/en/latest/getting-started.html) | Installation, enrollment, configuration |
| ⌨️ | [CLI Reference](https://melissae-documentation.readthedocs.io/en/latest/cli-reference.html) | Manager and agent commands |
| 🔒 | [Security](https://melissae-documentation.readthedocs.io/en/latest/security.html) | Defense-in-depth measures |
| 🤝 | [Contributing](https://melissae-documentation.readthedocs.io/en/latest/contributing.html) | Roadmap and how to contribute |

---

## Contributing

This project is open to contributions. Join the Discord to get involved:

[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?style=flat-square&logo=discord&logoColor=white)](https://discord.gg/RXWn85cnYm)

## Credits

- [summoningshells](https://github.com/summoningshells)

