# Contributing to Melissae

Thanks for helping the hive grow. This guide explains what we need, how the project is organised, and how to get a change merged.

**Discord**: [Join the server](https://discord.gg/RXWn85cnYm) — the best place to discuss ideas before opening a PR.
**Documentation**: [melissae-documentation.readthedocs.io](https://melissae-documentation.readthedocs.io)

---

## Ways to Contribute

| Area | Examples |
|------|----------|
| Honeypot modules | New protocols, CVE-specific decoys, better log parsing |
| Detection rules | New YAML rules in `rules/`, tuning scores and thresholds |
| Dashboard | React/Tailwind pages and components in `manager/dashboard/` |
| Inspektor AI | Skills, prompts and tools in `manager/inspektor/` |
| Documentation | README, this guide, the ReadTheDocs site |
| Bug reports | Reproducible issues with logs and steps |

## Roadmap

These are the open priorities for the next releases. Comment on (or open) an issue before starting one so work is not duplicated.

| Area | Task |
|------|------|
| Modules | Improve MQTT log parsing |
| Modules | New CVE modules |
| Modules | SNMP honeypot |
| Analysis | Behavioral clustering |
| Deception | Adaptive honeypot responses |
| Dashboard | Rules UI for scoring thresholds |

---

## Project Layout

| Path | What lives there |
|------|------------------|
| `manager/` | The hive: API (Flask), dashboard (React/Vite), scoring scripts, Inspektor, `melissae-manager.sh` |
| `manager/api/` | REST API used by the dashboard and agents |
| `manager/scripts/` | Rule engine, threat intel, MQL search, log purge |
| `manager/dashboard/` | Web UI (`npm run dev` / `npm run build`) |
| `manager/inspektor/` | AI analyst: `skills/`, `prompts/`, `tools.py` |
| `agent/` | Agent daemon, `docker-compose.yml`, `melissae-agent.sh` |
| `modules/` | One folder per honeypot module (Dockerfile, config, logs) |
| `rules/` | YAML detection rules (`MLSxxx.yml`) loaded by the rule engine |

## Development Setup

Follow the [Quick Start](README.md#quick-start) to run a manager and at least one agent. Use dedicated, isolated machines or VMs for agents: they are meant to be attacked.

To iterate on the dashboard without rebuilding the containers:

```bash
cd manager/dashboard
npm install
npm run dev
```

The Vite dev server proxies `/api` to `http://localhost:5000`, so the API must be reachable there.

## Adding Things

### A honeypot module

1. Create `modules/<name>/` with its `Dockerfile` (and config if needed); write logs under `logs/`.
2. Add the service to `agent/docker-compose.yml` (container name `melissae_<name>`).
3. Register it in `MODULE_REGISTRY` in `agent/melissae-agent.sh` (`name|service|port|description`).
4. Make sure its logs are collected and parsed by the manager, and show up in the dashboard search.

### A detection rule

Add `rules/MLSxxx.yml` using the next free id. Follow the existing rules:

```yaml
id: MLS015
name: Short human-readable name
description: >
  What the rule detects and why it matters.
severity: low | medium | high | critical
enabled: true
schedule: "*/1 * * * *"
lookback: 1m
mql: 'protocol:ssh AND action:Failed'
group_by: ip
threshold: 10
score: 40
tags: [bruteforce, ssh]
mitre: [T1110]
```

Check that the MQL query returns the expected events in the dashboard search before submitting.

### An Inspektor skill

Add a Markdown file in `manager/inspektor/skills/` following the existing ones: **Use when**, **Procedure**, **Tools used by this skill** and **Output format**.

---

## Issues

Use the issue templates. Titles start with a prefix:

| Prefix | Use for |
|--------|---------|
| `[BUG]` | Something broken — include steps, logs and versions |
| `[FEAT]` | A new feature or improvement |
| `[DOC]` | Missing or wrong documentation |

For large changes, open an issue first to align on the approach.

## Pull Request Process

1. Fork the repository and branch off `v2.8`, named after the type and issue: `feat/54-pdf-report`, `fix/61-agent-enroll`, `doc/57-contributing`.
2. Keep commits small and focused, with a short imperative message that references the issue, e.g. `Improve PDF report formatting (#54)`.
3. Test end-to-end: install, enroll an agent, enable the module, check the dashboard.
4. Open a PR against `v2.8` that includes:
   - what changed and the linked issue (`Closes #<number>`)
   - for modules: the protocol/port used and a sample log entry
   - for UI changes: a screenshot
5. Address review comments; a maintainer merges once it is approved.

## Code of Conduct

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report security vulnerabilities as described in [SECURITY.md](SECURITY.md), not in public issues.
