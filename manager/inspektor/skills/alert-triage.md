# Skill: Alert Triage

**Use when:** the operator asks what is firing right now, about recent alerts, or
about a specific detection rule (e.g. "any criticals lately?", "what fired in the
last hour", "explain MLS009 hits").

## Procedure

1. Call `get_recent_alerts` (raise `limit` for a broad window) for the latest
   firings: rule id/name, severity, score, IP, agent, MITRE, time.
2. Group by **rule** and **severity**; surface the IPs behind the most severe or
   most repeated alerts.
3. For the noteworthy IPs only, drill in one batch: `get_threat` for cumulative
   score/verdict/other rules, and `get_killchain` if the operator wants the
   underlying actions.
4. Separate signal from noise: low-severity scans (MLS005/MLS006/MLS012) are
   background; prioritize critical rules (successful logins, post-exploitation,
   CVE, ICS writes).

## Tools used by this skill

{{tools: get_recent_alerts, get_threat, get_killchain}}

## Output format

- **Summary line:** how many alerts, over what window, how many critical.
- **By severity / rule:** a compact table or bullets — Rule | Count | Top IP(s) | Severity.
- **Worth attention:** 1–3 bullets on the alerts that matter and why.
