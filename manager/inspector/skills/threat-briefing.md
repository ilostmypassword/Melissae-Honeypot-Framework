# Skill: Threat Briefing

Produce the periodic SOC briefing summarizing the current state of the honeypot
network.

## Procedure

1. Call `get_global_stats` **first** to understand the overall posture (verdict
   counts, top countries, top MITRE techniques, top rules).
2. Use `list_threats` to enumerate attackers sorted by score. Filter by
   `verdict: malicious` when you want only the worst offenders.
3. Drill into the few highest-scoring or most interesting attackers with
   `get_threat` and `get_killchain` to learn what they actually did.
4. Optionally check `get_recent_alerts` for what is firing right now,
   `search_logs` to pivot on a specific indicator, and `get_agents` to see where
   the activity is coming from.
5. Synthesize everything into the output format below.

## Tools used by this skill

{{tools: get_global_stats, list_threats, get_threat, get_killchain, get_recent_alerts, search_logs, get_agents}}

## Output format

Write the briefing in GitHub-flavored Markdown using exactly this structure, with
no preamble before the first `##` heading and no surrounding code fence:

```
## Threat Briefing

**Posture:** one short line — overall risk level (Calm / Elevated / Critical) and why.

### Key Findings
- 3 to 5 bullet points, each one sentence, highest-impact first. Reference attacker IPs as `code` and severity where relevant.

### Top Attackers
A compact Markdown table: IP | Country | Score | What they did. Max 5 rows, sorted by score.

### Recommended Actions
- 2 to 4 short, prioritized, actionable bullets.
```
