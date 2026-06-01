# Skill: Threat Briefing

**Use when:** the operator asks for a report, briefing, summary, or overall
"state of the network" — this is the skill behind the *Generate report* button.

## Procedure

1. Call `get_global_stats` **first** for posture: verdict counts, top countries,
   top MITRE techniques, top rules.
2. Call `list_threats` with `verdict: malicious` to get the worst offenders by
   score; if there are few or none, widen to `suspicious`.
3. Drill into the 2–4 highest-scoring or most interesting attackers with
   `get_threat` (why they scored) and, when it adds insight, `get_killchain`
   (what they actually did, step by step).
4. Optionally call `get_recent_alerts` for what is firing right now and
   `get_agents` to note where activity concentrates.
5. Synthesize into the output format below. If `get_global_stats` shows zero
   tracked IPs, return the *quiet network* variant instead of inventing content.

## Tools used by this skill

{{tools: get_global_stats, list_threats, get_threat, get_killchain, get_recent_alerts, get_agents}}

## Output format

GitHub-flavored Markdown, no preamble before the first `##` heading, no code
fence around it:

```
## Threat Briefing

**Posture:** one line — overall risk level (Calm / Elevated / Critical) and why.

### Key Findings
- 3–5 bullets, one sentence each, highest-impact first. Reference IPs as `code`, cite scores/verdicts and rule ids where relevant.

### Top Attackers
Compact table: IP | Country | Score | What they did. Max 5 rows, sorted by score descending.

### Recommended Actions
- 2–4 short, prioritized, actionable bullets.
```

Quiet network: keep the `## Threat Briefing` heading, set **Posture: Calm**, and
state plainly that no attacker activity is currently tracked. Do not fabricate
attackers or actions.
