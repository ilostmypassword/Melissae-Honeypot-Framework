# Skill: Threat Briefing

**Use when:** the operator asks for a report, briefing, summary, or overall
"state of the network" — this is the skill behind the *Generate report* button.

## Procedure

1. Call `get_global_stats` **first** for posture: verdict counts, top countries,
   top MITRE techniques, top rules.
2. Call `get_log_overview` **next, always** — this is the ground truth. It tells
   you how many *distinct source IPs* the sensors actually saw, how many are not
   yet scored (`untracked_source_ips`), the per-protocol and per-agent breakdown,
   and the busiest IPs (each flagged `tracked_in_threats`). A briefing that reads
   `threats` only is wrong whenever the pipeline lags. Never describe overall
   activity or call an agent "silent" without this.
3. Call `list_threats` with `verdict: malicious` to get the worst *scored*
   offenders; if there are few or none, widen to `suspicious`.
4. Drill into the 2–4 highest-scoring or most interesting attackers with
   `get_threat` (why they scored) and, when it adds insight, `get_killchain`
   (what they actually did, step by step).
5. If `get_log_overview` shows notable **untracked** sources (e.g. an SSH
   brute-forcer or a probing scanner with `tracked_in_threats: false`), pivot on
   the most serious one with `search_logs` (`field: ip`) and surface it — these
   are the blind spots a `threats`-only briefing misses.
6. Optionally call `get_recent_alerts` for what is firing right now. Use
   `get_agents` for health, but judge whether an agent is busy from
   `get_log_overview`'s per-agent counts, **not** from `threats`.
7. Synthesize into the output format below. Treat the network as *quiet* only when
   **`get_log_overview` reports no events** — not merely when `threats` is empty.

## Tools used by this skill

{{tools: get_global_stats, get_log_overview, list_threats, get_threat, get_killchain, get_recent_alerts, search_logs, get_agents}}

## Output format

GitHub-flavored Markdown, no preamble before the first `##` heading, no code
fence around it. This briefing is exported to PDF: **plain text only — no emoji,
no country flags, no icon glyphs** (they render as garbage). Name countries in
words. Do **not** narrate your process (no "composing the briefing", "I have the
data"); the only allowed lead-in is the single atmospheric line.

```
## Threat Briefing

**Posture:** one line stating the overall risk level (Calm, Elevated, or
Critical) and why.

### Key Findings
* 3 to 5 bullets, one sentence each, highest-impact first. Use `*` markers. Wrap IPs, rule ids and verdicts in `code`. State both the tracked threats and the wider log picture (distinct sources seen, untracked activity) when they differ.

### Top Attackers
Compact table: `IP | Country | Score | What they did`. Lead with scored threats; include serious untracked sources, marking their score as `untracked` rather than inventing one. Max 5 rows.

### Untracked / Emerging Activity
Only when `get_log_overview` shows sources not in `threats`: a short `*` bullet list of the notable ones (IP, protocol, agent, what they did) so coverage gaps and scoring lag are visible. Omit this section if there is none.

### Recommended Actions
1. 2 to 4 short, prioritized, actionable items as a numbered list.
```

Quiet network: only if `get_log_overview` reports zero events. Keep the
`## Threat Briefing` heading, set **Posture: Calm**, and state plainly that no
activity is currently observed. Do not fabricate attackers or actions. If `logs`
hold events but `threats` is empty, that is **not** a quiet network — report the
log activity and note it has not yet been scored.
