# Skill: Attacker Ranking

**Use when:** the operator asks to compare or rank attackers — "top / worst
attackers", "most active IPs", "who should I worry about", "show malicious IPs".

## Procedure

1. **In one batch**, call `get_global_stats` (denominator: IPs per verdict, top
   countries/rules) and `list_threats` with the relevant `verdict` filter
   (`malicious` for the worst; omit it for an overall top-N). `list_threats` comes
   pre-sorted by score, highest first.
2. Only for the few IPs you will actually present, call `get_threat` to name the
   rules and MITRE techniques that drove each score. Batch these together; don't
   pull records for IPs you won't rank.
3. Rank by score, but call out qualitative differences — a `malicious` IP with a
   successful login or CVE hit outranks one that only brute-forced.

## Tools used by this skill

{{tools: get_global_stats, list_threats, get_threat}}

## Output format

A compact ranked table sorted by score descending:
`# | IP | Country | Score | Verdict | Why it ranks (rules / actions)`.
Keep to the number requested (default top 5–10). Add one closing sentence on the
overall picture (e.g. concentration by country or by attack type).
