# Skill: Attacker Ranking

**Use when:** the operator asks to compare or rank attackers — "top / worst
attackers", "most active IPs", "who should I worry about", "show malicious IPs".

## Procedure

1. Call `get_global_stats` for context (how many IPs per verdict, top countries
   and rules) so your ranking has a denominator.
2. Call `list_threats` with the relevant `verdict` filter (`malicious` for the
   worst, omit the filter for an overall top-N) and a sensible `limit`. Results
   come pre-sorted by score, highest first.
3. For any IP whose ranking needs justification, call `get_threat` to name the
   specific rules and MITRE techniques that drove its score. Do this only for the
   few you actually present.
4. Rank by score, but call out qualitative differences (a `malicious` IP that got
   a successful login or CVE hit outranks one that only brute-forced).

## Tools used by this skill

{{tools: get_global_stats, list_threats, get_threat}}

## Output format

A compact ranked table sorted by score descending:
`# | IP | Country | Score | Verdict | Why it ranks (rules / actions)`.
Keep to the number requested (default top 5–10). Add one closing sentence on the
overall picture (e.g. concentration by country or by attack type).
