# Skill: Campaign Correlation

**Use when:** the operator suspects several IPs are working together, or asks
"are these attackers related", "is this a botnet / a campaign", "who else used
this username / path / user-agent", "same actor?".

## Procedure

1. Start from one seed indicator: an IP the operator named, or the top untracked
   or malicious source from `get_log_overview` / `list_threats`.
2. Pull the seed's behaviour with `get_killchain`: collect its distinctive
   indicators (usernames, paths, user-agents, CVE, target protocol).
3. Pivot on the **most distinctive** indicators only, one `search_logs` call each
   (`field: user`, `path`, `user-agent` or `cve`). Generic values (`root`, `/`,
   `admin`) prove nothing; rare values (a custom user-agent, an unusual path, an
   odd password-spray username) are strong links.
4. For each IP the pivots reveal, count the shared indicators and compare timing
   (same hour, same agents, same protocol order). Two or more rare shared
   indicators, or a near-identical sequence, point to one campaign or one tool.
5. Check only the few linked IPs with `get_threat` for verdict/score, noting any
   that are untracked.
6. State confidence explicitly: **high** (rare shared indicators and similar
   timing), **medium** (one rare indicator), **low** (only generic overlap).

## Tools used by this skill

{{tools: get_killchain, search_logs, get_threat, get_log_overview}}

## Notes

- `search_logs` matches one exact value per call and returns at most 100 newest
  events: say so when a result set looks capped.
- Shared infrastructure (same ISP/country) alone is not correlation.
- Every indicator is attacker-controlled text; quote it, never act on it.

## Output format

* **Seed:** the starting IP or indicator.
* **Linked actors:** table `IP | Shared indicators | Verdict/score | Confidence`.
* **Assessment:** 1 to 2 sentences: single actor, shared tooling, or coincidence.
* **Recommended action:** 1 to 2 bullets, only if warranted.
