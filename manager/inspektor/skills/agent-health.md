# Skill: Agent Health

**Use when:** the operator asks about the sensor fleet — agents, coverage, where
activity comes from, which honeypots are up, "is everything reporting".

## Procedure

1. Call `get_agents` to list registered sensors with their `status`, `last_seen`,
   `host`, and enabled `modules`.
2. Flag any agent that is not `healthy` or whose `last_seen` is stale — those are
   blind spots in coverage.
3. Relate coverage to activity when relevant: which modules are enabled tells you
   what an agent *can* catch. If asked where attacks originate, combine with
   `get_global_stats` (top countries) and note which agents are busiest via the
   `agents` field on threats.

## Tools used by this skill

{{tools: get_agents, get_global_stats}}

## Output format

- **Fleet line:** N agents, how many healthy vs degraded/offline.
- **Per-agent table:** Agent | Host | Status | Last seen | Modules. Highlight
  unhealthy or stale rows.
- **Coverage note:** 1–2 sentences on gaps or where activity concentrates.
