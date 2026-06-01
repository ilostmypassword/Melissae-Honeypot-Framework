# Skill: Agent Health

**Use when:** the operator asks about the sensor fleet — agents, coverage, where
activity comes from, which honeypots are up, "is everything reporting".

## Procedure

1. Call `get_agents` to list registered sensors with their `status`, `last_seen`,
   `host`, and enabled `modules`.
2. Flag any agent that is not `healthy` or whose `last_seen` is stale — those are
   the real reporting blind spots.
3. Call `get_log_overview` to see, per agent (`by_agent`), how much traffic each
   sensor has actually captured. **Judge "silent" from this, never from
   `threats`:** an agent can be `healthy` and busy in `logs` while having zero
   scored threats. Only an agent with no log events is genuinely silent.
4. If asked specifically what one agent has seen, confirm with
   `search_logs` (`field: agent_id`, `value: <name>`) before concluding.
5. Relate coverage to activity: enabled `modules` tell you what an agent *can*
   catch; the per-agent log counts tell you what it *did*. A healthy agent with
   zero events may signal an exposure/reachability gap rather than calm.

## Tools used by this skill

{{tools: get_agents, get_log_overview, search_logs, get_global_stats}}

## Output format

- **Fleet line:** N agents, how many healthy vs degraded/offline.
- **Per-agent table:** Agent | Host | Status | Last seen | Modules | Events seen.
  Highlight unhealthy or stale rows, and any healthy agent with zero events.
- **Coverage note:** 1–2 sentences on gaps. Distinguish "not reporting" (health
  problem) from "reporting but no scored threats" (normal lag) from "healthy but
  zero events" (possible exposure gap).
