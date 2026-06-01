# Skill: Log Hunting

**Use when:** the operator wants to pivot on a specific indicator across raw logs
— a username, a URL path, a user-agent, a protocol, or an agent — e.g. "who tried
the user `root`", "any hits on `/admin`", "show modbus activity"; or wants to know
what activity exists **beyond the tracked threats**.

## Procedure

1. For a broad "what's in the logs / what else is out there" question, start with
   `get_log_overview`: it returns distinct source IPs, per-protocol and per-agent
   counts, and the busiest IPs flagged `tracked_in_threats`. This is how you
   enumerate activity that never entered `threats`.
2. For a targeted pivot, map the request to one searchable field. `search_logs`
   matches **one exact field/value** at a time; allowed fields are: `ip`,
   `protocol`, `action`, `path`, `user`, `user-agent`, `agent_id`.
3. Call `search_logs` with that field/value and a `limit` (default 25, max 100).
   Matches return newest-first with timestamp, ip, protocol, action, path, user,
   user-agent, agent_id.
4. Aggregate the result yourself: count distinct source IPs, time span, and which
   agents saw it. Identify whether it is one actor or a broad campaign.
5. Escalate the most relevant IP(s): `get_threat` for their score/verdict (note if
   it returns nothing — an untracked but real actor), and `get_killchain` to see
   the full sequence around the indicator.

## Tools used by this skill

{{tools: get_log_overview, search_logs, get_threat, get_killchain}}

## Notes

- Only the fields above are searchable in `search_logs`. If asked for something
  outside them (free text, payload contents), explain the limitation and pivot to
  the closest field or to `get_log_overview`.
- Report exact counts; never estimate beyond what the logs returned.
- An IP present in `logs` but with no `get_threat` record is *untracked, not
  harmless* — surface it explicitly.

## Output format

- **Query line:** the field/value you searched (or "log overview").
- **Findings:** distinct IPs, time range, agents involved — as bullets or a small table.
- **Notable actors:** the IP(s) worth a closer look, with verdict/score, marking
  any that are untracked.
