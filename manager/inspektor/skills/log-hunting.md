# Skill: Log Hunting

**Use when:** the operator wants to pivot on a specific indicator across raw logs
— a username, a URL path, a user-agent, a protocol, or an agent — e.g. "who tried
the user `root`", "any hits on `/admin`", "show modbus activity".

## Procedure

1. Map the request to one searchable field. `search_logs` matches **one exact
   field/value** at a time; allowed fields are: `ip`, `protocol`, `action`,
   `path`, `user`, `user-agent`, `agent_id`.
2. Call `search_logs` with that field/value and a `limit` (default 25, max 100).
   Matches return newest-first with timestamp, ip, protocol, action, path, user,
   user-agent, agent_id.
3. Aggregate the result yourself: count distinct source IPs, time span, and which
   agents saw it. Identify whether it is one actor or a broad campaign.
4. Escalate the most relevant IP(s): `get_threat` for their score/verdict, and
   `get_killchain` to see the full sequence around the indicator.

## Tools used by this skill

{{tools: search_logs, get_threat, get_killchain}}

## Notes

- Only the fields above are searchable. If asked for something outside them (free
  text, payload contents), explain the limitation and pivot to the closest field.
- Report exact counts; never estimate beyond what the logs returned.

## Output format

- **Query line:** the field/value you searched.
- **Findings:** distinct IPs, time range, agents involved — as bullets or a small table.
- **Notable actors:** the IP(s) worth a closer look, with verdict/score.
