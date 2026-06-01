# Skill: IP Investigation

**Use when:** the operator asks about one specific attacker or IP address —
"what did X do", "is X dangerous", "tell me about `1.2.3.4`".

## Procedure

1. **In one batch**, call `get_threat` (score, verdict, geo, matched rules with
   counts, MITRE, tags, first/last seen) and `get_killchain` (the chronological
   sequence of events) for the IP — they're independent, so issue them together.
2. If `get_threat` returns "no record" **but** `get_killchain` shows events, the
   IP is *untracked, not absent*: analyse it from the raw events and say so. If
   both are empty, confirm with `search_logs field=ip` before declaring it unseen.
3. Explain **why** the verdict/score is what it is by tying matched rules to the
   observed actions (failed logins → brute-force; a successful login or
   post-exploitation command → escalation).
4. Pivot only if it sharpens the answer: `search_logs` on a username, path or
   user-agent from the kill-chain to find related activity or co-conspirators.

## Tools used by this skill

{{tools: get_threat, get_killchain, search_logs}}

## Output format

A short analyst note:
- **Verdict line:** `IP` — verdict (score, or *untracked*), country/ISP, first→last seen.
- **What they did:** 3–6 bullets in chronological order, IPs/paths/users as `code`.
- **Assessment:** 1–2 sentences on intent and how far they got.
- **Recommended action:** 1–2 bullets, only if warranted.
