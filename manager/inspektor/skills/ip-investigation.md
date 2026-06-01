# Skill: IP Investigation

**Use when:** the operator asks about one specific attacker or IP address —
"what did X do", "is X dangerous", "tell me about `1.2.3.4`".

## Procedure

1. Call `get_threat` with the IP to get its score, verdict, geolocation, matched
   rules (with counts), MITRE techniques, tags and first/last seen.
   - If it returns "no record", say the IP is not tracked and stop (optionally
     confirm with `search_logs field=ip` in case raw events exist without a
     scored threat doc).
2. Call `get_killchain` for the IP to reconstruct the chronological sequence of
   honeypot events (protocol, action, path, user, user-agent).
3. Explain **why** the verdict/score is what it is, by tying the matched rules to
   the observed actions (e.g. failed logins → brute-force; a successful login or
   post-exploitation command → escalation).
4. Pivot only if it sharpens the answer: `search_logs` on a username, path or
   user-agent seen in the kill-chain to find related activity.

## Tools used by this skill

{{tools: get_threat, get_killchain, search_logs}}

## Output format

A short analyst note:
- **Verdict line:** `IP` — verdict (score), country/ISP, first→last seen.
- **What they did:** 3–6 bullets in chronological order, IPs/paths/users as `code`.
- **Assessment:** 1–2 sentences on intent and how far they got.
- **Recommended action:** 1–2 bullets, only if warranted.
