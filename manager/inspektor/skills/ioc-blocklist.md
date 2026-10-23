# Skill: IOC Blocklist

**Use when:** the operator wants something to block or share — "give me a
blocklist", "IPs to ban", "export the malicious IPs", "what should I put in the
firewall".

## Procedure

1. Call `list_threats` with `verdict: malicious` and a generous `limit` (up to
   100). Sorted by score, highest first.
2. If the operator wants a wider list, add `verdict: suspicious` in a second
   call and keep the two tiers separate.
3. Only for borderline cases or when asked why, call `get_threat` on a few IPs;
   do not query every IP.
4. Exclude nothing silently: if the list was capped at the tool limit, say so.
5. Remind the operator to review before enforcing: honeypot data is reliable for
   "this IP touched a decoy", but shared NAT, cloud or research-scanner ranges
   may warrant monitoring rather than blocking.

## Tools used by this skill

{{tools: list_threats, get_threat}}

## Output format

* **Count line:** how many malicious (and suspicious) IPs, and whether capped.
* **Block tier (malicious):** a plain code block, one IP per line, highest score
  first.
* **Watch tier (suspicious):** same format, only when requested.
* **Caveat:** one sentence on reviewing before enforcement.
