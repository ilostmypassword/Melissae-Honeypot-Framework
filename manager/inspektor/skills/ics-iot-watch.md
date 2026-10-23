# Skill: ICS and IoT Watch

**Use when:** the operator asks about industrial or IoT activity — Modbus, MQTT,
Telnet botnets, "any ICS tampering", "who wrote to the PLC", "MQTT abuse".

## Procedure

1. Call `get_log_overview` to see how much `modbus`, `mqtt` and `telnet` traffic
   exists and which agents carry it. No events on these protocols means the
   sensors are quiet there; say so.
2. Call `get_recent_alerts` and keep the relevant rules: MLS007 (Modbus write),
   MLS014 (MQTT publish / wildcard subscribe), MLS001 / MLS011 / MLS013 (Telnet).
3. For the protocol of interest, call `search_logs` with `field: protocol` and
   the protocol name. Read the `action` text yourself:
   * Modbus: write functions are tampering; reads are reconnaissance.
   * MQTT: `Publish to ...` is tampering; `Subscribe to "#"` or other wildcards
     enumerate every topic; plain connects are scanning.
   * Telnet: repeated failed logins then a success and a downloader command is
     the classic IoT-botnet infection chain.
4. Drill into the one to three IPs doing writes, publishes or post-login commands
   with `get_threat` and `get_killchain`.
5. Judge impact: a write or publish against a decoy is intent to alter a process;
   say what the attacker tried to change, never that something real was altered.

## Tools used by this skill

{{tools: get_log_overview, get_recent_alerts, search_logs, get_threat, get_killchain}}

## Output format

* **Exposure line:** events per ICS/IoT protocol and which agents saw them.
* **Findings:** table `IP | Protocol | What they did | Rule | Severity`.
* **Assessment:** 1 to 2 sentences on intent (recon, tampering, botnet infection).
* **Recommended action:** 1 to 2 bullets, only if warranted.
