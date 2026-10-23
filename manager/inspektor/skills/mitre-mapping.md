# Skill: MITRE Mapping

**Use when:** the operator asks about MITRE ATT&CK — "which techniques are we
seeing", "map this attacker to ATT&CK", "what tactics are covered", "coverage
gaps".

## Procedure

1. Call `get_global_stats` for the most frequent techniques (`top_mitre`) and the
   rules driving them (`top_rules`).
2. For one named IP, call `get_threat` and read its `mitre` list and matched
   `rules`; add `get_killchain` only when the operator wants the techniques tied
   to concrete actions.
3. Group the technique IDs by tactic using standard ATT&CK knowledge:
   * **Reconnaissance / Discovery:** T1595, T1046, T1083
   * **Initial Access:** T1190, T1078
   * **Execution:** T1059
   * **Credential Access:** T1110
   * **Command and Control / Transfer:** T1105
   * **Impact:** T1565; ICS techniques `T08xx` (e.g. T0831, T0836)
   Report only techniques that appear in the data. Do not add techniques the
   rules did not tag.
4. Order the tactics along the attack lifecycle to show how far attackers got:
   reconnaissance only, access gained, execution, or ICS/IoT impact.
5. For "gaps", compare the tactics present with the protocols the sensors cover
   (use `get_log_overview`): activity on a protocol with no technique tagged
   suggests a missing detection rule, not a missing attacker.

## Tools used by this skill

{{tools: get_global_stats, get_threat, get_killchain, get_log_overview}}

## Output format

* **Summary line:** number of distinct techniques and the furthest tactic reached.
* **Table:** `Tactic | Technique | Seen via rule | IPs/count`.
* **Reading:** 1 to 2 sentences on the attack lifecycle position.
* **Gaps:** only when a covered protocol shows activity with no mapped technique.
