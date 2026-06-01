from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from langchain_core.tools import tool
from pymongo.database import Database
from pymongo.errors import PyMongoError

DB: Optional[Database] = None
KILLCHAIN_LIMIT: int = 200

_VALID_VERDICTS = {"malicious", "suspicious", "benign"}
_ALLOWED_LOG_FIELDS = {
    "ip", "protocol", "action", "path", "user", "user-agent", "agent_id",
}
_MAX_LIST = 100


def _as_json(value) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


# --------------------------------------------------------------------------- #
# Tool calls
# --------------------------------------------------------------------------- #

@tool
def get_global_stats() -> str:
    """Return an overview of the current threat landscape: total tracked IPs,
    counts per verdict (malicious/suspicious/benign), the top source countries,
    the most common MITRE ATT&CK techniques and the most frequently matched
    detection rules. Call this FIRST to understand the big picture."""
    if DB is None:
        return "Database unavailable."
    try:
        threats = list(
            DB["threats"].find(
                {},
                {"_id": 0, "verdict": 1, "geo": 1, "mitre": 1, "rules": 1,
                 "protocol-score": 1},
            )
        )
    except PyMongoError as e:
        return f"Database error: {e}"

    counts = {"malicious": 0, "suspicious": 0, "benign": 0}
    countries: Dict[str, int] = {}
    mitre: Dict[str, int] = {}
    rules: Dict[str, int] = {}
    for t in threats:
        counts[t.get("verdict", "benign")] = counts.get(t.get("verdict", "benign"), 0) + 1
        geo = t.get("geo") or {}
        if geo.get("country"):
            countries[geo["country"]] = countries.get(geo["country"], 0) + 1
        for m in t.get("mitre") or []:
            mitre[m] = mitre.get(m, 0) + 1
        for r in t.get("rules") or []:
            name = f"{r.get('name')} [{r.get('id')}]"
            rules[name] = rules.get(name, 0) + 1

    def top(d: Dict[str, int], n: int) -> Dict[str, int]:
        return dict(sorted(d.items(), key=lambda kv: -kv[1])[:n])

    return _as_json({
        "total_tracked_ips": len(threats),
        "verdict_counts": counts,
        "top_countries": top(countries, 8),
        "top_mitre": top(mitre, 10),
        "top_rules": top(rules, 10),
    })


@tool
def list_threats(verdict: str = "", limit: int = 20) -> str:
    """List tracked attacker IPs sorted by score (highest first). Optionally
    filter by verdict ("malicious", "suspicious" or "benign"). Returns for each:
    ip, score, verdict, country, isp, alert_count, mitre, first_seen, last_seen.
    Use this to find which attackers deserve a closer look."""
    if DB is None:
        return "Database unavailable."
    query: Dict = {}
    v = (verdict or "").strip().lower()
    if v in _VALID_VERDICTS:
        query["verdict"] = v
    try:
        lim = max(1, min(int(limit), _MAX_LIST))
    except (TypeError, ValueError):
        lim = 20
    try:
        docs = list(
            DB["threats"]
            .find(query, {"_id": 0})
            .sort("protocol-score", -1)
            .limit(lim)
        )
    except PyMongoError as e:
        return f"Database error: {e}"

    out = []
    for t in docs:
        geo = t.get("geo") or {}
        out.append({
            "ip": t.get("ip"),
            "score": t.get("protocol-score"),
            "verdict": t.get("verdict"),
            "country": geo.get("country"),
            "isp": geo.get("isp"),
            "alert_count": t.get("alert_count"),
            "mitre": t.get("mitre", []),
            "first_seen": t.get("first_seen"),
            "last_seen": t.get("last_seen"),
        })
    return _as_json(out)


@tool
def get_threat(ip: str) -> str:
    """Return the full threat record for a single attacker IP: score, verdict,
    geolocation, matched detection rules (id, name, severity, score, count),
    MITRE techniques, tags, agents that saw it, and first/last seen. Use this for
    a deep dive on a specific IP."""
    if DB is None:
        return "Database unavailable."
    try:
        threat = DB["threats"].find_one({"ip": str(ip)}, {"_id": 0})
    except PyMongoError as e:
        return f"Database error: {e}"
    if not threat:
        return f"No threat record found for {ip}."
    return _as_json(threat)


@tool
def get_killchain(ip: str) -> str:
    """Return the chronological kill-chain of honeypot events observed for a
    specific attacker IP (timestamp, protocol, action, path, user, user-agent).
    Use this to understand exactly what an attacker did, step by step."""
    if DB is None:
        return "Database unavailable."
    try:
        logs = list(
            DB["logs"]
            .find(
                {"ip": str(ip)},
                {"_id": 0, "timestamp": 1, "date": 1, "hour": 1, "protocol": 1,
                 "action": 1, "path": 1, "user": 1, "user-agent": 1},
            )
            .sort("timestamp", 1)
            .limit(KILLCHAIN_LIMIT)
        )
    except PyMongoError as e:
        return f"Database error while reading kill-chain: {e}"

    if not logs:
        return f"No raw events found for {ip}."

    lines: List[str] = []
    for entry in logs:
        ts = entry.get("timestamp") or f"{entry.get('date', '')} {entry.get('hour', '')}".strip()
        parts = [str(ts), entry.get("protocol", "other"), entry.get("action", "")]
        if entry.get("path"):
            parts.append(f"path={entry['path']}")
        if entry.get("user"):
            parts.append(f"user={entry['user']}")
        if entry.get("user-agent"):
            parts.append(f"ua={entry['user-agent']}")
        lines.append(" | ".join(p for p in parts if p))
    return "\n".join(lines)


@tool
def get_recent_alerts(limit: int = 30) -> str:
    """Return the most recent detection alerts across the whole platform
    (rule id/name, severity, score, ip, agent, MITRE, created_at). Use this to
    see what is firing right now."""
    if DB is None:
        return "Database unavailable."
    try:
        lim = max(1, min(int(limit), _MAX_LIST))
    except (TypeError, ValueError):
        lim = 30
    try:
        docs = list(
            DB["alerts"]
            .find(
                {},
                {"_id": 0, "rule_id": 1, "rule_name": 1, "severity": 1,
                 "score": 1, "ip": 1, "agent_id": 1, "mitre": 1, "created_at": 1},
            )
            .sort("created_at", -1)
            .limit(lim)
        )
    except PyMongoError as e:
        return f"Database error: {e}"
    return _as_json(docs)


@tool
def search_logs(field: str, value: str, limit: int = 25) -> str:
    """Search raw honeypot logs by an exact field match and return matching
    events. Allowed fields: ip, protocol, action, path, user, user-agent,
    agent_id. Use this to investigate a specific indicator (e.g. a username, a
    URL path or a protocol)."""
    if DB is None:
        return "Database unavailable."
    f = (field or "").strip().lower()
    if f not in _ALLOWED_LOG_FIELDS:
        return f"Field '{field}' is not searchable. Allowed: {sorted(_ALLOWED_LOG_FIELDS)}"
    try:
        lim = max(1, min(int(limit), _MAX_LIST))
    except (TypeError, ValueError):
        lim = 25
    try:
        docs = list(
            DB["logs"]
            .find(
                {f: str(value)},
                {"_id": 0, "timestamp": 1, "ip": 1, "protocol": 1, "action": 1,
                 "path": 1, "user": 1, "user-agent": 1, "agent_id": 1},
            )
            .sort("timestamp", -1)
            .limit(lim)
        )
    except PyMongoError as e:
        return f"Database error: {e}"
    if not docs:
        return f"No logs found for {f}={value}."
    return _as_json(docs)


@tool
def get_agents() -> str:
    """Return the list of registered honeypot agents and their health status
    (agent_id, status, last_seen, enabled modules). Use this to know where the
    activity is coming from across the deployment."""
    if DB is None:
        return "Database unavailable."
    try:
        docs = list(
            DB["agents"].find(
                {},
                {"_id": 0, "agent_id": 1, "status": 1, "last_seen": 1,
                 "host": 1, "modules": 1},
            )
        )
    except PyMongoError as e:
        return f"Database error: {e}"
    return _as_json(docs)


@tool
def get_log_overview(top_ips: int = 15) -> str:
    """Summarize the RAW `logs` collection — the ground-truth SUPERSET of every
    event the sensors captured, including sources not (yet) scored into `threats`.
    Returns total events, the number of DISTINCT source IPs actually seen, a
    per-protocol breakdown, a per-agent breakdown, and the busiest source IPs
    (each flagged `tracked_in_threats` true/false). Use this in briefings and
    whenever you need to know what the hive has truly seen — never rely on
    `threats` or `total_tracked_ips` alone to judge how much activity exists or
    whether an agent is silent."""
    if DB is None:
        return "Database unavailable."
    try:
        n = max(1, min(int(top_ips), 50))
    except (TypeError, ValueError):
        n = 15
    try:
        logs = DB["logs"]
        total = logs.estimated_document_count()
        by_protocol = list(logs.aggregate([
            {"$group": {"_id": "$protocol", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]))
        by_agent = list(logs.aggregate([
            {"$group": {"_id": "$agent_id", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]))
        top = list(logs.aggregate([
            {"$group": {
                "_id": "$ip",
                "events": {"$sum": 1},
                "protocols": {"$addToSet": "$protocol"},
                "agents": {"$addToSet": "$agent_id"},
            }},
            {"$sort": {"events": -1}},
            {"$limit": n},
        ]))
        distinct_ips = len(logs.distinct("ip"))
    except PyMongoError as e:
        return f"Database error: {e}"

    try:
        tracked = set(DB["threats"].distinct("ip"))
    except PyMongoError:
        tracked = set()

    return _as_json({
        "total_events": total,
        "distinct_source_ips": distinct_ips,
        "tracked_in_threats": len(tracked),
        "untracked_source_ips": max(distinct_ips - len(tracked), 0),
        "by_protocol": {(d.get("_id") or "unknown"): d["count"] for d in by_protocol},
        "by_agent": {(d.get("_id") or "unknown"): d["count"] for d in by_agent},
        "top_source_ips": [
            {
                "ip": d.get("_id"),
                "events": d["events"],
                "protocols": [p for p in (d.get("protocols") or []) if p],
                "agents": [a for a in (d.get("agents") or []) if a],
                "tracked_in_threats": d.get("_id") in tracked,
            }
            for d in top
        ],
    })


# --------------------------------------------------------------------------- #
# Skills — loaded on demand so the system prompt only carries a short index
# --------------------------------------------------------------------------- #

SKILLS_DIR = Path(__file__).resolve().parent / "skills"


def _expand_tool_refs(text: str) -> str:
    def repl(match: "re.Match[str]") -> str:
        names = [n.strip() for n in match.group(1).split(",") if n.strip()]
        lines = []
        for name in names:
            t = TOOLS_BY_NAME.get(name)
            if t is None:
                lines.append(f"- `{name}`: (unknown tool)")
                continue
            summary = " ".join((t.description or "").split())
            lines.append(f"- `{name}`: {summary}")
        return "\n".join(lines)

    return re.sub(r"\{\{tools:([^}]*)\}\}", repl, text)


def _skill_meta(path: Path) -> Dict[str, str]:
    title = path.stem.replace("-", " ").title()
    summary = ""
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s.startswith("# Skill:"):
                title = s[len("# Skill:"):].strip() or title
            elif s.lower().startswith("**use when:**"):
                summary = s.split("**", 2)[-1].strip()
                break
    except OSError:
        pass
    return {"name": path.stem, "title": title, "summary": summary}


def skill_names() -> List[str]:
    if not SKILLS_DIR.is_dir():
        return []
    return [p.stem for p in sorted(SKILLS_DIR.glob("*.md"))]


def skills_index() -> str:
    if not SKILLS_DIR.is_dir():
        return "(no skills available)"
    lines = []
    for path in sorted(SKILLS_DIR.glob("*.md")):
        meta = _skill_meta(path)
        summary = meta["summary"] or "(no description)"
        lines.append(f"- `{meta['name']}` — {summary}")
    return "\n".join(lines) if lines else "(no skills available)"


@tool
def get_skill(name: str) -> str:
    """Load the full step-by-step procedure for one of Inspektor's named skills,
    then follow it. Call this before acting on any task that matches a skill in
    the system-prompt skill index. Available skills: threat-briefing,
    ip-investigation, attacker-ranking, alert-triage, log-hunting, agent-health."""
    key = (name or "").strip().lower().replace(" ", "-")
    if not key:
        return f"Provide a skill name. Available: {', '.join(skill_names())}"
    path = SKILLS_DIR / f"{key}.md"
    if not path.is_file():
        return f"Unknown skill '{name}'. Available: {', '.join(skill_names())}"
    try:
        return _expand_tool_refs(path.read_text(encoding="utf-8")).strip()
    except OSError as e:
        return f"Could not load skill '{name}': {e}"


TOOLS = [
    get_global_stats,
    list_threats,
    get_threat,
    get_killchain,
    get_recent_alerts,
    search_logs,
    get_agents,
    get_log_overview,
    get_skill,
]

TOOLS_BY_NAME = {t.name: t for t in TOOLS}
