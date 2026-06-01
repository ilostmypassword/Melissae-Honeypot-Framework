from __future__ import annotations

import json
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


TOOLS = [
    get_global_stats,
    list_threats,
    get_threat,
    get_killchain,
    get_recent_alerts,
    search_logs,
    get_agents,
]

TOOLS_BY_NAME = {t.name: t for t in TOOLS}
