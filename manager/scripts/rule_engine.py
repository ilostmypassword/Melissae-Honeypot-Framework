from __future__ import annotations

import hashlib
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml
from pymongo import MongoClient, UpdateOne
from pymongo.errors import PyMongoError

from mql import match_log

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGO_DB", "melissae")
RULES_DIR = os.getenv("MELISSAE_RULES_DIR",
                      str(Path(__file__).resolve().parent.parent.parent / "rules"))

VALID_SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(VALID_SEVERITIES)}

ALERT_RETENTION_DAYS = 90

_LOOKBACK_RE = re.compile(r"^\s*(\d+)\s*([smhd])\s*$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Lookback / cron helpers
# ---------------------------------------------------------------------------

def parse_lookback(value: str) -> timedelta:
    """Parse a lookback string like '5m', '2h', '1d'. Defaults to 5 minutes."""
    if not isinstance(value, str):
        return timedelta(minutes=5)
    m = _LOOKBACK_RE.match(value)
    if not m:
        return timedelta(minutes=5)
    n, unit = int(m.group(1)), m.group(2).lower()
    return {
        "s": timedelta(seconds=n),
        "m": timedelta(minutes=n),
        "h": timedelta(hours=n),
        "d": timedelta(days=n),
    }[unit]


def _expand_cron_field(field: str, lo: int, hi: int) -> set:
    """Expand a single cron field into the set of matching integers."""
    result: set = set()
    for piece in field.split(","):
        piece = piece.strip()
        if not piece:
            continue
        step = 1
        if "/" in piece:
            base, step_str = piece.split("/", 1)
            try:
                step = max(1, int(step_str))
            except ValueError:
                step = 1
        else:
            base = piece
        if base == "*" or base == "":
            start, end = lo, hi
        elif "-" in base:
            a, b = base.split("-", 1)
            try:
                start, end = int(a), int(b)
            except ValueError:
                continue
        else:
            try:
                v = int(base)
                start = end = v
            except ValueError:
                continue
        for v in range(start, end + 1):
            if v < lo or v > hi:
                continue
            if (v - start) % step == 0:
                result.add(v)
    return result


def cron_matches(expr: str, dt: datetime) -> bool:
    """Minimal 5-field cron matcher (minute hour dom month dow). dow: 0=Sunday."""
    if not expr or not isinstance(expr, str):
        return False
    parts = expr.split()
    if len(parts) != 5:
        return False
    minutes  = _expand_cron_field(parts[0], 0, 59)
    hours    = _expand_cron_field(parts[1], 0, 23)
    doms     = _expand_cron_field(parts[2], 1, 31)
    months   = _expand_cron_field(parts[3], 1, 12)
    dows     = _expand_cron_field(parts[4], 0, 6)
    return (
        dt.minute in minutes
        and dt.hour in hours
        and dt.day in doms
        and dt.month in months
        and (dt.weekday() + 1) % 7 in dows  # Python: Mon=0 → cron Sun=0
    )


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

def _validate_rule(raw: Dict, source: str) -> Optional[Dict]:
    if not isinstance(raw, dict):
        print(f"[rule_engine] {source}: not a YAML mapping, skipped")
        return None
    rid = raw.get("id")
    if not isinstance(rid, str) or not re.match(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$", rid):
        print(f"[rule_engine] {source}: missing/invalid id, skipped")
        return None
    mql_query = raw.get("mql")
    if not isinstance(mql_query, str) or not mql_query.strip():
        print(f"[rule_engine] {rid}: missing mql, skipped")
        return None
    schedule = raw.get("schedule", "*/1 * * * *")
    if not isinstance(schedule, str) or len(schedule.split()) != 5:
        print(f"[rule_engine] {rid}: invalid schedule, skipped")
        return None
    severity = str(raw.get("severity", "medium")).lower()
    if severity not in VALID_SEVERITIES:
        severity = "medium"
    try:
        score = int(raw.get("score", 10))
    except (TypeError, ValueError):
        score = 10
    score = max(0, min(100, score))
    try:
        threshold = max(1, int(raw.get("threshold", 1)))
    except (TypeError, ValueError):
        threshold = 1
    return {
        "id": rid,
        "name": str(raw.get("name", rid))[:200],
        "description": str(raw.get("description", ""))[:2000],
        "severity": severity,
        "enabled": bool(raw.get("enabled", True)),
        "schedule": schedule,
        "lookback": str(raw.get("lookback", "5m")),
        "mql": mql_query.strip(),
        "group_by": str(raw.get("group_by", "ip")).strip() or "ip",
        "threshold": threshold,
        "score": score,
        "tags": [str(t)[:64] for t in (raw.get("tags") or []) if t][:32],
        "mitre": [str(t)[:32] for t in (raw.get("mitre") or []) if t][:32],
        "source_file": source,
    }


def load_rules(rules_dir: str = RULES_DIR) -> List[Dict]:
    """Load and validate all *.yml/*.yaml rules from rules_dir."""
    base = Path(rules_dir)
    if not base.is_dir():
        print(f"[rule_engine] rules dir not found: {rules_dir}")
        return []
    out: List[Dict] = []
    seen_ids: set = set()
    for path in sorted(base.iterdir()):
        if not path.is_file() or path.suffix.lower() not in (".yml", ".yaml"):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
        except (OSError, yaml.YAMLError) as e:
            print(f"[rule_engine] cannot read {path.name}: {e}")
            continue
        rule = _validate_rule(raw, path.name)
        if rule is None:
            continue
        if rule["id"] in seen_ids:
            print(f"[rule_engine] duplicate rule id '{rule['id']}' in {path.name}, skipped")
            continue
        seen_ids.add(rule["id"])
        out.append(rule)
    return out


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def _alert_id(rule_id: str, log_id: str) -> str:
    return hashlib.sha256(f"{rule_id}|{log_id}".encode("utf-8")).hexdigest()


def _log_event_time(log: Dict) -> Optional[str]:
    ts = log.get("timestamp")
    if isinstance(ts, str) and ts:
        return ts.replace(" ", "T", 1)
    date = log.get("date")
    hour = log.get("hour")
    if isinstance(date, str) and date:
        if isinstance(hour, str) and hour:
            return f"{date}T{hour}"
        return f"{date}T00:00:00"
    return None


def _log_unique_id(log: Dict) -> str:
    """Stable id for a log: prefer stored hash/_id, fall back to digest of key fields."""
    for k in ("_id", "hash"):
        v = log.get(k)
        if isinstance(v, str) and v:
            return v
    payload = "|".join(str(log.get(k, "")) for k in
                       ("protocol", "timestamp", "date", "hour", "ip", "action", "path"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _fetch_logs(db, lookback: timedelta) -> List[Dict]:
    """Fetch logs newer than (now - lookback). Uses date+hour fallback."""
    cutoff_dt = datetime.now(timezone.utc) - lookback
    cutoff_iso = cutoff_dt.isoformat()
    cutoff_date = cutoff_dt.strftime("%Y-%m-%d")
    query = {
        "$or": [
            {"timestamp": {"$gte": cutoff_iso[:19]}},
            {"date": {"$gte": cutoff_date}},
        ]
    }
    return list(db["logs"].find(query, {}).limit(50000))


def execute_rule(rule: Dict, db, now: datetime) -> Tuple[int, int]:
    """
    Run a single rule against the DB.
    Returns (alerts_emitted, groups_triggered).
    """
    if not rule.get("enabled", True):
        return (0, 0)

    lookback = parse_lookback(rule.get("lookback", "5m"))
    logs = _fetch_logs(db, lookback)

    matched: List[Dict] = []
    for log in logs:
        try:
            if match_log(log, rule["mql"]):
                matched.append(log)
        except Exception as e:  # defensive: a malformed query shouldn't kill the engine
            print(f"[rule_engine] {rule['id']}: MQL eval error: {e}")
            return (0, 0)

    if not matched:
        return (0, 0)

    group_field = rule["group_by"]
    grouped: Dict[str, List[Dict]] = defaultdict(list)
    for log in matched:
        key = str(log.get(group_field) or "_unknown")
        grouped[key].append(log)

    threshold = rule["threshold"]
    triggered_groups = {k: v for k, v in grouped.items() if len(v) >= threshold}
    if not triggered_groups:
        return (0, 0)

    now_iso = now.isoformat()
    ops: List[UpdateOne] = []

    for group_value, group_logs in triggered_groups.items():
        for log in group_logs:
            log_uid = _log_unique_id(log)
            aid = _alert_id(rule["id"], log_uid)
            event_time = _log_event_time(log) or now_iso
            doc = {
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "rule_mql": rule["mql"],
                "severity": rule["severity"],
                "score": rule["score"],
                "tags": rule["tags"],
                "mitre": rule["mitre"],
                "group_by": group_field,
                "group_value": group_value,
                "ip": log.get("ip"),
                "agent_id": log.get("agent_id"),
                "protocol": log.get("protocol"),
                "log_id": log_uid,
                "log": {
                    "protocol":   log.get("protocol"),
                    "action":     log.get("action"),
                    "ip":         log.get("ip"),
                    "user":       log.get("user"),
                    "path":       log.get("path"),
                    "user-agent": log.get("user-agent"),
                    "cve":        log.get("cve"),
                    "date":       log.get("date"),
                    "hour":       log.get("hour"),
                    "timestamp":  log.get("timestamp"),
                    "agent_id":   log.get("agent_id"),
                },
                "detected_at": now_iso,
                "updated_at":  now_iso,
            }
            ops.append(UpdateOne(
                {"_id": aid},
                {
                    "$setOnInsert": {
                        "_id": aid,
                        "status": "new",
                        "created_at": event_time,
                        "expires_at": now + timedelta(days=ALERT_RETENTION_DAYS),
                    },
                    "$set": doc,
                },
                upsert=True,
            ))

    if not ops:
        return (0, 0)

    try:
        result = db["alerts"].bulk_write(ops, ordered=False)
        emitted = result.upserted_count
    except PyMongoError as e:
        print(f"[rule_engine] {rule['id']}: bulk_write failed: {e}")
        return (0, 0)

    # Track rule run metadata for the dashboard
    try:
        db["rule_runs"].update_one(
            {"_id": rule["id"]},
            {"$set": {
                "rule_id": rule["id"],
                "last_run_at": now_iso,
                "last_alerts_emitted": emitted,
                "last_groups_triggered": len(triggered_groups),
            }},
            upsert=True,
        )
    except PyMongoError:
        pass

    return (emitted, len(triggered_groups))


def run_due_rules(now: Optional[datetime] = None,
                  rules_dir: str = RULES_DIR,
                  mongo_uri: str = MONGO_URI,
                  db_name: str = DB_NAME) -> Dict:
    """Entry point: run all rules due to fire at `now` (default: utcnow())."""
    if now is None:
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    rules = load_rules(rules_dir)
    if not rules:
        return {"due": 0, "executed": 0, "alerts": 0}

    try:
        client = MongoClient(mongo_uri)
        db = client[db_name]
    except PyMongoError as e:
        print(f"[rule_engine] mongo connect failed: {e}")
        return {"due": 0, "executed": 0, "alerts": 0}

    _ensure_indexes(db)

    due = [r for r in rules if r["enabled"] and cron_matches(r["schedule"], now)]
    total_alerts = 0
    for rule in due:
        emitted, _groups = execute_rule(rule, db, now)
        total_alerts += emitted

    return {"due": len(due), "executed": len(due), "alerts": total_alerts}


def _ensure_indexes(db) -> None:
    try:
        db["alerts"].create_index("ip")
        db["alerts"].create_index("rule_id")
        db["alerts"].create_index("status")
        db["alerts"].create_index("severity")
        db["alerts"].create_index([("created_at", -1)])
        db["alerts"].create_index("expires_at", expireAfterSeconds=0)
    except PyMongoError:
        pass


if __name__ == "__main__":
    summary = run_due_rules()
    print(f"[rule_engine] due={summary['due']} alerts={summary['alerts']}")
