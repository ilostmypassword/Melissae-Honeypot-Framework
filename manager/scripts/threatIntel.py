from __future__ import annotations

import ipaddress
import json
import os
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from pymongo import MongoClient, UpdateOne
from pymongo.errors import PyMongoError

from rule_engine import run_due_rules

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGO_DB", "melissae")

VERDICT_MALICIOUS = 70
VERDICT_SUSPICIOUS = 30
ALERTS_LOOKBACK_DAYS = 90


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.replace(tzinfo=None) if dt.tzinfo else dt
    except ValueError:
        return None


def is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return True


def _sanitize_geo_string(value: str, max_len: int = 128) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = "".join(c for c in value if c.isprintable() and c not in "<>{}$")
    return cleaned[:max_len]


def _validate_coordinate(val, min_v: float, max_v: float) -> float:
    try:
        f = float(val)
        return f if min_v <= f <= max_v else 0.0
    except (TypeError, ValueError):
        return 0.0


def get_existing_geo(db, ips: List[str]) -> Dict[str, Dict]:
    if not ips:
        return {}
    try:
        docs = db["threats"].find(
            {"ip": {"$in": ips}, "geo": {"$exists": True}},
            {"ip": 1, "geo": 1, "_id": 0},
        )
        return {doc["ip"]: doc["geo"] for doc in docs}
    except PyMongoError:
        return {}


def batch_geolocate(ips: List[str]) -> Dict[str, Dict]:
    public_ips = [ip for ip in ips if not is_private_ip(ip)]
    if not public_ips:
        return {}
    results: Dict[str, Dict] = {}
    batch_size = 100
    for i in range(0, len(public_ips), batch_size):
        batch = public_ips[i:i + batch_size]
        payload = json.dumps([
            {"query": ip,
             "fields": "status,query,country,countryCode,city,lat,lon,isp,org"}
            for ip in batch
        ]).encode("utf-8")
        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch", data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            if not isinstance(data, list):
                continue
            for item in data:
                if not isinstance(item, dict) or item.get("status") != "success":
                    continue
                q = item.get("query", "")
                if q not in batch:
                    continue
                lat = _validate_coordinate(item.get("lat"), -90, 90)
                lon = _validate_coordinate(item.get("lon"), -180, 180)
                if lat == 0.0 and lon == 0.0:
                    continue
                results[q] = {
                    "country": _sanitize_geo_string(item.get("country", "")),
                    "country_code": _sanitize_geo_string(item.get("countryCode", ""), 3),
                    "city": _sanitize_geo_string(item.get("city", "")),
                    "lat": lat,
                    "lon": lon,
                    "isp": _sanitize_geo_string(item.get("isp", "")),
                    "org": _sanitize_geo_string(item.get("org", "")),
                }
        except Exception as e:
            print(f"[threatIntel] GeoIP batch error: {e}")
        if i + batch_size < len(public_ips):
            time.sleep(4)
    return results


def _aggregate_alerts_by_ip(db) -> Dict[str, Dict]:
    """Group alerts (last N days) by IP."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=ALERTS_LOOKBACK_DAYS)).isoformat()
    cursor = db["alerts"].find(
        {"created_at": {"$gte": cutoff}, "ip": {"$ne": None}},
        {"_id": 0, "rule_id": 1, "rule_name": 1, "severity": 1, "score": 1,
         "ip": 1, "agent_id": 1, "tags": 1, "mitre": 1,
         "created_at": 1, "updated_at": 1},
    )
    by_ip: Dict[str, Dict] = defaultdict(lambda: {
        "rules": {},
        "agents": set(),
        "tags": set(),
        "mitre": set(),
        "alert_count": 0,
        "first_seen": None,
        "last_seen": None,
    })
    for doc in cursor:
        ip = doc.get("ip")
        if not ip:
            continue
        rid = doc.get("rule_id") or "unknown"
        bucket = by_ip[ip]
        bucket["alert_count"] += 1
        if doc.get("agent_id"):
            bucket["agents"].add(doc["agent_id"])
        for t in doc.get("tags") or []:
            bucket["tags"].add(t)
        for m in doc.get("mitre") or []:
            bucket["mitre"].add(m)
        rule_entry = bucket["rules"].setdefault(rid, {
            "name": doc.get("rule_name", rid),
            "score": int(doc.get("score") or 0),
            "severity": doc.get("severity", "medium"),
            "count": 0,
            "last_seen": None,
        })
        rule_entry["count"] += 1
        ts = _parse_iso(doc.get("created_at"))
        if ts:
            if bucket["first_seen"] is None or ts < bucket["first_seen"]:
                bucket["first_seen"] = ts
            if bucket["last_seen"] is None or ts > bucket["last_seen"]:
                bucket["last_seen"] = ts
            rule_last = _parse_iso(rule_entry["last_seen"])
            if rule_last is None or ts > rule_last:
                rule_entry["last_seen"] = ts.isoformat()
    return by_ip


def _compute_threat(ip: str, bucket: Dict) -> Dict:
    # Each alert contributes its rule score (capped at 100 overall).
    score = min(100, sum(r["score"] * r["count"] for r in bucket["rules"].values()))
    if score >= VERDICT_MALICIOUS:
        verdict = "malicious"
    elif score >= VERDICT_SUSPICIOUS:
        verdict = "suspicious"
    else:
        verdict = "benign"

    reasons = []
    for rid, r in sorted(bucket["rules"].items(),
                         key=lambda kv: (-kv[1]["score"], kv[0])):
        reasons.append(f"{r['name']} ({r['count']}× — +{r['score']})")

    doc = {
        "type": "ip",
        "ip": ip,
        "protocol-score": score,
        "verdict": verdict,
        "reasons": reasons,
        "rules": [
            {"id": rid, "name": r["name"], "severity": r["severity"],
             "score": r["score"], "count": r["count"],
             "last_seen": r["last_seen"]}
            for rid, r in bucket["rules"].items()
        ],
        "alert_count": bucket["alert_count"],
        "tags": sorted(bucket["tags"]),
        "mitre": sorted(bucket["mitre"]),
        "agents": sorted(bucket["agents"]),
    }
    if bucket["first_seen"]:
        doc["first_seen"] = bucket["first_seen"].isoformat()
    if bucket["last_seen"]:
        doc["last_seen"] = bucket["last_seen"].isoformat()
    return doc


def recompute_threats(db) -> int:
    by_ip = _aggregate_alerts_by_ip(db)
    if not by_ip:
        # No alerts at all → drop stale threats so the dashboard isn't lying.
        try:
            db["threats"].delete_many({})
        except PyMongoError:
            pass
        return 0

    all_ips = list(by_ip.keys())
    existing_geo = get_existing_geo(db, all_ips)
    new_ips = [ip for ip in all_ips
               if ip not in existing_geo and not is_private_ip(ip)]
    if new_ips:
        existing_geo.update(batch_geolocate(new_ips))

    ops = []
    for ip, bucket in by_ip.items():
        threat = _compute_threat(ip, bucket)
        geo = existing_geo.get(ip)
        if geo:
            threat["geo"] = geo
        ops.append(UpdateOne({"ip": ip}, {"$set": threat}, upsert=True))

    if ops:
        try:
            db["threats"].bulk_write(ops, ordered=False)
            db["threats"].create_index("ip", unique=True)
        except PyMongoError as e:
            print(f"[threatIntel] threats write error: {e}")

    try:
        db["threats"].delete_many({"ip": {"$nin": all_ips}})
    except PyMongoError:
        pass

    return len(ops)


def main() -> None:
    summary = run_due_rules(mongo_uri=MONGO_URI, db_name=DB_NAME)
    try:
        client = MongoClient(MONGO_URI)
        db = client[DB_NAME]
    except PyMongoError as e:
        print(f"[threatIntel] mongo connect failed: {e}")
        return
    touched = recompute_threats(db)
    print(f"[threatIntel] rules_due={summary['due']} "
          f"alerts={summary['alerts']} threats_updated={touched}")


if __name__ == "__main__":
    main()
