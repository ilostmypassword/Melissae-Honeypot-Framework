from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient, UpdateOne
from pymongo.errors import PyMongoError
import hashlib
import ipaddress
import json
import os
import re
import secrets
import urllib.request
from datetime import datetime, timezone, timedelta

app = Flask(__name__)
_cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:9999,http://127.0.0.1:9999,http://localhost:8080,http://127.0.0.1:8080")
CORS(app, resources={r"/api/*": {"origins": [o.strip() for o in _cors_origins.split(",") if o.strip()]}})

MONGO_URI = os.getenv("MONGO_URI", "mongodb://melissae_mongo:27017")
DB_NAME = os.getenv("MONGO_DB", "melissae")

MAX_BATCH_SIZE = 500
MAX_RESULTS_LOGS = 5000
MAX_RESULTS_THREATS = 2000

REQUIRED_LOG_FIELDS = {"protocol", "ip", "action"}

MAX_FIELD_LEN = 512

_mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, maxPoolSize=50)

def get_db():
    return _mongo_client[DB_NAME]

# Sanitize a string field: strip control chars, limit length, block $ operators
def _sanitize_str(val, max_len=MAX_FIELD_LEN):
    if not isinstance(val, str):
        return str(val)[:max_len] if val is not None else ""
    cleaned = "".join(c for c in val if c.isprintable())
    while cleaned.startswith("$"):
        cleaned = cleaned[1:]
    return cleaned[:max_len]

def _compute_uid(log):
    key_fields = ['protocol', 'timestamp', 'date', 'hour', 'ip', 'action', 'path', 'user', 'user-agent']
    payload = {k: log.get(k) for k in key_fields if k in log}
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(serialized.encode('utf-8')).hexdigest()

def _format_utc_iso(dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")

def _parse_log_datetime(log):
    raw_ts = log.get("timestamp") or log.get("time") or log.get("datetime")
    if isinstance(raw_ts, str) and raw_ts.strip():
        raw = raw_ts.strip().replace("Z", "+00:00").replace(" ", "T", 1)
        try:
            dt = datetime.fromisoformat(raw)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
        except ValueError:
            pass

    date = log.get("date")
    hour = log.get("hour") or "00:00:00"
    if isinstance(date, str) and date.strip():
        raw = f"{date.strip()}T{str(hour).strip()}".replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(raw)
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
        except ValueError:
            pass
        try:
            dt = datetime.strptime(f"{date.strip()} {str(hour).strip()[:8]}", "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            try:
                dt = datetime.fromisoformat(date.strip().replace("Z", "+00:00"))
                return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
            except ValueError:
                return None
    return None

def _normalize_log_timestamp(log):
    dt = _parse_log_datetime(log)
    if dt is None:
        return False
    log["timestamp"] = _format_utc_iso(dt)
    log["date"] = dt.strftime("%Y-%m-%d")
    log["hour"] = dt.strftime("%H:%M:%S")
    return True

def _log_sort_ts(log):
    dt = _parse_log_datetime(log)
    return dt.timestamp() if dt else 0

def _build_alert_query(args):
    query = {}

    status = args.get("status")
    if status:
        statuses = [s.strip() for s in status.split(",") if s.strip() in VALID_ALERT_STATUSES]
        if statuses:
            query["status"] = {"$in": statuses}

    severity = args.get("severity")
    if severity:
        sevs = [s.strip() for s in severity.split(",") if s.strip() in VALID_SEVERITIES]
        if sevs:
            query["severity"] = {"$in": sevs}

    rule_id = args.get("rule_id")
    if rule_id:
        query["rule_id"] = _sanitize_str(rule_id, 64)

    ip_filter = args.get("ip")
    if ip_filter:
        try:
            ipaddress.ip_address(ip_filter)
            query["ip"] = ip_filter
        except ValueError:
            raise ValueError("Invalid IP")

    agent_id = args.get("agent_id")
    if agent_id:
        query["agent_id"] = _sanitize_str(agent_id, 64)

    return query

def _build_log_stats_query(args):
    query = {}
    agent_id = args.get("agent_id")
    if agent_id:
        query["agent_id"] = _sanitize_str(agent_id, 64)

    date_range = args.get("range")
    now = datetime.now(timezone.utc)
    if date_range == "today":
        from_dt = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    elif date_range == "7d":
        from_dt = now - timedelta(days=7)
    elif date_range == "30d":
        from_dt = now - timedelta(days=30)
    else:
        from_dt = None

    if from_dt:
        query["timestamp"] = {"$gte": _format_utc_iso(from_dt), "$lte": _format_utc_iso(now)}
    return query

@app.route("/api/logs", methods=["GET"])
# GET /api/logs — Paginated log retrieval with filters
def api_logs():
    try:
        db = get_db()
        query = {}
        agent_id = request.args.get("agent_id")
        if agent_id:
            query["agent_id"] = _sanitize_str(agent_id, 64)
        log_id = request.args.get("log_id")
        if log_id:
            cleaned = _sanitize_str(log_id, 128)
            if not re.fullmatch(r"[A-Fa-f0-9]+", cleaned):
                return jsonify({"error": "Invalid log_id"}), 400
            query["_id"] = cleaned
        try:
            limit = max(1, min(int(request.args.get("limit", MAX_RESULTS_LOGS)), MAX_RESULTS_LOGS))
            skip = max(0, int(request.args.get("skip", 0)))
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid pagination parameters"}), 400
        data = list(
            db["logs"]
            .find(query, {"_id": 0})
            .sort("timestamp", -1)
            .skip(skip)
            .limit(limit)
        )
        return jsonify(data)
    except PyMongoError:
        return jsonify({"error": "Database error"}), 500

@app.route("/api/logs/stats", methods=["GET"])
# GET /api/logs/stats — Server-side counters for large log volumes
def api_logs_stats():
    try:
        db = get_db()
        query = _build_log_stats_query(request.args)
        pipeline = [
            {"$match": query},
            {"$group": {
                "_id": None,
                "totalLogs": {"$sum": 1},
                "uniqueIPs": {"$addToSet": "$ip"},
                "ssh": {"$sum": {"$cond": [{"$eq": ["$protocol", "ssh"]}, 1, 0]}},
                "ftp": {"$sum": {"$cond": [{"$eq": ["$protocol", "ftp"]}, 1, 0]}},
                "http": {"$sum": {"$cond": [{"$eq": ["$protocol", "http"]}, 1, 0]}},
                "modbus": {"$sum": {"$cond": [{"$eq": ["$protocol", "modbus"]}, 1, 0]}},
                "mqtt": {"$sum": {"$cond": [{"$eq": ["$protocol", "mqtt"]}, 1, 0]}},
                "telnet": {"$sum": {"$cond": [{"$eq": ["$protocol", "telnet"]}, 1, 0]}},
                "cveLogs": {"$sum": {"$cond": [{"$ifNull": ["$cve", False]}, 1, 0]}},
                "successSSH": {"$sum": {"$cond": [{"$and": [
                    {"$eq": ["$protocol", "ssh"]},
                    {"$regexMatch": {"input": {"$toLower": {"$ifNull": ["$action", ""]}}, "regex": "accepted|successful"}},
                ]}, 1, 0]}},
                "successFTP": {"$sum": {"$cond": [{"$and": [
                    {"$eq": ["$protocol", "ftp"]},
                    {"$regexMatch": {"input": {"$toLower": {"$ifNull": ["$action", ""]}}, "regex": "successful"}},
                ]}, 1, 0]}},
                "successTelnet": {"$sum": {"$cond": [{"$and": [
                    {"$eq": ["$protocol", "telnet"]},
                    {"$regexMatch": {"input": {"$toLower": {"$ifNull": ["$action", ""]}}, "regex": "session opened"}},
                ]}, 1, 0]}},
                "modbusWrites": {"$sum": {"$cond": [{"$and": [
                    {"$eq": ["$protocol", "modbus"]},
                    {"$regexMatch": {"input": {"$toLower": {"$ifNull": ["$action", ""]}}, "regex": "write"}},
                ]}, 1, 0]}},
            }},
        ]
        rows = list(db["logs"].aggregate(pipeline, allowDiskUse=True))
        if not rows:
            return jsonify({
                "totalLogs": 0,
                "uniqueIPs": 0,
                "protocols": {"ssh": 0, "ftp": 0, "http": 0, "modbus": 0, "mqtt": 0, "telnet": 0},
                "cveLogs": 0,
                "successSSH": 0,
                "successFTP": 0,
                "successTelnet": 0,
                "modbusWrites": 0,
            })

        row = rows[0]
        return jsonify({
            "totalLogs": int(row.get("totalLogs", 0)),
            "uniqueIPs": len([ip for ip in row.get("uniqueIPs", []) if ip]),
            "protocols": {
                "ssh": int(row.get("ssh", 0)),
                "ftp": int(row.get("ftp", 0)),
                "http": int(row.get("http", 0)),
                "modbus": int(row.get("modbus", 0)),
                "mqtt": int(row.get("mqtt", 0)),
                "telnet": int(row.get("telnet", 0)),
            },
            "cveLogs": int(row.get("cveLogs", 0)),
            "successSSH": int(row.get("successSSH", 0)),
            "successFTP": int(row.get("successFTP", 0)),
            "successTelnet": int(row.get("successTelnet", 0)),
            "modbusWrites": int(row.get("modbusWrites", 0)),
        })
    except PyMongoError:
        return jsonify({"error": "Database error"}), 500

@app.route("/api/threats", methods=["GET"])
# GET /api/threats — Threat list with pagination and sorting
def api_threats():
    try:
        db = get_db()
        query = {}
        agent_id = request.args.get("agent_id")
        if agent_id:
            query["agents"] = _sanitize_str(agent_id, 64)
        try:
            limit = max(1, min(int(request.args.get("limit", MAX_RESULTS_THREATS)), MAX_RESULTS_THREATS))
            skip = max(0, int(request.args.get("skip", 0)))
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid pagination parameters"}), 400
        data = list(db["threats"].find(query, {"_id": 0}).skip(skip).limit(limit))
        return jsonify(data)
    except PyMongoError:
        return jsonify({"error": "Database error"}), 500

@app.route("/api/threats/<ip>/killchain", methods=["GET"])
# GET /api/threats/<ip>/killchain — Attack timeline for an IP
def api_killchain(ip):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400

    try:
        db = get_db()
        logs = list(
            db["logs"]
            .find({"ip": ip}, {"_id": 0})
            .sort("timestamp", -1)
            .limit(5000)
        )

        events = []
        for log in logs:
            dt = _parse_log_datetime(log)
            ts_str = _format_utc_iso(dt) if dt else log.get("timestamp") or log.get("date")

            event = {
                "timestamp": ts_str,
                "protocol": log.get("protocol", "other"),
                "action": log.get("action"),
                "path": log.get("path"),
                "user": log.get("user"),
                "user-agent": log.get("user-agent"),
            }
            events.append((dt.timestamp() if dt else float("inf"), event))

        events.sort(key=lambda x: x[0])
        ordered = [e for _, e in events]

        return jsonify({"ip": ip, "events": ordered})
    except PyMongoError:
        return jsonify({"error": "Database error"}), 500

@app.route("/api/ingest", methods=["POST"])
# POST /api/ingest — Receive and deduplicate logs from agents
def api_ingest():
    client_cn = request.headers.get("X-SSL-Client-CN", "")
    if not client_cn:
        return jsonify({"error": "Missing client certificate CN"}), 401

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON body"}), 400

    agent_id = data.get("agent_id", "")
    batch = data.get("batch", [])

    if agent_id != client_cn:
        return jsonify({"error": "agent_id does not match certificate CN"}), 403

    try:
        db = get_db()
        if not db["agents"].find_one({"agent_id": agent_id}, {"_id": 1}):
            return jsonify({"error": "Agent not registered"}), 403
    except PyMongoError:
        return jsonify({"error": "Database error"}), 500

    if not isinstance(batch, list):
        return jsonify({"error": "batch must be an array"}), 400

    if len(batch) > MAX_BATCH_SIZE:
        return jsonify({"error": f"Batch too large (max {MAX_BATCH_SIZE})"}), 413

    try:
        db = get_db()
        col = db["logs"]
        bulk_ops = []
        seen = set()
        duplicates = 0

        for entry in batch:
            if not isinstance(entry, dict):
                continue

            if not REQUIRED_LOG_FIELDS.issubset(entry.keys()):
                continue

            sanitized = {}
            for k, v in entry.items():
                if isinstance(v, str):
                    sanitized[k] = _sanitize_str(v)
                else:
                    sanitized[k] = v

            if not _normalize_log_timestamp(sanitized):
                continue

            sanitized["agent_id"] = _sanitize_str(agent_id, 64)

            uid = entry.get("hash") or _compute_uid(sanitized)
            if uid in seen:
                duplicates += 1
                continue
            seen.add(uid)

            sanitized["_id"] = uid
            bulk_ops.append(UpdateOne(
                {"_id": uid},
                {"$setOnInsert": sanitized},
                upsert=True
            ))

        ingested = 0
        if bulk_ops:
            result = col.bulk_write(bulk_ops, ordered=False)
            ingested = result.upserted_count
            duplicates += (len(bulk_ops) - ingested)

        db["agents"].update_one(
            {"agent_id": agent_id},
            {"$set": {"last_push": datetime.now(timezone.utc).isoformat()}},
        )

        return jsonify({"status": "ok", "ingested": ingested, "duplicates": duplicates})

    except PyMongoError:
        return jsonify({"error": "Ingestion failed"}), 503

@app.route("/api/geoip", methods=["POST"])
# POST /api/geoip — Batch geolocate IPs via ip-api.com
def api_geoip():
    data = request.get_json(silent=True)
    if not data or not isinstance(data.get("ips"), list):
        return jsonify({"error": "Expected {ips: [...]}"}), 400

    raw_ips = data["ips"][:100]
    ips = []
    for ip in raw_ips:
        try:
            addr = ipaddress.ip_address(ip)
            if (not addr.is_private and not addr.is_loopback
                    and not addr.is_link_local and not addr.is_multicast
                    and not addr.is_reserved and not addr.is_unspecified):
                ips.append(str(addr))
        except ValueError:
            continue

    ips = list(set(ips))
    result = {}

    try:
        db = get_db()
        cache = db["geoip_cache"]

        cached = list(cache.find({"_id": {"$in": ips}}))
        for doc in cached:
            result[doc["_id"]] = doc.get("country", "??")

        uncached = [ip for ip in ips if ip not in result]

        for i in range(0, len(uncached), 100):
            batch = uncached[i:i + 100]
            try:
                payload = json.dumps(
                    [{"query": ip, "fields": "query,countryCode"} for ip in batch]
                ).encode()
                req = urllib.request.Request(
                    "http://ip-api.com/batch",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    api_result = json.loads(resp.read())
                    ops = []
                    for entry in api_result:
                        ip_addr = entry.get("query", "")
                        cc = entry.get("countryCode", "??")
                        result[ip_addr] = cc
                        ops.append(UpdateOne(
                            {"_id": ip_addr},
                            {"$set": {"country": cc, "cached_at": datetime.now(timezone.utc).isoformat()}},
                            upsert=True,
                        ))
                    if ops:
                        cache.bulk_write(ops, ordered=False)
            except Exception:
                for ip in batch:
                    result.setdefault(ip, "??")

    except PyMongoError:
        pass

    return jsonify(result)

@app.route("/api/geoip/<ip>", methods=["GET"])
# GET /api/geoip/<ip> — Detailed geolocation for a single public IP
def api_geoip_details(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400

    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return jsonify({"public": False}), 200

    ip_str = str(addr)

    try:
        db = get_db()
        cache = db["geoip_cache"]
        doc = cache.find_one({"_id": ip_str}) or {}

        needs_refresh = not all(k in doc for k in ("country_name", "city", "region_name"))

        if needs_refresh:
            try:
                payload = json.dumps(
                    [{"query": ip_str, "fields": "query,countryCode,country,regionName,city"}]
                ).encode()
                req = urllib.request.Request(
                    "http://ip-api.com/batch",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    api_result = json.loads(resp.read())
                    if api_result and isinstance(api_result, list):
                        entry = api_result[0]
                        doc = {
                            "country": entry.get("countryCode", "??"),
                            "country_name": entry.get("country", ""),
                            "region_name": entry.get("regionName", ""),
                            "city": entry.get("city", ""),
                            "cached_at": datetime.now(timezone.utc).isoformat(),
                        }
                        cache.update_one({"_id": ip_str}, {"$set": doc}, upsert=True)
            except Exception:
                pass

        return jsonify({
            "public": True,
            "ip": ip_str,
            "country": doc.get("country", "??"),
            "country_name": doc.get("country_name", ""),
            "region": doc.get("region_name", ""),
            "city": doc.get("city", ""),
        })

    except PyMongoError:
        return jsonify({"error": "Database error"}), 500

@app.route("/api/enroll", methods=["POST"])
# POST /api/enroll — Agent enrollment with one-time token
def api_enroll():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON body"}), 400

    token = data.get("token", "")

    if not token:
        return jsonify({"error": "Missing token"}), 400

    try:
        db = get_db()
        col = db["enrollment_tokens"]

        doc = col.find_one_and_delete({
            "token": token,
            "expires_at": {"$gt": datetime.now(timezone.utc).isoformat()}
        })

        if not doc:
            return jsonify({"error": "Invalid or expired token"}), 403

        agent_id = doc.get("agent_id", "")

        cert_dir = doc.get("cert_dir", "")
        pki_base = os.path.abspath(os.getenv("MELISSAE_CERTS_DIR", "/certs"))
        cert_dir = os.path.abspath(cert_dir)
        if not cert_dir.startswith(pki_base + os.sep) and cert_dir != pki_base:
            return jsonify({"error": "Invalid certificate path"}), 403
        if not cert_dir or not os.path.isdir(cert_dir):
            return jsonify({"error": "Certificate bundle not found — re-run enroll on manager"}), 500

        import base64
        cert_files = {
            "agent_crt": os.path.join(cert_dir, f"{agent_id}.crt"),
            "agent_key": os.path.join(cert_dir, f"{agent_id}.key"),
            "ca_crt": os.path.join(cert_dir, "ca.crt"),
        }
        bundle = {}
        for key, fpath in cert_files.items():
            if not os.path.isfile(fpath):
                return jsonify({"error": f"Missing {os.path.basename(fpath)}"}), 500
            with open(fpath, 'rb') as f:
                bundle[key] = base64.b64encode(f.read()).decode()

        db["agents"].update_one(
            {"agent_id": agent_id},
            {"$set": {
                "agent_id": agent_id,
                "registered_at": datetime.now(timezone.utc).isoformat(),
                "status": "enrolled",
            }},
            upsert=True
        )

        return jsonify({"status": "ok", "agent_id": agent_id, "agent_crt": bundle["agent_crt"], "agent_key": bundle["agent_key"], "ca_crt": bundle["ca_crt"]})

    except PyMongoError:
        return jsonify({"error": "Enrollment failed"}), 500

@app.route("/api/agents", methods=["GET"])
# GET /api/agents — List registered agents
def api_agents():
    try:
        db = get_db()
        data = list(db["agents"].find({}, {"_id": 0}))
        return jsonify(data)
    except PyMongoError:
        return jsonify({"error": "Database error"}), 500


MAX_RESULTS_ALERTS = 5000
VALID_ALERT_STATUSES = {"new", "acknowledged", "resolved"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}
RULES_DIR = os.getenv("MELISSAE_RULES_DIR", "/rules")


@app.route("/api/alerts", methods=["GET"])
# GET /api/alerts — Paginated alerts backlog with filters
def api_alerts():
    try:
        db = get_db()
        try:
            query = _build_alert_query(request.args)
        except ValueError:
            return jsonify({"error": "Invalid query parameters"}), 400

        try:
            limit = max(1, min(int(request.args.get("limit", 500)), MAX_RESULTS_ALERTS))
            skip = max(0, int(request.args.get("skip", 0)))
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid pagination parameters"}), 400

        cursor = db["alerts"].find(query).sort("created_at", -1).skip(skip).limit(limit)
        return jsonify(list(cursor))
    except PyMongoError:
        return jsonify({"error": "Database error"}), 500


@app.route("/api/alerts/count", methods=["GET"])
# GET /api/alerts/count — Counts grouped by status (for navbar badge)
def api_alerts_count():
    try:
        db = get_db()
        try:
            query = _build_alert_query(request.args)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        out = {
            "new": 0,
            "acknowledged": 0,
            "resolved": 0,
            "total": 0,
            "groups": 0,
            "new_groups": 0,
            "severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
        }

        status_pipeline = [{"$match": query}, {"$group": {"_id": "$status", "n": {"$sum": 1}}}]
        for row in db["alerts"].aggregate(status_pipeline):
            status = row.get("_id") or "new"
            if status in out:
                out[status] = int(row.get("n", 0))
            out["total"] += int(row.get("n", 0))

        severity_pipeline = [{"$match": query}, {"$group": {"_id": "$severity", "n": {"$sum": 1}}}]
        for row in db["alerts"].aggregate(severity_pipeline):
            severity = row.get("_id") or "medium"
            if severity in out["severity"]:
                out["severity"][severity] = int(row.get("n", 0))

        groups_pipeline = [
            {"$match": query},
            {"$group": {"_id": {"rule_id": "$rule_id", "ip": "$ip"}}},
            {"$count": "n"},
        ]
        rows = list(db["alerts"].aggregate(groups_pipeline))
        if rows:
            out["groups"] = int(rows[0].get("n", 0))

        new_group_query = dict(query)
        new_group_query["status"] = "new"
        group_pipeline = [
            {"$match": new_group_query},
            {"$group": {"_id": {"rule_id": "$rule_id", "ip": "$ip"}}},
            {"$count": "n"},
        ]
        rows = list(db["alerts"].aggregate(group_pipeline))
        if rows:
            out["new_groups"] = int(rows[0].get("n", 0))

        return jsonify(out)
    except PyMongoError:
        return jsonify({"error": "Database error"}), 500


@app.route("/api/alerts/<alert_id>/status", methods=["POST", "PATCH"])
# POST /api/alerts/<id>/status — Update an alert's lifecycle status
def api_alerts_set_status(alert_id):
    if not re.match(r"^[a-f0-9]{32,128}$", alert_id):
        return jsonify({"error": "Invalid alert id"}), 400

    data = request.get_json(silent=True) or {}
    new_status = str(data.get("status", "")).lower().strip()
    if new_status not in VALID_ALERT_STATUSES:
        return jsonify({"error": "Invalid status"}), 400

    try:
        db = get_db()
        result = db["alerts"].update_one(
            {"_id": alert_id},
            {"$set": {
                "status": new_status,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }},
        )
        if result.matched_count == 0:
            return jsonify({"error": "Alert not found"}), 404
        return jsonify({"status": "ok", "alert_id": alert_id, "new_status": new_status})
    except PyMongoError:
        return jsonify({"error": "Database error"}), 500


@app.route("/api/alerts/bulk-status", methods=["POST"])
# POST /api/alerts/bulk-status — Update many alerts at once
def api_alerts_bulk_status():
    data = request.get_json(silent=True) or {}
    ids = data.get("ids") or []
    new_status = str(data.get("status", "")).lower().strip()
    if not isinstance(ids, list) or not ids:
        return jsonify({"error": "Missing ids"}), 400
    if new_status not in VALID_ALERT_STATUSES:
        return jsonify({"error": "Invalid status"}), 400

    safe_ids = [i for i in ids if isinstance(i, str) and re.match(r"^[a-f0-9]{32,128}$", i)]
    if not safe_ids:
        return jsonify({"error": "No valid ids"}), 400
    if len(safe_ids) > 1000:
        return jsonify({"error": "Too many ids (max 1000)"}), 413

    try:
        db = get_db()
        result = db["alerts"].update_many(
            {"_id": {"$in": safe_ids}},
            {"$set": {
                "status": new_status,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }},
        )
        return jsonify({"status": "ok", "updated": result.modified_count})
    except PyMongoError:
        return jsonify({"error": "Database error"}), 500


@app.route("/api/rules", methods=["GET"])
# GET /api/rules — List rules with last-run metadata
def api_rules():
    rules = []
    try:
        if os.path.isdir(RULES_DIR):
            import yaml
            for fname in sorted(os.listdir(RULES_DIR)):
                if not fname.endswith((".yml", ".yaml")):
                    continue
                fpath = os.path.join(RULES_DIR, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        raw = yaml.safe_load(f)
                except (OSError, yaml.YAMLError):
                    continue
                if not isinstance(raw, dict):
                    continue
                rules.append({
                    "id": raw.get("id"),
                    "name": raw.get("name"),
                    "description": raw.get("description"),
                    "severity": raw.get("severity", "medium"),
                    "enabled": bool(raw.get("enabled", True)),
                    "schedule": raw.get("schedule"),
                    "lookback": raw.get("lookback"),
                    "mql": raw.get("mql"),
                    "group_by": raw.get("group_by", "ip"),
                    "threshold": raw.get("threshold", 1),
                    "score": raw.get("score", 0),
                    "tags": raw.get("tags") or [],
                    "mitre": raw.get("mitre") or [],
                    "source_file": fname,
                })
    except OSError:
        return jsonify({"error": "Rules directory unavailable"}), 500

    try:
        db = get_db()
        runs = {doc["_id"]: doc for doc in db["rule_runs"].find({})}
        for r in rules:
            run = runs.get(r["id"])
            if run:
                r["last_run_at"] = run.get("last_run_at")
                r["last_alerts_emitted"] = run.get("last_alerts_emitted", 0)
                r["last_groups_triggered"] = run.get("last_groups_triggered", 0)
    except PyMongoError:
        pass

    return jsonify(rules)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

