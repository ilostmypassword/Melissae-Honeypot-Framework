from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient, UpdateOne
from pymongo.errors import PyMongoError
import hashlib
import ipaddress
import json
import os
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

REQUIRED_LOG_FIELDS = {"protocol", "date", "ip", "action"}

MAX_FIELD_LEN = 512

def get_db():
    client = MongoClient(MONGO_URI)
    return client[DB_NAME]

# Sanitize a string value (strip $ operators, limit length)
def _sanitize_str(val, max_len=MAX_FIELD_LEN):
    """Sanitize a string field: strip control chars, limit length, block $ operators."""
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

@app.route("/api/logs", methods=["GET"])
# GET /api/logs — Paginated log retrieval with filters
def api_logs():
    try:
        db = get_db()
        query = {}
        agent_id = request.args.get("agent_id")
        if agent_id:
            query["agent_id"] = _sanitize_str(agent_id, 64)
        try:
            limit = max(1, min(int(request.args.get("limit", MAX_RESULTS_LOGS)), MAX_RESULTS_LOGS))
            skip = max(0, int(request.args.get("skip", 0)))
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid pagination parameters"}), 400
        data = list(db["logs"].find(query, {"_id": 0}).sort("timestamp", -1).skip(skip).limit(limit))
        return jsonify(data)
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
        logs = list(db["logs"].find({"ip": ip}, {"_id": 0}))

        events = []
        for log in logs:
            ts_str = log.get("timestamp")
            dt = None

            if ts_str:
                try:
                    dt = datetime.fromisoformat(ts_str)
                except ValueError:
                    dt = None

            if not dt and log.get("date") and log.get("hour"):
                ts_str = f"{log['date']} {log['hour']}"
                try:
                    dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    dt = None

            if not dt and log.get("date"):
                ts_str = log.get("date")
                try:
                    dt = datetime.fromisoformat(ts_str)
                except ValueError:
                    dt = None

            event = {
                "timestamp": dt.isoformat() if dt else ts_str,
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
    """
    Receives a batch of parsed logs from an agent.
    Nginx terminates mTLS and injects X-SSL-Client-CN header.
    """
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
            if not addr.is_private and not addr.is_loopback:
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

@app.route("/api/enroll", methods=["POST"])
# POST /api/enroll — Agent enrollment with one-time token
def api_enroll():
    """
    Agent enrollment via one-time token.
    The manager CLI generates a token and stores it in MongoDB.
    The agent sends the token to receive its certificate bundle.
    """
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

