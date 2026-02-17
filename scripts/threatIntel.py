import ipaddress
import json
import math
import os
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from pymongo import MongoClient, UpdateOne
from pymongo.errors import PyMongoError

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")

# Sensitive patterns for signal detection
SENSITIVE_HTTP_PATHS = [
    "/wp-admin", "/wp-login", "/phpmyadmin", "/.git", "/.env",
    "/admin", "/login", "/shell", "/cgi-bin", "/xmlrpc",
    "/console", "/manager", "/actuator", "/debug",
    "/.aws", "/.ssh", "/passwd", "/config", "/backup",
]
SENSITIVE_SSH_COMMANDS = [
    "sudo", "wget", "curl", "nc", "ncat", "netcat", "powershell",
    "chmod +x", "useradd", "ssh-keygen", "cat /etc/passwd",
    "cat /etc/shadow", "uname -a", "id", "whoami", "ifconfig",
    "ip addr", "iptables", "crontab", "base64", "python",
    "perl", "ruby", "nmap", "scp", "sftp",
]

VERDICT_MALICIOUS = 70
VERDICT_SUSPICIOUS = 30

def parse_timestamp(entry: Dict) -> Optional[datetime]:
    ts_raw = entry.get("timestamp") or ""
    if ts_raw:
        try:
            dt = datetime.fromisoformat(ts_raw.replace("Z", ""))
            return dt.replace(tzinfo=None) if dt.tzinfo else dt
        except ValueError:
            pass
    date_str = entry.get("date")
    hour_str = entry.get("hour")
    if date_str and hour_str:
        try:
            return datetime.strptime(f"{date_str} {hour_str}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    return None


def detect_bursts(events: List[Optional[datetime]], window_minutes: int = 5) -> int:
    clean = sorted(e for e in events if e is not None)
    if not clean:
        return 0
    window = timedelta(minutes=window_minutes)
    max_hits = start = 0
    for end in range(len(clean)):
        while clean[end] - clean[start] > window:
            start += 1
        max_hits = max(max_hits, end - start + 1)
    return max_hits

def calculate_threat_score(
    ip_data: List[Dict],
) -> Tuple[int, float, List[str], Optional[datetime], Optional[datetime]]:
    http_timestamps: List[Optional[datetime]] = []
    ssh_timestamps: List[Optional[datetime]] = []
    ftp_timestamps: List[Optional[datetime]] = []
    http_count = 0
    ssh_success = ssh_failed = 0
    ftp_success = ftp_failed = 0
    ftp_transfers = 0
    mqtt_events = 0
    modbus_reads = modbus_writes = 0
    telnet_timestamps: List[Optional[datetime]] = []
    telnet_success = telnet_failed = 0
    cve_exploits: set = set()
    sensitive_paths = 0
    unique_sensitive: set = set()
    sensitive_cmds = 0
    protocols_seen: set = set()
    reasons: List[str] = []
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    for entry in ip_data:
        protocol = (entry.get("protocol") or "").lower()
        action = (entry.get("action") or "").lower()
        path = (entry.get("path") or "").lower()
        cve = entry.get("cve")
        if cve:
            cve_exploits.add(cve)
        dt = parse_timestamp(entry)

        if dt:
            first_seen = dt if first_seen is None else min(first_seen, dt)
            last_seen = dt if last_seen is None else max(last_seen, dt)

        protocols_seen.add(protocol)

        if protocol == "http":
            http_count += 1
            http_timestamps.append(dt)
            for sp in SENSITIVE_HTTP_PATHS:
                if sp.lower() in path:
                    sensitive_paths += 1
                    unique_sensitive.add(sp.lower())

        elif protocol == "ssh":
            ssh_timestamps.append(dt)
            if "successful" in action:
                ssh_success += 1
            elif "failed" in action:
                ssh_failed += 1
            if any(kw in action for kw in SENSITIVE_SSH_COMMANDS):
                sensitive_cmds += 1

        elif protocol == "ftp":
            ftp_timestamps.append(dt)
            if "successful" in action:
                ftp_success += 1
            elif "failed" in action:
                ftp_failed += 1
            if "upload" in action or "download" in action:
                ftp_transfers += 1

        elif protocol == "modbus":
            if "write" in action:
                modbus_writes += 1
            elif "read" in action:
                modbus_reads += 1

        elif protocol == "mqtt":
            mqtt_events += 1

        elif protocol == "telnet":
            telnet_timestamps.append(dt)
            if "successful" in action:
                telnet_success += 1
            elif "failed" in action:
                telnet_failed += 1

    http_burst = detect_bursts(http_timestamps, window_minutes=5)
    ssh_burst = detect_bursts(ssh_timestamps, window_minutes=5)
    ftp_burst = detect_bursts(ftp_timestamps, window_minutes=5)
    telnet_burst = detect_bursts(telnet_timestamps, window_minutes=5)

    total_events = len(ip_data)

    raw = 0.0

    def add(points: float, reason: str) -> None:
        nonlocal raw
        raw += points
        if reason not in reasons:
            reasons.append(reason)

    if http_count > 0:
        add(min(20, 5 + 5 * math.log2(max(1, http_count))),
            f"HTTP activity ({http_count} requests)")

    if mqtt_events > 0:
        add(min(15, 5 + 4 * math.log2(max(1, mqtt_events))),
            f"MQTT activity ({mqtt_events} events)")

    if modbus_reads > 0:
        add(min(25, 10 + 5 * modbus_reads),
            f"Modbus read operations ({modbus_reads})")

    if sensitive_paths > 0:
        path_score = min(35, 15 + 5 * len(unique_sensitive))
        add(path_score,
            f"Sensitive HTTP paths probed ({sensitive_paths} hits on "
            f"{len(unique_sensitive)} distinct paths)")

    if http_burst >= 20:
        add(min(25, 10 + 0.3 * http_burst),
            f"HTTP burst ({http_burst} hits in 5 min)")

    auth_failures = ssh_failed + ftp_failed + telnet_failed
    if auth_failures >= 5:
        add(min(35, 15 + 2 * auth_failures),
            f"Brute-force attempts ({auth_failures} failures)")
    elif auth_failures >= 1:
        add(8 * auth_failures,
            f"Authentication failures ({auth_failures})")

    if ssh_burst >= 5:
        add(min(20, 10 + ssh_burst),
            f"SSH burst ({ssh_burst} attempts in 5 min)")

    if ftp_burst >= 5:
        add(min(20, 10 + ftp_burst),
            f"FTP burst ({ftp_burst} attempts in 5 min)")

    if telnet_burst >= 5:
        add(min(20, 10 + telnet_burst),
            f"Telnet burst ({telnet_burst} attempts in 5 min)")

    if len(telnet_timestamps) > 0:
        add(15, f"Telnet activity ({len(telnet_timestamps)} events — deprecated protocol)")
    if telnet_success > 0:
        add(45, f"Successful Telnet login ({telnet_success}) — possible CVE exploitation")

    if cve_exploits:
        cve_list = ', '.join(sorted(cve_exploits))
        add(50, f"CVE exploitation confirmed ({cve_list})")

    if ssh_success > 0:
        add(40, f"Successful SSH login ({ssh_success})")
    if ftp_success > 0:
        add(35, f"Successful FTP login ({ftp_success})")
    if ftp_transfers > 0:
        add(min(25, 10 + 5 * ftp_transfers),
            f"FTP file transfers ({ftp_transfers})")

    if sensitive_cmds > 0:
        add(min(45, 20 + 5 * sensitive_cmds),
            f"Post-compromise commands ({sensitive_cmds})")

    if modbus_writes > 0:
        add(min(50, 25 + 10 * modbus_writes),
            f"Modbus write operations ({modbus_writes})")

    if len(protocols_seen) >= 3:
        add(15, f"Multi-protocol activity ({', '.join(sorted(protocols_seen))})")
    if ssh_success and ftp_success:
        add(20, "Multiple services compromised (SSH + FTP)")
    if telnet_success and (ssh_success or ftp_success):
        add(20, "Multiple services compromised (Telnet + SSH/FTP)")
    if modbus_writes and (ssh_success or ftp_success):
        add(25, "ICS tampering with valid credentials")

    score = max(0, min(100, int(round(raw))))

    signal_count = len(reasons)

    c_volume = min(1.0, math.log2(max(1, total_events)) / 7)

    c_signals = min(1.0, signal_count / 5)

    c_protocols = min(1.0, len(protocols_seen) / 3)

    c_time = 0.3
    if first_seen and last_seen:
        hours = (last_seen - first_seen).total_seconds() / 3600
        c_time = min(1.0, 0.3 + 0.7 * min(hours, 24) / 24)

    c_certainty = 0.0
    if ssh_success or ftp_success or telnet_success:
        c_certainty += 0.5
    if cve_exploits:
        c_certainty += 0.3
    if sensitive_cmds:
        c_certainty += 0.3
    if modbus_writes:
        c_certainty += 0.3
    c_certainty = min(1.0, c_certainty)

    confidence = (
        0.20 * c_volume
        + 0.25 * c_signals
        + 0.10 * c_protocols
        + 0.15 * c_time
        + 0.30 * c_certainty
    )
    confidence = max(0.10, min(1.0, confidence))

    return score, confidence, reasons, first_seen, last_seen

def is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return True


def get_existing_geo(ips: List[str]) -> Dict[str, Dict]:
    try:
        client = MongoClient(MONGO_URI)
        col = client["melissae"]["threats"]
        docs = col.find(
            {"ip": {"$in": ips}, "geo": {"$exists": True}},
            {"ip": 1, "geo": 1, "_id": 0},
        )
        return {doc["ip"]: doc["geo"] for doc in docs}
    except PyMongoError:
        return {}


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


def batch_geolocate(ips: List[str]) -> Dict[str, Dict]:
    public_ips = [ip for ip in ips if not is_private_ip(ip)]
    if not public_ips:
        return {}

    results: Dict[str, Dict] = {}
    batch_size = 100

    for i in range(0, len(public_ips), batch_size):
        batch = public_ips[i : i + batch_size]
        payload = json.dumps(
            [
                {
                    "query": ip,
                    "fields": "status,query,country,countryCode,city,lat,lon,isp,org",
                }
                for ip in batch
            ]
        ).encode("utf-8")

        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())

            if not isinstance(data, list):
                print("[threatIntel] GeoIP: unexpected response type")
                continue

            for item in data:
                if not isinstance(item, dict):
                    continue
                if item.get("status") != "success":
                    continue
                query_ip = item.get("query", "")
                if query_ip not in batch:
                    continue

                lat = _validate_coordinate(item.get("lat"), -90, 90)
                lon = _validate_coordinate(item.get("lon"), -180, 180)
                if lat == 0.0 and lon == 0.0:
                    continue

                results[query_ip] = {
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

def fetch_logs_from_mongo() -> List[Dict]:
    try:
        client = MongoClient(MONGO_URI)
        col = client["melissae"]["logs"]
        return list(col.find({}, {"_id": 0}))
    except PyMongoError as e:
        print(f"[threatIntel] Mongo read error: {e}")
        return []


def write_threats_to_mongo(threats: List[Dict]) -> None:
    """Upsert threat records by IP — preserves any manually-added fields."""
    try:
        client = MongoClient(MONGO_URI)
        col = client["melissae"]["threats"]

        current_ips = {t["ip"] for t in threats if t.get("ip")}

        if threats:
            ops = [
                UpdateOne({"ip": t["ip"]}, {"$set": t}, upsert=True)
                for t in threats
            ]
            col.bulk_write(ops, ordered=False)

        if current_ips:
            col.delete_many({"ip": {"$nin": list(current_ips)}})

        col.create_index("ip", unique=True)
    except PyMongoError as e:
        print(f"[threatIntel] Mongo write error: {e}")

def process_logs(logs: List[Dict]) -> None:
    ip_data: Dict[str, List[Dict]] = defaultdict(list)
    for entry in logs:
        if not isinstance(entry, dict):
            continue
        ip = entry.get("ip", "")
        if ip:
            ip_data[ip].append(entry)

    all_ips = [ip for ip in ip_data if ip]
    existing_geo = get_existing_geo(all_ips)
    new_ips = [ip for ip in all_ips if ip not in existing_geo]
    if new_ips:
        fresh_geo = batch_geolocate(new_ips)
        existing_geo.update(fresh_geo)

    threats = []
    for ip, entries in ip_data.items():
        score, confidence, reasons, first_seen, last_seen = calculate_threat_score(entries)

        if score >= VERDICT_MALICIOUS:
            verdict = "malicious"
        elif score >= VERDICT_SUSPICIOUS:
            verdict = "suspicious"
        else:
            verdict = "benign"

        threat_doc = {
            "type": "ip",
            "ip": ip,
            "protocol-score": score,
            "verdict": verdict,
            "confidence": round(confidence, 2),
            "reasons": reasons,
        }
        if first_seen:
            threat_doc["first_seen"] = first_seen.isoformat()
        if last_seen:
            threat_doc["last_seen"] = last_seen.isoformat()

        geo = existing_geo.get(ip)
        if geo:
            threat_doc["geo"] = geo

        threats.append(threat_doc)

    write_threats_to_mongo(threats)


# Main
if __name__ == "__main__":
    logs = fetch_logs_from_mongo()
    process_logs(logs)
