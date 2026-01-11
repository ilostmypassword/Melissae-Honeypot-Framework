import os
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

from pymongo import MongoClient
from pymongo.errors import PyMongoError

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")

SENSITIVE_HTTP_PATHS = ["/wp-admin", "/phpmyadmin", "/.git", "/.env", "/admin", "/login", "/shell", "/cgi-bin"]
SENSITIVE_SSH_COMMANDS = ["sudo", "wget", "curl", "nc", "ncat", "netcat", "powershell", "chmod +x", "useradd", "ssh-keygen"]


def parse_timestamp(entry: Dict) -> Tuple[datetime, str]:
    """Return naive datetime if possible plus raw string for reference."""
    ts_raw = entry.get("timestamp") or ""
    dt = None
    if ts_raw:
        try:
            dt = datetime.fromisoformat(ts_raw.replace("Z", ""))
        except ValueError:
            dt = None
    if not dt and entry.get("date") and entry.get("hour"):
        try:
            dt = datetime.strptime(f"{entry['date']} {entry['hour']}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            dt = None
    return dt, ts_raw


def detect_bursts(events: List[datetime], window_minutes: int = 5) -> int:
    if not events:
        return 0
    events = sorted([e for e in events if e])
    max_hits = 0
    start = 0
    for end in range(len(events)):
        while events[end] - events[start] > timedelta(minutes=window_minutes):
            start += 1
        max_hits = max(max_hits, end - start + 1)
    return max_hits


def calculate_protocol_score(ip_data: List[Dict]) -> Tuple[int, float, List[str], datetime, datetime]:
    http_events: List[datetime] = []
    http_count = 0
    ssh_success = ssh_failed = 0
    ftp_success = ftp_failed = 0
    mqtt_events = 0
    modbus_reads = 0
    modbus_writes = 0
    sensitive_paths = 0
    sensitive_cmds = 0
    protocols_seen = set()
    reasons: List[str] = []
    first_seen = last_seen = None

    for entry in ip_data:
        protocol = (entry.get('protocol') or '').lower()
        action = (entry.get('action') or '').lower()
        path = (entry.get('path') or '')
        cmd = action
        dt, ts_raw = parse_timestamp(entry)

        if dt:
            first_seen = dt if not first_seen else min(first_seen, dt)
            last_seen = dt if not last_seen else max(last_seen, dt)

        protocols_seen.add(protocol)

        if protocol == 'http':
            http_count += 1
            http_events.append(dt if dt else None)
            if any(p.lower() in path.lower() for p in SENSITIVE_HTTP_PATHS):
                sensitive_paths += 1
        elif protocol == 'mqtt':
            mqtt_events += 1
        elif protocol == 'ssh':
            if 'successful' in action:
                ssh_success += 1
            elif 'failed' in action:
                ssh_failed += 1
            if any(keyword in cmd for keyword in SENSITIVE_SSH_COMMANDS):
                sensitive_cmds += 1
        elif protocol == 'ftp':
            if 'successful' in action:
                ftp_success += 1
            elif 'failed' in action:
                ftp_failed += 1
        elif protocol == 'modbus':
            if 'write' in action:
                modbus_writes += 1
            elif 'read' in action:
                modbus_reads += 1

    http_burst = detect_bursts([e for e in http_events if e], window_minutes=5)

    score = 1
    signals = 0

    def bump(target: int, reason: str):
        nonlocal score, signals
        if reason not in reasons:
            reasons.append(reason)
            signals += 1
        score = max(score, target)

    # Legacy high-severity combos
    if ssh_success and ftp_success:
        bump(5, "Multiple services compromised (SSH + FTP)")
    if modbus_writes and (ssh_success or ftp_success):
        bump(5, "ICS tamper plus valid creds")

    # Legacy malicious paths
    if ssh_success or ftp_success:
        bump(4, "Successful SSH/FTP login")
    if modbus_writes and (ssh_failed or ftp_failed):
        bump(4, "Modbus writes after failed auth")

    # Legacy suspicious thresholds
    if http_count > 50:
        bump(2, "Excessive HTTP hits (>50)")
    if mqtt_events > 30:
        bump(2, "High MQTT activity (>30)")
    if modbus_reads:
        bump(2, "Modbus read operations")
    if ssh_failed or ftp_failed:
        bump(2, "Auth failures (SSH/FTP)")

    # Newer behavioral signals
    if http_burst >= 50:
        bump(2, "HTTP burst (>50 hits / 5min)")
    if ssh_failed >= 5 or ftp_failed >= 5:
        bump(2, "Brute-force attempts (>=5 failures)")
    if modbus_reads >= 3:
        bump(2, "Modbus reconnaissance (>=3 reads)")
    if sensitive_paths:
        bump(4, "Sensitive HTTP paths probed")
    if sensitive_cmds:
        bump(4, "Post-compromise tooling (SSH commands)")
    if modbus_writes:
        bump(4, "Modbus write operations")
    if len(protocols_seen) >= 3 and (ssh_failed or ftp_failed or modbus_writes):
        bump(4, "Multi-protocol intrusion pattern")

    # Escalation for strong combos
    if score >= 4 and (http_burst >= 50 or sensitive_paths or sensitive_cmds):
        bump(5, "Layered intrusion with high-risk web or post-exploit activity")

    # Confirmed SSH/FTP access
    success_bonus = 0
    if ssh_success:
        success_bonus += 2
    if ftp_success:
        success_bonus += 2

    confidence_raw = 0.2 + 0.15 * max(1, signals) + 0.25 * success_bonus
    confidence = min(1.0, confidence_raw)

    # Cap score to 4 since verdicts are now Benign/Suspicious/Malicious
    capped_score = min(score, 4)

    return capped_score, confidence, reasons, first_seen, last_seen

# Fetch logs from MongoDB
def fetch_logs_from_mongo():
    try:
        client = MongoClient(MONGO_URI)
        col = client['melissae']['logs']
        return list(col.find({}, {'_id': 0}))
    except PyMongoError as e:
        print(f"[threatIntel] Mongo read error: {e}")
        return []

# Write threats IoCs to MongoDB
def write_threats_to_mongo(threats):
    try:
        client = MongoClient(MONGO_URI)
        col = client['melissae']['threats']
        col.drop()
        if threats:
            col.insert_many(threats)
        col.create_index('ip', unique=True)
    except PyMongoError as e:
        print(f"[threatIntel] Mongo write error: {e}")
        
# Process logs
def process_logs(logs):
    ip_data = defaultdict(list)
    for entry in logs:
        if not isinstance(entry, dict):
            continue
        ip_data[entry.get('ip', '')].append(entry)

    threats = []
    for ip, entries in ip_data.items():
        if not ip:
            continue

        score, confidence, reasons, first_seen, last_seen = calculate_protocol_score(entries)

        threat_doc = {
            "type": "ip",
            "ip": ip,
            "protocol-score": score,
            "verdict": "benign",
            "confidence": round(confidence, 2),
            "reasons": reasons,
        }

        if score >= 4:
            threat_doc["verdict"] = "malicious"
        elif score >= 2:
            threat_doc["verdict"] = "suspicious"

        if first_seen:
            threat_doc["first_seen"] = first_seen.isoformat()
        if last_seen:
            threat_doc["last_seen"] = last_seen.isoformat()

        threats.append(threat_doc)

    write_threats_to_mongo(threats)

# Main
if __name__ == "__main__":
    logs = fetch_logs_from_mongo()
    process_logs(logs)
