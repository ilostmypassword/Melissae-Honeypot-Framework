import json
from collections import defaultdict
from pathlib import Path

# Scoring rules by IP
def calculate_protocol_score(ip_data):
    http_count = 0
    mqtt_count = 0
    ssh_failed = False
    ssh_success = False
    ftp_failed = False
    ftp_success = False
    modbus_write = False
    modbus_read = False

    for entry in ip_data:
        protocol = entry.get('protocol', '').upper()
        action = entry.get('action', '').lower()

        if protocol == 'HTTP':
            http_count += 1
        elif protocol == 'MQTT':
            mqtt_count += 1
        elif protocol == 'SSH':
            if 'failed' in action:
                ssh_failed = True
            elif 'successful' in action:
                ssh_success = True
        elif protocol == 'FTP':
            if 'failed' in action:
                ftp_failed = True
            elif 'successful' in action:
                ftp_success = True
        elif protocol == 'MODBUS':
            if 'write' in action:
                modbus_write = True
            elif 'read' in action:
                modbus_read = True

    # Nefarious - Multiple successful compromises or Modbus writes and one successful compromise
    if (ssh_success and ftp_success) or (modbus_write and (ssh_success or ftp_success)):
        return 5

    # Malicious - Single successful compromise or multiple protocols failed with Modbus writes
    elif (ssh_success or ftp_success) or (modbus_write and (ssh_failed or ftp_failed)):
        return 4

    # Suspicious - Failed attempts or excessive HTTP or Modbus reconnaissance
    elif http_count > 50 or mqtt_count > 30 or ssh_failed or ftp_failed or modbus_read:
        return 2

    # Benign
    else:
        return 1

    return 0

def get_verdict(score):
    verdicts = {
        1: "benign",
        2: "suspicious",
        4: "malicious",
        5: "nefarious"
    }
    return verdicts.get(score, "unknown")

# Path validation
def validate_path(base_dir, relative_path):
    full_path = (base_dir / relative_path).resolve(strict=False)
    if not str(full_path).startswith(str(base_dir)):
        raise ValueError("Path outside base directory")
    return full_path

# Logs processing
def process_logs(input_path, output_path):
    if input_path.suffix.lower() != '.json' or output_path.suffix.lower() != '.json':
        raise ValueError("Files must be in JSON format")

    with input_path.open('r', encoding='utf-8') as f:
        logs = json.load(f)

    ip_data = defaultdict(list)
    for entry in logs:
        if not isinstance(entry, dict):
            continue
        ip_data[entry.get('ip', '')].append(entry)

    threats = []
    for ip, entries in ip_data.items():
        if not ip:
            continue
        score = calculate_protocol_score(entries)
        threats.append({
            "type": "ip",
            "ip": ip,
            "protocol-score": score,
            "verdict": get_verdict(score)
        })

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open('w', encoding='utf-8') as f:
        json.dump(threats, f, indent=2, ensure_ascii=False)

# Main
if __name__ == "__main__":
    script_dir = Path(__file__).parent.resolve()
    base_dir = script_dir.parent

    input_rel = Path("dashboard/json/logs.json")
    output_rel = Path("dashboard/json/threats.json")

    input_path = validate_path(base_dir, input_rel)
    output_path = validate_path(base_dir, output_rel)

    process_logs(input_path, output_path)
