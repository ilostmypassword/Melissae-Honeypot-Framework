#!/usr/bin/env python3

import os
import re
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Optional

from pymongo import MongoClient, UpdateOne
from pymongo.errors import PyMongoError

# Paths
WORKING_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017')

# Patterns (If you want to create a module, you need to add your patterns here)
PATTERNS = {
    'ssh_auth': {
        'source': 'modules/ssh/logs/sshd.log',
        'patterns': {
            'date': re.compile(r'(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+\d{2}:\d{2})'),
            'ip': re.compile(r'from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'),
            'action': re.compile(r'(?P<action>Failed password|Accepted password|Accepted publickey|Accepted keyboard-interactive|Invalid user|Connection closed)'),
            'user': re.compile(r'(?:for|user)\s+(?P<user>\S+)')
        }
    },
    'ssh_commands': {
        'source': 'modules/ssh/logs/commands.log',
        'pattern': re.compile(r'(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| (?P<ip>\d+\.\d+\.\d+\.\d+) \| (?P<command>.+)')
    },
    'ftp': {
        'source': 'modules/ftp/logs/vsftpd.log',
        'patterns': {
            'connect': re.compile(r'(\w{3} \w{3} \s?\d{1,2} \d{2}:\d{2}:\d{2} \d{4}) \[pid \d+\] CONNECT: Client "(?P<ip>\d+\.\d+\.\d+\.\d+)"'),
            'login': re.compile(r'(\w{3} \w{3} \s?\d{1,2} \d{2}:\d{2}:\d{2} \d{4}) \[pid \d+\] \[(?P<user>[^\]]+)\] (?P<status>OK|FAIL) LOGIN: Client "(?P<ip>\d+\.\d+\.\d+\.\d+)"'),
            'transfer': re.compile(r'(\w{3} \w{3} \s?\d{1,2} \d{2}:\d{2}:\d{2} \d{4}) \[pid \d+\] \[(?P<user>[^\]]+)\] OK (?P<type>UPLOAD|DOWNLOAD): Client "(?P<ip>\d+\.\d+\.\d+\.\d+)", "(?P<file>.+?)", (?P<size>\d+) bytes')
        }
    },
    'http': {
        'source': 'modules/web/logs/access.log',
        'pattern': re.compile(r'^(\S+) - - \[(.*?)\] "(GET|POST|PUT|DELETE|HEAD|OPTIONS|PROPFIND|EWYM) (\S+) HTTP/\d\.\d" (\d+) \d+ ".*?" "(.*?)"$')
    },
    'modbus': {
        'source': 'modules/modbus/logs/modbus.log',
        'pattern': re.compile(r'(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| (?P<ip>\d+\.\d+\.\d+\.\d+) \| (?P<action>.+?)(?:\s\|\s(?P<details>\{.*\}))?$')
    },
    'mqtt': {
        'source': 'modules/mqtt/logs/mosquitto.log',
        'patterns': {
            'connect': re.compile(r'(?P<date>\d+): New client connected from (?P<ip>\d+\.\d+\.\d+\.\d+):\d+'),
            'disconnect': re.compile(r'(?P<date>\d+): Client (?P<user>\S+) disconnected\.'),
            'subscribe': re.compile(r'(?P<date>\d+): Received SUBSCRIBE from (?P<user>\S+)'),
            'subscribe_topic': re.compile(r'^\s+(?P<path>\S+)'),
            'publish': re.compile(r"(?P<date>\d+): Received PUBLISH from (?P<user>\S+).*?'(?P<path>[^']+)'.*?$(?P<size>\d+)\s+bytes$")
        }
    },
    'telnet_cve_2026_24061': {
        'source': 'modules/cve/CVE-2026-24061/logs/auth.log',
        'patterns': {
            'failed_login': re.compile(
                r'^(?P<datetime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})\s+\S+\s+login\[\d+\]:\s+FAILED LOGIN.*?from\s+\'(?P<ip>\d+\.\d+\.\d+\.\d+)\'(?:\s+FOR\s+\'(?P<user>[^\']+)\')?'
            ),
            'root_login': re.compile(
                r'^(?P<datetime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})\s+\S+\s+login\[\d+\]:\s+ROOT LOGIN.*?from\s+\'(?P<ip>\d+\.\d+\.\d+\.\d+)\''
            ),
            'pam_failure': re.compile(
                r'^(?P<datetime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})\s+\S+\s+login\[\d+\]:\s+pam_unix\(login:auth\):\s+authentication failure.*?rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)(?:\s+user=(?P<user>\S+))?'
            ),
        }
    },
    'telnet_cve_2026_24061_commands': {
        'source': 'modules/cve/CVE-2026-24061/logs/commands.log',
        'pattern': re.compile(r'(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| (?P<ip>\d+\.\d+\.\d+\.\d+) \| (?P<user>\S+) \| (?P<command>.+)')
    },
    'telnet': {
        'source': 'modules/telnet/logs/auth.log',
        'patterns': {
            'failed_login': re.compile(
                r'^(?P<datetime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})\s+\S+\s+login\[\d+\]:\s+FAILED LOGIN.*?from\s+\'(?P<ip>\d+\.\d+\.\d+\.\d+)\'(?:\s+FOR\s+\'(?P<user>[^\']+)\')?'
            ),
            'pam_failure': re.compile(
                r'^(?P<datetime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})\s+\S+\s+login\[\d+\]:\s+pam_unix\(login:auth\):\s+authentication failure.*?rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)(?:\s+user=(?P<user>\S+))?'
            ),
            'pam_success': re.compile(
                r'^(?P<datetime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})\s+\S+\s+login\[\d+\]:\s+pam_unix\(login:auth\):.*?rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)(?:\s+user=(?P<user>\S+))?'
            ),
            'session_open': re.compile(
                r'^(?P<datetime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})\s+\S+\s+login\[\d+\]:\s+pam_unix\(login:session\):\s+session opened for user\s+(?P<user>\S+)'
            ),
        }
    },
    'telnet_commands': {
        'source': 'modules/telnet/logs/commands.log',
        'pattern': re.compile(r'(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| (?P<ip>\d+\.\d+\.\d+\.\d+) \| (?P<user>\S+) \| (?P<command>.+)')
    }
}


def compute_uid(log: Dict) -> str:
    key_fields = ['protocol', 'timestamp', 'date', 'hour', 'ip', 'action', 'path', 'user', 'user-agent']
    payload = {k: log.get(k) for k in key_fields if k in log}
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return hashlib.sha1(serialized.encode('utf-8')).hexdigest()


def load_ingestion_state() -> Dict[str, Dict]:
    try:
        client = MongoClient(MONGO_URI)
        col = client['melissae']['ingestion_state']
        doc = col.find_one({'_id': 'logParser'}) or {}
        return doc.get('files', {}), doc.get('telnet_pid_to_ip', {})
    except PyMongoError as e:
        print(f"[logParser] Mongo state read error: {e}")
        return {}, {}


def save_ingestion_state(file_states: Dict[str, Dict], telnet_pid_to_ip: Dict[str, str] = None) -> None:
    try:
        client = MongoClient(MONGO_URI)
        col = client['melissae']['ingestion_state']
        update_doc = {'files': file_states, 'updated_at': datetime.utcnow()}
        if telnet_pid_to_ip is not None:
            update_doc['telnet_pid_to_ip'] = telnet_pid_to_ip
        col.update_one(
            {'_id': 'logParser'},
            {'$set': update_doc},
            upsert=True,
        )
    except PyMongoError as e:
        print(f"[logParser] Mongo state write error: {e}")


def read_new_lines(source: str, file_states: Dict[str, Dict]) -> List[str]:
    if not os.path.exists(source):
        return []

    try:
        stats = os.stat(source)
        size = stats.st_size
        mtime = stats.st_mtime
        state = file_states.get(source, {})
        offset = state.get('offset', 0)
        prev_mtime = state.get('mtime', 0)

        if size < offset or mtime < prev_mtime:
            offset = 0

        with open(source, 'r', encoding='utf-8') as f:
            f.seek(offset)
            lines = f.readlines()
            new_offset = f.tell()

        file_states[source] = {
            'offset': new_offset,
            'mtime': mtime,
            'size': size,
        }
        return lines
    except OSError as e:
        print(f"[logParser] Unable to read {source}: {e}")
        return []


def ensure_indexes(col) -> None:
    try:
        col.create_index('ip')
        col.create_index('protocol')
        col.create_index('date')
    except PyMongoError as e:
        print(f"[logParser] Mongo index error: {e}")

def create_entry(protocol: str, dt: datetime, ip: str, action: str, path: str = None, user_agent: str = None, user: Optional[str] = None, cve: Optional[str] = None) -> Dict:
    if dt.tzinfo is not None:
        dt = dt.replace(tzinfo=None)
    entry = {
        "protocol": protocol,
        "date": dt.strftime('%Y-%m-%d'),
        "hour": dt.strftime('%H:%M:%S'),
        "timestamp": dt.isoformat(sep=' ', timespec='microseconds'),
        "ip": ip,
        "action": action,
    }
    if path:
        entry["path"] = path
    if user_agent:
        entry["user-agent"] = user_agent
    if user and user.lower() != 'unknown':
        entry["user"] = user
    if cve:
        entry["cve"] = cve
    return entry

def parse_ssh_auth_line(line: str) -> Optional[Dict]:
    """Parse a single SSH auth log line into a structured entry."""
    date_match = PATTERNS['ssh_auth']['patterns']['date'].search(line)
    ip_match = PATTERNS['ssh_auth']['patterns']['ip'].search(line)
    action_match = PATTERNS['ssh_auth']['patterns']['action'].search(line)
    user_match = PATTERNS['ssh_auth']['patterns']['user'].search(line)

    if not ip_match or not action_match:
        return None

    dt: Optional[datetime] = None
    if date_match:
        dt = datetime.strptime(date_match.group('date'), "%Y-%m-%dT%H:%M:%S.%f%z").replace(tzinfo=None)
    else:
        syslog_date = re.match(r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})', line)
        if syslog_date:
            year = datetime.utcnow().year
            month = syslog_date.group('month')
            day = syslog_date.group('day')
            time_str = syslog_date.group('time')
            dt = datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")

    if not dt:
        return None

    ip = ip_match.group('ip')
    action = action_match.group('action')
    user = user_match.group('user') if user_match else None

    action_desc = {
        'Accepted password': 'Login successful',
        'Accepted publickey': 'Login successful',
        'Accepted keyboard-interactive': 'Login successful',
        'Failed password': 'Login failed',
        'Invalid user': 'Login failed',
        'Connection closed': 'Connection closed'
    }.get(action, action)

    return create_entry('ssh', dt, ip, action_desc, user=user)

def process_ssh_auth(file_states: Dict[str, Dict]) -> List[Dict]:
    logs = []
    source = os.path.join(WORKING_DIR, PATTERNS['ssh_auth']['source'])
    for line in read_new_lines(source, file_states):
        entry = parse_ssh_auth_line(line)
        if entry:
            logs.append(entry)
    return logs

def process_ssh_commands(file_states: Dict[str, Dict]) -> List[Dict]:
    logs = []
    source = os.path.join(WORKING_DIR, PATTERNS['ssh_commands']['source'])
    for line in read_new_lines(source, file_states):
        match = PATTERNS['ssh_commands']['pattern'].match(line.strip())
        if match:
            dt = datetime.strptime(match.group('date'), "%Y-%m-%d %H:%M:%S")
            raw_command = match.group('command').strip()
            cleaned_command = re.sub(r'^\d+\s+', '', raw_command)
            logs.append(create_entry('ssh', dt, match.group('ip'), cleaned_command))
    return logs

# FTP Module parsing & processing
def parse_ftp_line(line: str) -> Optional[Dict]:
    for pattern_name in ['transfer', 'connect', 'login']:
        pattern = PATTERNS['ftp']['patterns'][pattern_name]
        match = pattern.match(line)
        if match:
            dt = datetime.strptime(match.group(1), '%a %b %d %H:%M:%S %Y')
            if pattern_name == 'transfer':
                return create_entry('ftp', dt, match.group('ip'), f"{match.group('type').capitalize()} of '{match.group('file')}' ({match.group('size')} bytes)", user=match.group('user'))
            elif pattern_name == 'connect':
                return create_entry('ftp', dt, match.group('ip'), 'Connection established')
            elif pattern_name == 'login':
                status = 'Login successful' if match.group('status') == 'OK' else 'Login failed'
                return create_entry('ftp', dt, match.group('ip'), status, user=match.group('user'))
    return None

def process_ftp(file_states: Dict[str, Dict]) -> List[Dict]:
    logs = []
    source = os.path.join(WORKING_DIR, PATTERNS['ftp']['source'])
    for line in read_new_lines(source, file_states):
        entry = parse_ftp_line(line)
        if entry:
            logs.append(entry)
    return logs

# Web Module parsing & processing
def parse_http_line(line: str) -> Optional[Dict]:
    match = PATTERNS['http']['pattern'].match(line.strip())
    if not match:
        return None
    ip = match.group(1)
    dt = datetime.strptime(match.group(2), "%d/%b/%Y:%H:%M:%S %z")
    action = match.group(3)
    path = match.group(4)
    user_agent = match.group(6)
    return create_entry('http', dt, ip, action, path, user_agent)

def process_http(file_states: Dict[str, Dict]) -> List[Dict]:
    logs = []
    source = os.path.join(WORKING_DIR, PATTERNS['http']['source'])
    for line in read_new_lines(source, file_states):
        entry = parse_http_line(line)
        if entry:
            logs.append(entry)
    return logs

# Modbus Module parsing & processing
def parse_modbus_line(line: str) -> Optional[Dict]:
    """Parse a single Modbus log line with optional JSON details."""
    match = PATTERNS['modbus']['pattern'].match(line.strip())
    if not match:
        return None
    
    dt = datetime.strptime(match.group('date'), "%Y-%m-%d %H:%M:%S")
    ip = match.group('ip')
    action = match.group('action')
    details = match.group('details')
    
    if details:
        try:
            details_json = json.loads(details)
            if 'function' in details_json:
                action = f"{action} - {details_json['function']}"
        except json.JSONDecodeError:
            pass
    
    return create_entry('modbus', dt, ip, action)

def process_modbus(file_states: Dict[str, Dict]) -> List[Dict]:
    """Process Modbus honeypot logs."""
    logs = []
    source = os.path.join(WORKING_DIR, PATTERNS['modbus']['source'])
    for line in read_new_lines(source, file_states):
        entry = parse_modbus_line(line)
        if entry:
            logs.append(entry)
    return logs

# Mosquitto Module parsing & processing
def parse_mqtt_line(line: str, next_line: Optional[str], client_ip_map: Dict[str, str]) -> Optional[Dict]:
    p = PATTERNS['mqtt']['patterns']

    m = p['connect'].search(line)
    if m:
        dt = datetime.fromtimestamp(int(m.group('date')))
        ip = m.group('ip')
        client_match = re.search(r'as\s+(?P<client>\S+)', line)
        if client_match:
            client_ip_map[client_match.group('client')] = ip
        return create_entry('mqtt', dt, ip, 'Client connected')

    m = p['disconnect'].search(line)
    if m:
        dt = datetime.fromtimestamp(int(m.group('date')))
        user = m.group('user')
        ip = client_ip_map.get(user, 'unknown')
        return create_entry('mqtt', dt, ip, 'Client disconnected', user=user)

    m = p['subscribe'].search(line)
    if m:
        dt = datetime.fromtimestamp(int(m.group('date')))
        user = m.group('user')
        ip = client_ip_map.get(user, 'unknown')
        topic = None
        if next_line:
            mt = p['subscribe_topic'].match(next_line)
            if mt:
                topic = mt.group('path')
        action = f'Subscribe to "{topic}"' if topic else 'Subscribe'
        return create_entry('mqtt', dt, ip, action, user=user)

    m = p['publish'].search(line)
    if m:
        dt = datetime.fromtimestamp(int(m.group('date')))
        user = m.group('user')
        topic = m.group('path')
        size = m.group('size')
        ip = client_ip_map.get(user, 'unknown')
        action = f'Publish to "{topic}" ({size} bytes)'
        return create_entry('mqtt', dt, ip, action, user=user)

    return None

def process_mqtt(file_states: Dict[str, Dict]) -> List[Dict]:
    logs: List[Dict] = []
    source = os.path.join(WORKING_DIR, PATTERNS['mqtt']['source'])
    lines = read_new_lines(source, file_states)
    if not lines:
        return logs

    client_ip_map: Dict[str, str] = {}

    i = 0
    while i < len(lines):
        line = lines[i].rstrip('\n')
        next_line = lines[i+1].rstrip('\n') if i+1 < len(lines) else None

        conn_match = PATTERNS['mqtt']['patterns']['connect'].search(line)
        if conn_match:
            ip = conn_match.group('ip')
            client_match = re.search(r'as\s+(?P<client>\S+)', line)
            if client_match:
                client_ip_map[client_match.group('client')] = ip

        entry = parse_mqtt_line(line, next_line, client_ip_map)
        if entry:
            logs.append(entry)
            if PATTERNS['mqtt']['patterns']['subscribe'].search(line) and next_line and PATTERNS['mqtt']['patterns']['subscribe_topic'].match(next_line):
                i += 2
                continue
        i += 1

    return logs

# Telnet Module parsing & processing
def parse_syslog_ts(month_str: str, day_str: str, time_str: str) -> datetime:
    year = datetime.utcnow().year
    return datetime.strptime(f"{year} {month_str} {day_str} {time_str}", "%Y %b %d %H:%M:%S")

def parse_iso8601_ts(datetime_str: str) -> datetime:
    dt_part = datetime_str.split('.')[0]
    return datetime.strptime(dt_part, "%Y-%m-%dT%H:%M:%S")

TELNET_PID_RE = re.compile(r'login\[(?P<pid>\d+)\]:')
TELNET_RHOST_RE = re.compile(r'rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)')

def process_telnet_lines(lines: List[str], pid_to_ip: Dict[str, str], patterns_key: str = 'telnet', cve: Optional[str] = None) -> List[Dict]:
    logs = []
    p = PATTERNS[patterns_key]['patterns']
    last_ip = None

    for line in lines:
        line = line.rstrip('\n')
        
        pid_match = TELNET_PID_RE.search(line)
        pid = pid_match.group('pid') if pid_match else None
        
        rhost_match = TELNET_RHOST_RE.search(line)
        if rhost_match:
            last_ip = rhost_match.group('ip')
            if pid:
                pid_to_ip[pid] = last_ip

        if 'root_login' in p:
            m = p['root_login'].match(line)
            if m:
                dt = parse_iso8601_ts(m.group('datetime'))
                ip = m.group('ip') if 'ip' in m.groupdict() else pid_to_ip.get(pid, last_ip)
                logs.append(create_entry('telnet', dt, ip, 'Root login successful', user='root', cve=cve))
                continue

        if 'session_open' in p:
            m = p['session_open'].match(line)
            if m:
                dt = parse_iso8601_ts(m.group('datetime'))
                user = m.group('user').split('(')[0]
                ip = pid_to_ip.get(pid, last_ip)
                logs.append(create_entry('telnet', dt, ip, 'Login successful', user=user))
                continue

        m = p['failed_login'].match(line)
        if m:
            dt = parse_iso8601_ts(m.group('datetime'))
            user = m.group('user') if 'user' in m.groupdict() and m.group('user') else None
            logs.append(create_entry('telnet', dt, m.group('ip'), 'Login failed', user=user))
            continue

        if 'pam_failure' in p:
            m = p['pam_failure'].match(line)
            if m and pid:
                pid_to_ip[pid] = m.group('ip')

    return logs

def process_telnet(file_states: Dict[str, Dict], pid_to_ip: Dict[str, str]) -> List[Dict]:
    source = os.path.join(WORKING_DIR, PATTERNS['telnet']['source'])
    lines = list(read_new_lines(source, file_states))
    return process_telnet_lines(lines, pid_to_ip, patterns_key='telnet')

def process_telnet_commands(file_states: Dict[str, Dict]) -> List[Dict]:
    logs = []
    source = os.path.join(WORKING_DIR, PATTERNS['telnet_commands']['source'])
    for line in read_new_lines(source, file_states):
        match = PATTERNS['telnet_commands']['pattern'].match(line.strip())
        if match:
            dt = datetime.strptime(match.group('date'), "%Y-%m-%d %H:%M:%S")
            raw_command = match.group('command').strip()
            cleaned_command = re.sub(r'^\d+\s+', '', raw_command)
            user = match.group('user')
            logs.append(create_entry('telnet', dt, match.group('ip'), cleaned_command, user=user))
    return logs

# CVE-2026-24061 Module parsing & processing
def process_telnet_cve_2026_24061(file_states: Dict[str, Dict], pid_to_ip: Dict[str, str]) -> List[Dict]:
    source = os.path.join(WORKING_DIR, PATTERNS['telnet_cve_2026_24061']['source'])
    lines = list(read_new_lines(source, file_states))
    return process_telnet_lines(lines, pid_to_ip, patterns_key='telnet_cve_2026_24061', cve='CVE-2026-24061')

def process_telnet_cve_2026_24061_commands(file_states: Dict[str, Dict]) -> List[Dict]:
    logs = []
    source = os.path.join(WORKING_DIR, PATTERNS['telnet_cve_2026_24061_commands']['source'])
    for line in read_new_lines(source, file_states):
        match = PATTERNS['telnet_cve_2026_24061_commands']['pattern'].match(line.strip())
        if match:
            dt = datetime.strptime(match.group('date'), "%Y-%m-%d %H:%M:%S")
            raw_command = match.group('command').strip()
            cleaned_command = re.sub(r'^\d+\s+', '', raw_command)
            user = match.group('user')
            logs.append(create_entry('telnet', dt, match.group('ip'), cleaned_command, user=user))
    return logs

def upsert_logs(logs: List[Dict]) -> (bool, int):
    if not logs:
        return True, 0

    try:
        client = MongoClient(MONGO_URI)
        col = client['melissae']['logs']
        seen_ids = set()
        bulk_ops = []

        for log in logs:
            uid = compute_uid(log)
            if uid in seen_ids:
                continue
            seen_ids.add(uid)
            log['_id'] = uid
            bulk_ops.append(UpdateOne({'_id': uid}, {'$setOnInsert': log}, upsert=True))

        if not bulk_ops:
            return True, 0

        result = col.bulk_write(bulk_ops, ordered=False)
        ensure_indexes(col)
        return True, result.upserted_count
    except PyMongoError as e:
        print(f"[logParser] Mongo write error: {e}")
        return False, 0

# Main
if __name__ == "__main__":
    file_states, telnet_pid_to_ip = load_ingestion_state()
    all_logs: List[Dict] = []

    all_logs.extend(process_ssh_auth(file_states))
    all_logs.extend(process_ssh_commands(file_states))
    all_logs.extend(process_ftp(file_states))
    all_logs.extend(process_http(file_states))
    all_logs.extend(process_modbus(file_states))
    all_logs.extend(process_mqtt(file_states))
    all_logs.extend(process_telnet(file_states, telnet_pid_to_ip))
    all_logs.extend(process_telnet_commands(file_states))
    all_logs.extend(process_telnet_cve_2026_24061(file_states, telnet_pid_to_ip))
    all_logs.extend(process_telnet_cve_2026_24061_commands(file_states))

    success, inserted = upsert_logs(all_logs)
    if success:
        save_ingestion_state(file_states, telnet_pid_to_ip)
