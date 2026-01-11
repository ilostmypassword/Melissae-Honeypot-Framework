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
    }
}


def compute_uid(log: Dict) -> str:
    """Deterministic identifier to avoid duplicates across runs."""
    key_fields = ['protocol', 'timestamp', 'date', 'hour', 'ip', 'action', 'path', 'user', 'user-agent']
    payload = {k: log.get(k) for k in key_fields if k in log}
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return hashlib.sha1(serialized.encode('utf-8')).hexdigest()


def load_ingestion_state() -> Dict[str, Dict]:
    try:
        client = MongoClient(MONGO_URI)
        col = client['melissae']['ingestion_state']
        doc = col.find_one({'_id': 'logParser'}) or {}
        return doc.get('files', {})
    except PyMongoError as e:
        print(f"[logParser] Mongo state read error: {e}")
        return {}


def save_ingestion_state(file_states: Dict[str, Dict]) -> None:
    try:
        client = MongoClient(MONGO_URI)
        col = client['melissae']['ingestion_state']
        col.update_one(
            {'_id': 'logParser'},
            {'$set': {'files': file_states, 'updated_at': datetime.utcnow()}},
            upsert=True,
        )
    except PyMongoError as e:
        print(f"[logParser] Mongo state write error: {e}")


def read_new_lines(source: str, file_states: Dict[str, Dict]) -> List[str]:
    """Read only the new portion of a file, keeping offsets in memory."""
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
            offset = 0  # reset on rotation/truncate

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

# Create log entries (Should be modified in case of adding new modules)
def create_entry(protocol: str, dt: datetime, ip: str, action: str, path: str = None, user_agent: str = None, user: Optional[str] = None) -> Dict:
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
    return entry

# SSH Module parsing & processing
def parse_ssh_auth_line(line: str) -> Optional[Dict]:
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

# Persist logs incrementally using deterministic IDs
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
    file_states: Dict[str, Dict] = load_ingestion_state()
    all_logs: List[Dict] = []

    all_logs.extend(process_ssh_auth(file_states))
    all_logs.extend(process_ssh_commands(file_states))
    all_logs.extend(process_ftp(file_states))
    all_logs.extend(process_http(file_states))
    all_logs.extend(process_modbus(file_states))
    all_logs.extend(process_mqtt(file_states))

    success, inserted = upsert_logs(all_logs)
    if success:
        save_ingestion_state(file_states)
