#!/usr/bin/env python3

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

PATTERNS = {
    'ssh_auth': {
        'source': 'ssh/sshd.log',
        'patterns': {
            'date': re.compile(r'(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+\d{2}:\d{2})'),
            'ip': re.compile(r'from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'),
            'action': re.compile(r'(?P<action>Failed password|Accepted password|Accepted publickey|Accepted keyboard-interactive|Invalid user|Connection closed)'),
            'user': re.compile(r'(?:for|user)\s+(?P<user>\S+)')
        }
    },
    'ssh_commands': {
        'source': 'ssh/commands.log',
        'pattern': re.compile(r'(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| (?P<ip>\d+\.\d+\.\d+\.\d+) \| (?P<command>.+)')
    },
    'ftp': {
        'source': 'ftp/vsftpd.log',
        'patterns': {
            'connect': re.compile(r'(\w{3} \w{3} \s?\d{1,2} \d{2}:\d{2}:\d{2} \d{4}) \[pid \d+\] CONNECT: Client "(?P<ip>\d+\.\d+\.\d+\.\d+)"'),
            'login': re.compile(r'(\w{3} \w{3} \s?\d{1,2} \d{2}:\d{2}:\d{2} \d{4}) \[pid \d+\] \[(?P<user>[^\]]+)\] (?P<status>OK|FAIL) LOGIN: Client "(?P<ip>\d+\.\d+\.\d+\.\d+)"'),
            'transfer': re.compile(r'(\w{3} \w{3} \s?\d{1,2} \d{2}:\d{2}:\d{2} \d{4}) \[pid \d+\] \[(?P<user>[^\]]+)\] OK (?P<type>UPLOAD|DOWNLOAD): Client "(?P<ip>\d+\.\d+\.\d+\.\d+)", "(?P<file>.+?)", (?P<size>\d+) bytes')
        }
    },
    'http': {
        'source': 'web/access.log',
        'pattern': re.compile(r'^(\S+) - - \[(.*?)\] "(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|PROPFIND|TRACE|CONNECT|SEARCH) (\S+) HTTP/\d\.\d" (\d+) \d+ ".*?" "(.*?)"$')
    },
    'modbus': {
        'source': 'modbus/modbus.log',
        'pattern': re.compile(r'(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| (?P<ip>\d+\.\d+\.\d+\.\d+) \| (?P<action>.+?)(?:\s\|\s(?P<details>\{.*\}))?$')
    },
    'mqtt': {
        'source': 'mqtt/mosquitto.log',
        'patterns': {
            'connect': re.compile(r'(?P<date>\d+): New client connected from (?P<ip>\d+\.\d+\.\d+\.\d+):\d+'),
            'disconnect': re.compile(r'(?P<date>\d+): Client (?P<user>\S+) disconnected\.'),
            'subscribe': re.compile(r'(?P<date>\d+): Received SUBSCRIBE from (?P<user>\S+)'),
            'subscribe_topic': re.compile(r'^\s+(?P<path>\S+)'),
            'publish': re.compile(r"(?P<date>\d+): Received PUBLISH from (?P<user>\S+).*?'(?P<path>[^']+)'.*?(?P<size>\d+)\s+bytes$")
        }
    },
    'telnet': {
        'source': 'telnet/auth.log',
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
        'source': 'telnet/commands.log',
        'pattern': re.compile(r'(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| (?P<ip>\d+\.\d+\.\d+\.\d+) \| (?P<user>\S+) \| (?P<command>.+)')
    },
    'telnet_cve_2026_24061': {
        'source': 'cve/CVE-2026-24061/auth.log',
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
        'source': 'cve/CVE-2026-24061/commands.log',
        'pattern': re.compile(r'(?P<date>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| (?P<ip>\d+\.\d+\.\d+\.\d+) \| (?P<user>\S+) \| (?P<command>.+)')
    }
}

TELNET_PID_RE = re.compile(r'login\[(?P<pid>\d+)\]:')
TELNET_RHOST_RE = re.compile(r'rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)')

# Compute a unique hash for deduplication
def compute_uid(log: Dict) -> str:
    key_fields = ['protocol', 'timestamp', 'date', 'hour', 'ip', 'action', 'path', 'user', 'user-agent']
    payload = {k: log.get(k) for k in key_fields if k in log}
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(serialized.encode('utf-8')).hexdigest()

# Create a standardized log entry dict
def create_entry(protocol: str, dt: datetime, ip: str, action: str,
                 path: str = None, user_agent: str = None,
                 user: Optional[str] = None, cve: Optional[str] = None) -> Dict:
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
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
    entry["hash"] = compute_uid(entry)
    return entry

# Parse an ISO 8601 timestamp string
def parse_iso8601_ts(datetime_str: str) -> datetime:
    dt_part = datetime_str.split('.')[0]
    return datetime.strptime(dt_part, "%Y-%m-%dT%H:%M:%S")

# Load file read positions from disk
def load_file_states(state_path: str) -> Dict:
    if os.path.exists(state_path):
        with open(state_path, 'r') as f:
            return json.load(f)
    return {"files": {}, "telnet_pid_to_ip": {}}

# Save file read positions to disk
def save_file_states(state_path: str, state: Dict) -> None:
    tmp = state_path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(state, f)
    os.replace(tmp, state_path)

# Read new lines from a log file since last position
def read_new_lines(source: str, file_states: Dict) -> List[str]:
    if not os.path.exists(source):
        return []
    try:
        stats = os.stat(source)
        size = stats.st_size
        mtime = stats.st_mtime
        inode = stats.st_ino
        state = file_states.get(source, {})
        offset = state.get('offset', 0)
        prev_mtime = state.get('mtime', 0)
        prev_inode = state.get('inode', 0)

        # Reset on rotation: inode changed, file shrunk, or mtime went backward
        if inode != prev_inode or size < offset or mtime < prev_mtime:
            offset = 0

        with open(source, 'r', encoding='utf-8') as f:
            f.seek(offset)
            lines = f.readlines()
            new_offset = f.tell()

        file_states[source] = {
            'offset': new_offset,
            'mtime': mtime,
            'size': size,
            'inode': inode,
        }
        return lines
    except OSError as e:
        print(f"[log_parser] Unable to read {source}: {e}")
        return []

# Parse SSH authentication log lines
def parse_ssh_auth(logs_dir: str, file_states: Dict) -> List[Dict]:
    logs = []
    source = os.path.join(logs_dir, PATTERNS['ssh_auth']['source'])
    for line in read_new_lines(source, file_states):
        p = PATTERNS['ssh_auth']['patterns']
        date_match = p['date'].search(line)
        ip_match = p['ip'].search(line)
        action_match = p['action'].search(line)
        user_match = p['user'].search(line)

        if not ip_match or not action_match:
            continue

        dt = None
        if date_match:
            dt = datetime.strptime(date_match.group('date'), "%Y-%m-%dT%H:%M:%S.%f%z").replace(tzinfo=None)
        else:
            syslog_date = re.match(r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})', line)
            if syslog_date:
                year = datetime.utcnow().year
                dt = datetime.strptime(
                    f"{year} {syslog_date.group('month')} {syslog_date.group('day')} {syslog_date.group('time')}",
                    "%Y %b %d %H:%M:%S"
                )
        if not dt:
            continue

        action_desc = {
            'Accepted password': 'Login successful',
            'Accepted publickey': 'Login successful',
            'Accepted keyboard-interactive': 'Login successful',
            'Failed password': 'Login failed',
            'Invalid user': 'Login failed',
            'Connection closed': 'Connection closed'
        }.get(action_match.group('action'), action_match.group('action'))

        logs.append(create_entry('ssh', dt, ip_match.group('ip'), action_desc,
                                 user=user_match.group('user') if user_match else None))
    return logs

# Parse SSH command log lines
def parse_ssh_commands(logs_dir: str, file_states: Dict) -> List[Dict]:
    logs = []
    source = os.path.join(logs_dir, PATTERNS['ssh_commands']['source'])
    for line in read_new_lines(source, file_states):
        match = PATTERNS['ssh_commands']['pattern'].match(line.strip())
        if match:
            dt = datetime.strptime(match.group('date'), "%Y-%m-%d %H:%M:%S")
            raw_command = match.group('command').strip()
            cleaned_command = re.sub(r'^\d+\s+', '', raw_command)
            logs.append(create_entry('ssh', dt, match.group('ip'), cleaned_command))
    return logs

# Parse FTP honeypot log lines
def parse_ftp(logs_dir: str, file_states: Dict) -> List[Dict]:
    logs = []
    source = os.path.join(logs_dir, PATTERNS['ftp']['source'])
    for line in read_new_lines(source, file_states):
        for pattern_name in ['transfer', 'connect', 'login']:
            pattern = PATTERNS['ftp']['patterns'][pattern_name]
            match = pattern.match(line)
            if match:
                dt = datetime.strptime(match.group(1), '%a %b %d %H:%M:%S %Y')
                if pattern_name == 'transfer':
                    logs.append(create_entry('ftp', dt, match.group('ip'),
                                             f"{match.group('type').capitalize()} of '{match.group('file')}' ({match.group('size')} bytes)",
                                             user=match.group('user')))
                elif pattern_name == 'connect':
                    logs.append(create_entry('ftp', dt, match.group('ip'), 'Connection established'))
                elif pattern_name == 'login':
                    status = 'Login successful' if match.group('status') == 'OK' else 'Login failed'
                    logs.append(create_entry('ftp', dt, match.group('ip'), status, user=match.group('user')))
                break
    return logs

# Parse HTTP honeypot log lines
def parse_http(logs_dir: str, file_states: Dict) -> List[Dict]:
    logs = []
    source = os.path.join(logs_dir, PATTERNS['http']['source'])
    for line in read_new_lines(source, file_states):
        match = PATTERNS['http']['pattern'].match(line.strip())
        if match:
            ip = match.group(1)
            dt = datetime.strptime(match.group(2), "%d/%b/%Y:%H:%M:%S %z")
            logs.append(create_entry('http', dt, ip, match.group(3),
                                     path=match.group(4), user_agent=match.group(6)))
    return logs

# Parse Modbus honeypot log lines
def parse_modbus(logs_dir: str, file_states: Dict) -> List[Dict]:
    logs = []
    source = os.path.join(logs_dir, PATTERNS['modbus']['source'])
    for line in read_new_lines(source, file_states):
        match = PATTERNS['modbus']['pattern'].match(line.strip())
        if not match:
            continue
        dt = datetime.strptime(match.group('date'), "%Y-%m-%d %H:%M:%S")
        action = match.group('action')
        details = match.group('details')
        if details:
            try:
                dj = json.loads(details)
                if 'function' in dj:
                    action = f"{action} - {dj['function']}"
            except json.JSONDecodeError:
                pass
        logs.append(create_entry('modbus', dt, match.group('ip'), action))
    return logs

# Parse MQTT honeypot log lines
def parse_mqtt(logs_dir: str, file_states: Dict, client_ip_map: Dict[str, str]) -> List[Dict]:
    logs = []
    source = os.path.join(logs_dir, PATTERNS['mqtt']['source'])
    lines = read_new_lines(source, file_states)
    if not lines:
        return logs

    p = PATTERNS['mqtt']['patterns']
    i = 0
    while i < len(lines):
        line = lines[i].rstrip('\n')
        next_line = lines[i + 1].rstrip('\n') if i + 1 < len(lines) else None

        m = p['connect'].search(line)
        if m:
            dt = datetime.utcfromtimestamp(int(m.group('date')))
            ip = m.group('ip')
            client_match = re.search(r'as\s+(?P<client>\S+)', line)
            if client_match:
                client_ip_map[client_match.group('client')] = ip
            logs.append(create_entry('mqtt', dt, ip, 'Client connected'))
            i += 1
            continue

        m = p['disconnect'].search(line)
        if m:
            dt = datetime.utcfromtimestamp(int(m.group('date')))
            user = m.group('user')
            ip = client_ip_map.get(user, 'unknown')
            logs.append(create_entry('mqtt', dt, ip, 'Client disconnected', user=user))
            i += 1
            continue

        m = p['subscribe'].search(line)
        if m:
            dt = datetime.utcfromtimestamp(int(m.group('date')))
            user = m.group('user')
            ip = client_ip_map.get(user, 'unknown')
            topic = None
            if next_line:
                mt = p['subscribe_topic'].match(next_line)
                if mt:
                    topic = mt.group('path')
            action = f'Subscribe to "{topic}"' if topic else 'Subscribe'
            logs.append(create_entry('mqtt', dt, ip, action, user=user))
            if next_line and p['subscribe_topic'].match(next_line):
                i += 2
                continue
            i += 1
            continue

        m = p['publish'].search(line)
        if m:
            dt = datetime.utcfromtimestamp(int(m.group('date')))
            user = m.group('user')
            ip = client_ip_map.get(user, 'unknown')
            logs.append(create_entry('mqtt', dt, ip,
                                     f'Publish to "{m.group("path")}" ({m.group("size")} bytes)',
                                     user=user))
        i += 1
    return logs

# Parse raw telnet log lines into events
def _parse_telnet_lines(lines: List[str], pid_to_ip: Dict[str, str],
                        patterns_key: str = 'telnet',
                        cve: Optional[str] = None) -> List[Dict]:
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
                if not ip:
                    continue
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

# Parse Telnet honeypot log lines
def parse_telnet(logs_dir: str, file_states: Dict, pid_to_ip: Dict[str, str]) -> List[Dict]:
    source = os.path.join(logs_dir, PATTERNS['telnet']['source'])
    lines = list(read_new_lines(source, file_states))
    return _parse_telnet_lines(lines, pid_to_ip, 'telnet')

# Parse Telnet honeypot log lines
def parse_telnet_commands(logs_dir: str, file_states: Dict) -> List[Dict]:
    logs = []
    source = os.path.join(logs_dir, PATTERNS['telnet_commands']['source'])
    for line in read_new_lines(source, file_states):
        match = PATTERNS['telnet_commands']['pattern'].match(line.strip())
        if match:
            dt = datetime.strptime(match.group('date'), "%Y-%m-%d %H:%M:%S")
            cleaned = re.sub(r'^\d+\s+', '', match.group('command').strip())
            logs.append(create_entry('telnet', dt, match.group('ip'), cleaned, user=match.group('user')))
    return logs

# Parse Telnet honeypot log lines
def parse_telnet_cve(logs_dir: str, file_states: Dict, pid_to_ip: Dict[str, str]) -> List[Dict]:
    source = os.path.join(logs_dir, PATTERNS['telnet_cve_2026_24061']['source'])
    lines = list(read_new_lines(source, file_states))
    return _parse_telnet_lines(lines, pid_to_ip, 'telnet_cve_2026_24061', cve='CVE-2026-24061')

# Parse Telnet honeypot log lines
def parse_telnet_cve_commands(logs_dir: str, file_states: Dict) -> List[Dict]:
    logs = []
    source = os.path.join(logs_dir, PATTERNS['telnet_cve_2026_24061_commands']['source'])
    for line in read_new_lines(source, file_states):
        match = PATTERNS['telnet_cve_2026_24061_commands']['pattern'].match(line.strip())
        if match:
            dt = datetime.strptime(match.group('date'), "%Y-%m-%d %H:%M:%S")
            cleaned = re.sub(r'^\d+\s+', '', match.group('command').strip())
            logs.append(create_entry('telnet', dt, match.group('ip'), cleaned, user=match.group('user')))
    return logs

MODULE_PARSERS = {
    'ssh':             [parse_ssh_auth, parse_ssh_commands],
    'ftp':             [parse_ftp],
    'http':            [parse_http],
    'modbus':          [parse_modbus],
    'mqtt':            [parse_mqtt],
    'telnet':          [parse_telnet, parse_telnet_commands],
    'cve-2026-24061':  [parse_telnet_cve, parse_telnet_cve_commands],
}

_NEEDS_PID_MAP = {parse_telnet, parse_telnet_cve}
_NEEDS_CLIENT_MAP = {parse_mqtt}

# Parse logs from all enabled modules
def parse_all_modules(logs_dir: str, enabled_modules: Dict[str, str],
                      state: Dict) -> List[Dict]:
    file_states = state.setdefault('files', {})
    pid_to_ip = state.setdefault('telnet_pid_to_ip', {})
    mqtt_client_ip_map = state.setdefault('mqtt_client_ip_map', {})
    all_logs: List[Dict] = []

    for module_name in enabled_modules:
        parsers = MODULE_PARSERS.get(module_name, [])
        for parser_fn in parsers:
            if parser_fn in _NEEDS_PID_MAP:
                all_logs.extend(parser_fn(logs_dir, file_states, pid_to_ip))
            elif parser_fn in _NEEDS_CLIENT_MAP:
                all_logs.extend(parser_fn(logs_dir, file_states, mqtt_client_ip_map))
            else:
                all_logs.extend(parser_fn(logs_dir, file_states))

    return all_logs

