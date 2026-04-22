#!/usr/bin/env python3

import json
import logging
import os
import signal
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

import requests
import yaml

from log_parser import parse_all_modules, load_file_states, save_file_states

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger('melissae-agent')

# Load agent configuration from YAML
def load_config(path: str) -> dict:
    with open(path, 'r') as f:
        return yaml.safe_load(f)

# SQLite-based log buffer with size management
class LogBuffer:
    def __init__(self, db_path: str, max_size_mb: int = 512):
        self.db_path = db_path
        self.max_size_mb = max_size_mb
        os.makedirs(os.path.dirname(db_path) or '.', exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self.conn:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS pending_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    json_payload TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
            ''')

    def insert(self, logs: list):
        if not logs:
            return
        with self.lock:
            with self.conn:
                self.conn.executemany(
                    'INSERT INTO pending_logs (json_payload, created_at) VALUES (?, ?)',
                    [(json.dumps(l), datetime.now(timezone.utc).isoformat()) for l in logs]
                )

    def fetch_batch(self, batch_size: int) -> list:
        with self.lock:
            cursor = self.conn.execute(
                'SELECT id, json_payload FROM pending_logs ORDER BY id LIMIT ?',
                (batch_size,)
            )
            return cursor.fetchall()

    def delete_ids(self, ids: list):
        if not ids:
            return
        with self.lock:
            placeholders = ','.join('?' * len(ids))
            with self.conn:
                self.conn.execute(f'DELETE FROM pending_logs WHERE id IN ({placeholders})', ids)

    def pending_count(self) -> int:
        with self.lock:
            row = self.conn.execute('SELECT COUNT(*) FROM pending_logs').fetchone()
            return row[0] if row else 0

    def oldest_pending(self) -> str:
        with self.lock:
            row = self.conn.execute(
                'SELECT created_at FROM pending_logs ORDER BY id LIMIT 1'
            ).fetchone()
            return row[0] if row else None

    def check_size(self):
        try:
            size_mb = os.path.getsize(self.db_path) / (1024 * 1024)
            if size_mb > self.max_size_mb:
                log.warning(f"Buffer size {size_mb:.1f}MB exceeds limit {self.max_size_mb}MB — pruning oldest entries")
                with self.lock:
                    with self.conn:
                        self.conn.execute(
                            'DELETE FROM pending_logs WHERE id IN (SELECT id FROM pending_logs ORDER BY id LIMIT 1000)'
                        )
        except OSError:
            pass

# mTLS client for pushing logs to the manager
class PushClient:
    def __init__(self, config: dict):
        mgr = config['manager']
        agent = config['agent']
        self.url = mgr['url'].rstrip('/') + '/api/ingest'
        self.agent_id = config['agent_id']
        self.session = requests.Session()
        self.session.cert = (agent['cert'], agent['key'])
        self.session.verify = mgr['ca_cert']
        self.batch_size = config['push']['batch_size']
        self.timeout = 30

    def push_batch(self, batch: list) -> dict:
        payload = {
            'agent_id': self.agent_id,
            'batch': [json.loads(row[1]) for row in batch]
        }
        resp = self.session.post(self.url, json=payload, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

# HTTPS handler for health checks and remote commands
class HealthHandler(BaseHTTPRequestHandler):
    agent_state = {}
    compose_cmd = None
    def do_GET(self):
        if self.path != '/health':
            self.send_error(404)
            return
        state = self.__class__.agent_state
        body = json.dumps(state, default=str).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != '/command':
            self.send_error(404)
            return

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 4096:
            self._json_response(413, {'error': 'Payload too large'})
            return

        try:
            raw = self.rfile.read(content_length)
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            self._json_response(400, {'error': 'Invalid JSON'})
            return

        action = data.get('action', '')
        module = data.get('module', 'all')

        allowed_actions = ('start', 'stop', 'restart', 'status')
        if action not in allowed_actions:
            self._json_response(400, {'error': f'Invalid action. Allowed: {allowed_actions}'})
            return

        if module != 'all' and not all(c.isalnum() or c in '-_' for c in module):
            self._json_response(400, {'error': 'Invalid module name'})
            return

        compose = self.__class__.compose_cmd
        if not compose:
            self._json_response(500, {'error': 'Compose command not configured'})
            return

        try:
            result = self._exec_compose(compose, action, module)
            self._json_response(200, result)
        except Exception as e:
            log.error(f"Command execution error: {e}")
            self._json_response(500, {'error': str(e)})

    def _exec_compose(self, compose: list, action: str, module: str) -> dict:
        if action == 'status':
            cmd = ['docker', 'ps', '-a', '--filter', 'name=melissae_',
                   '--format', '{{.Names}}|{{.Status}}']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            services = []
            for line in proc.stdout.strip().split('\n'):
                if not line:
                    continue
                parts = line.split('|', 1)
                name = parts[0]
                status = parts[1] if len(parts) > 1 else 'unknown'
                if module != 'all' and f'melissae_{module}' != name:
                    continue
                services.append({'service': name, 'state': status})
            return {'action': 'status', 'services': services}


        ls = subprocess.run(
            ['docker', 'ps', '-a', '--filter', 'name=melissae_',
             '--format', '{{.Names}}'],
            capture_output=True, text=True, timeout=10
        )
        known = {n for n in ls.stdout.strip().split('\n')
                 if n and n != 'melissae_agent'}

        if module == 'all':
            targets = list(known)
        else:
            container_name = f'melissae_{module}'
            # Validate against the discovered set — targets is built from known,
            # not from user input, which cuts the taint flow.
            targets = [n for n in known if n == container_name]
            if not targets:
                return {'action': action, 'module': module, 'success': False,
                        'error': 'Unknown module'}

        if not targets:
            return {'action': action, 'module': module, 'success': True,
                    'output': 'No matching containers'}

        if action == 'start':
            cmd = ['docker', 'start'] + targets
        elif action == 'stop':
            cmd = ['docker', 'stop'] + targets
        elif action == 'restart':
            cmd = ['docker', 'restart'] + targets
        else:
            return {'error': 'Unknown action'}

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {
            'action': action,
            'module': module,
            'success': proc.returncode == 0,
            'output': (proc.stdout + proc.stderr).strip()[-500:],
        }

    def _json_response(self, code: int, data: dict):
        body = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass
# Start the mTLS health and command server
def start_health_server(config: dict, agent_state: dict):
    agent_cfg = config['agent']
    mgr_cfg = config['manager']
    port = agent_cfg.get('health_port', 8444)

    HealthHandler.agent_state = agent_state

    try:
        subprocess.run(['docker', 'version'], capture_output=True, check=True, timeout=5)
        HealthHandler.compose_cmd = ['docker']
    except Exception:
        log.warning("Docker CLI not found — /command endpoint disabled")
        HealthHandler.compose_cmd = None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(agent_cfg['cert'], agent_cfg['key'])
    ctx.load_verify_locations(mgr_cfg['ca_cert'])
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    server = HTTPServer(('0.0.0.0', port), HealthHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    log.info(f"Health endpoint listening on :{port} (mTLS)")
    return server

# Get the status of all Docker containers
def get_container_statuses() -> list:
    try:
        out = subprocess.check_output(
            ['docker', 'ps', '--all', '--format', '{{.Names}}|{{.Status}}', '--filter', 'name=melissae_'],
            text=True, timeout=5
        )
        modules = []
        for line in out.strip().split('\n'):
            if not line:
                continue
            name, status = line.split('|', 1)
            running = 'Up' in status
            modules.append({
                'name': name.replace('melissae_', ''),
                'container': name,
                'status': 'running' if running else 'stopped'
            })
        return modules
    except Exception:
        return []

# Entry point — start all daemon threads and the log tailer
def main():
    if len(sys.argv) < 3 or sys.argv[1] != '--config':
        print(f"Usage: {sys.argv[0]} --config <config.yml>")
        sys.exit(1)

    config = load_config(sys.argv[2])
    agent_id = config['agent_id']
    logs_dir = config.get('logs_dir', '/logs')
    push_interval = config['push']['interval_seconds']
    batch_size = config['push']['batch_size']
    retry_max = config['push']['retry_max_seconds']
    buffer_db = config['buffer']['db_path']
    max_buffer = config['buffer']['max_size_mb']
    state_path = config.get('state_path', '/var/lib/melissae/parser_state.json')

    enabled_modules = {}
    for mod_name, mod_cfg in config.get('modules', {}).items():
        if mod_cfg.get('enabled', False):
            enabled_modules[mod_name] = mod_cfg.get('log_path')

    log.info(f"Agent '{agent_id}' starting — {len(enabled_modules)} modules enabled")

    buffer = LogBuffer(buffer_db, max_buffer)
    push_client = PushClient(config)
    os.makedirs(os.path.dirname(state_path) or '.', exist_ok=True)
    parser_state = load_file_states(state_path)

    start_time = datetime.now(timezone.utc)
    last_push_time = None
    last_push_status = None
    retry_delay = push_interval

    agent_state = {
        'agent_id': agent_id,
        'status': 'healthy',
        'uptime_seconds': 0,
        'version': '2.1',
        'modules': [],
        'buffer': {'pending_logs': 0, 'oldest_pending': None},
        'last_push': None,
        'last_push_status': None,
    }

    health_server = start_health_server(config, agent_state)

    running = True

    def handle_signal(signum, frame):
        nonlocal running
        log.info(f"Received signal {signum}, shutting down...")
        running = False

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    while running:
        loop_start = time.time()

        try:
            new_logs = parse_all_modules(logs_dir, enabled_modules, parser_state)
            if new_logs:
                buffer.insert(new_logs)
                save_file_states(state_path, parser_state)
                log.info(f"Parsed {len(new_logs)} new log entries")
        except Exception as e:
            log.error(f"Parse error: {e}")

        try:
            batch = buffer.fetch_batch(batch_size)
            if batch:
                result = push_client.push_batch(batch)
                ids = [row[0] for row in batch]
                buffer.delete_ids(ids)
                last_push_time = datetime.now(timezone.utc).isoformat()
                last_push_status = 'success'
                retry_delay = push_interval
                log.info(f"Pushed {result.get('ingested', len(batch))} logs "
                         f"({result.get('duplicates', 0)} duplicates)")
        except requests.RequestException as e:
            last_push_status = 'failed'
            retry_delay = min(retry_delay * 2, retry_max)
            log.warning(f"Push failed (retry in {retry_delay}s): {e}")
        except Exception as e:
            last_push_status = 'failed'
            log.error(f"Push error: {e}")

        buffer.check_size()
        pending = buffer.pending_count()
        agent_state.update({
            'uptime_seconds': int((datetime.now(timezone.utc) - start_time).total_seconds()),
            'modules': get_container_statuses(),
            'buffer': {
                'pending_logs': pending,
                'oldest_pending': buffer.oldest_pending(),
            },
            'last_push': last_push_time,
            'last_push_status': last_push_status,
            'status': 'healthy' if last_push_status != 'failed' or pending < 1000 else 'degraded',
        })

        elapsed = time.time() - loop_start
        sleep_time = max(0, (retry_delay if last_push_status == 'failed' else push_interval) - elapsed)
        if running and sleep_time > 0:
            time.sleep(min(sleep_time, 1.0))
            remaining = sleep_time - 1.0
            while running and remaining > 0:
                time.sleep(min(remaining, 1.0))
                remaining -= 1.0

    log.info("Agent daemon stopped")
    health_server.shutdown()

if __name__ == '__main__':
    main()
