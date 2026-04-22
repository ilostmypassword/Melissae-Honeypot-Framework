#!/bin/bash

set -uo pipefail

WORKING_DIRECTORY=$(cd "$(dirname "$0")" && pwd)
cd "$WORKING_DIRECTORY" || exit 1
compose_cmd=()
COMPOSE_FILE="docker-compose.yml"
VERSION="2.1"
PKI_DIR="$WORKING_DIRECTORY/pki/ca"
CERTS_DIR="$PKI_DIR/certs"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

info()    { echo -e "${BLUE}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[✓]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[✗]${RESET} $1"; }
debug()   { echo -e "${GRAY}[~]${RESET} $1"; }

# Validate name contains only safe characters
_validate_name() {
    [[ "$1" =~ ^[a-zA-Z0-9_-]+$ ]]
}

# Validate input is a positive integer
_validate_int() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

# Display the ASCII art banner
print_banner() {
    clear
    echo -e "${MAGENTA}"
    cat << 'EOF'
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║  █▀▄▀█ ▄███▄   █    ▄█    ▄▄▄▄▄    ▄▄▄▄▄   ██   ▄███▄                     ║
    ║  █ █ █ █▀   ▀  █    ██   █     ▀▄ █     ▀▄ █ █  █▀   ▀                    ║
    ║  █ ▄ █ ██▄▄    █    ██ ▄  ▀▀▀▀▄ ▄  ▀▀▀▀▄   █▄▄█ ██▄▄                      ║
    ║  █   █ █▄   ▄▀ ███▄ ▐█  ▀▄▄▄▄▀   ▀▄▄▄▄▀    █  █ █▄   ▄▀                   ║
    ║     █  ▀███▀       ▀ ▐                        █ ▀███▀                     ║
    ║    ▀                                         █                            ║
    ║                                             ▀                             ║
    ║                                                                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${RESET}"
    echo -e "       ${CYAN}Melissae Manager${RESET}  ${DIM}v${VERSION}${RESET}"
    echo -e "       ${DIM}Type 'help' for available commands${RESET}"
    echo
}

# Detect and set the docker compose command
ensure_compose_cmd() {
    if [ ${#compose_cmd[@]} -gt 0 ]; then return 0; fi
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        compose_cmd=(docker compose -f "$COMPOSE_FILE")
    elif command -v docker-compose >/dev/null 2>&1; then
        compose_cmd=(docker-compose -f "$COMPOSE_FILE")
    else
        error "Docker Compose not found. Run 'install' first."
        return 1
    fi
}

# Count running manager containers
get_running_count() {
    ensure_compose_cmd 2>/dev/null || { echo "0"; return; }
    local count
    count=$("${compose_cmd[@]}" ps --format '{{.Service}}' 2>/dev/null | grep -c "melissae_" 2>/dev/null || true)
    echo "${count:-0}" | tr -d '[:space:]'
}

# Build the interactive shell prompt
get_prompt() {
    local running_count
    running_count=$(get_running_count 2>/dev/null || echo "?")
    echo -e "${BOLD}${MAGENTA}manager${RESET} ${DIM}[${running_count} active]${RESET} ${CYAN}>${RESET} "
}

# Initialize the ECDSA P-384 Certificate Authority
_init_ca() {
    if [ -f "$PKI_DIR/ca.key" ] && [ -f "$PKI_DIR/ca.crt" ]; then
        info "CA already initialized at $PKI_DIR"
        return 0
    fi

    info "Initializing Certificate Authority..."
    mkdir -p "$PKI_DIR" "$CERTS_DIR"

    openssl ecparam -genkey -name secp384r1 -out "$PKI_DIR/ca.key" 2>/dev/null
    chmod 600 "$PKI_DIR/ca.key"

    openssl req -new -x509 -sha384 \
        -key "$PKI_DIR/ca.key" \
        -out "$PKI_DIR/ca.crt" \
        -days 3650 \
        -subj "/CN=Melissae CA/O=Melissae Honeypot Framework" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        2>/dev/null

    echo "01" > "$PKI_DIR/serial"
    touch "$PKI_DIR/index.txt"

    cat > "$PKI_DIR/openssl.cnf" << SSLEOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $PKI_DIR
certs             = \$dir/certs
new_certs_dir     = \$dir/certs
database          = \$dir/index.txt
serial            = \$dir/serial
certificate       = \$dir/ca.crt
private_key       = \$dir/ca.key
default_days      = 365
default_md        = sha384
policy            = policy_anything
unique_subject    = no

[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional
SSLEOF

    success "CA initialized: $PKI_DIR/ca.crt"
}

# Generate a signed certificate with SAN (domain or IP)
_gen_cert() {
    local name="$1"
    local cert_type="${2:-dual}"  # server, client, dual
    shift 2
    local sans=("$@")

    local cert_dir="$CERTS_DIR/$name"
    mkdir -p "$cert_dir"

    openssl ecparam -genkey -name secp384r1 -out "$cert_dir/$name.key" 2>/dev/null
    chmod 600 "$cert_dir/$name.key"

    local san_str=""
    local idx=1
    for san in "${sans[@]}"; do
        if [[ "$san" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            san_str="${san_str}IP.${idx} = ${san}\n"
        else
            san_str="${san_str}DNS.${idx} = ${san}\n"
        fi
        idx=$((idx + 1))
    done

    local eku=""
    case "$cert_type" in
        server) eku="serverAuth" ;;
        client) eku="clientAuth" ;;
        dual)   eku="serverAuth, clientAuth" ;;
    esac

    local ext_file="$cert_dir/ext.cnf"
    cat > "$ext_file" << EXTEOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $name

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = $eku
subjectAltName = @alt_names

[alt_names]
$(echo -e "$san_str")
EXTEOF

    openssl req -new -sha384 \
        -key "$cert_dir/$name.key" \
        -out "$cert_dir/$name.csr" \
        -config "$ext_file" \
        2>/dev/null

    openssl x509 -req -sha384 \
        -in "$cert_dir/$name.csr" \
        -CA "$PKI_DIR/ca.crt" \
        -CAkey "$PKI_DIR/ca.key" \
        -CAcreateserial \
        -out "$cert_dir/$name.crt" \
        -days 365 \
        -extensions v3_req \
        -extfile "$ext_file" \
        2>/dev/null

    cp "$PKI_DIR/ca.crt" "$cert_dir/ca.crt"

    rm -f "$cert_dir/$name.csr" "$ext_file"

    success "Certificate generated: $cert_dir/$name.crt (type: $cert_type, validity: 365 days)"
}

# Revoke and remove an agent certificate
_revoke_cert() {
    local name="$1"
    local cert_file="$CERTS_DIR/$name/$name.crt"

    if [ ! -f "$cert_file" ]; then
        error "Certificate not found: $cert_file"
        return 1
    fi

    rm -rf "$CERTS_DIR/$name"

    success "Certificate revoked: $name"
}

# Display available commands and usage
cmd_help() {
    echo
    echo -e "${BOLD}${WHITE}CORE COMMANDS${RESET}"
    echo -e "  ${CYAN}status${RESET}                       Show manager services status"
    echo -e "  ${CYAN}start${RESET}                        Start manager services"
    echo -e "  ${CYAN}stop${RESET}                         Stop manager services"
    echo -e "  ${CYAN}restart${RESET}                      Restart manager services"
    echo -e "  ${CYAN}build${RESET}                        Rebuild manager containers"
    echo
    echo -e "${BOLD}${WHITE}AGENT MANAGEMENT${RESET}"
    echo -e "  ${CYAN}enroll${RESET} <agent-name> <host>   Generate enrollment token for new agent"
    echo -e "  ${CYAN}agents${RESET}                       List registered agents with health"
    echo -e "  ${CYAN}agent-exec${RESET} <name> <action> [mod]  Remote: start/stop/restart/status on agent"
    echo -e "  ${CYAN}revoke${RESET} <agent-name>          Revoke agent certificate and unregister"
    echo -e "  ${CYAN}agent-logs${RESET} <agent> [count]   Show logs from a specific agent"
    echo -e "  ${CYAN}modules${RESET}                      List available honeypot module types"
    echo
    echo -e "${BOLD}${WHITE}CERTIFICATES${RESET}"
    echo -e "  ${CYAN}certs list${RESET}                   List all issued certificates"
    echo -e "  ${CYAN}certs renew${RESET} <agent-name>     Renew agent certificate"
    echo
    echo -e "${BOLD}${WHITE}MONITORING${RESET}"
    echo -e "  ${CYAN}stats${RESET}                        Show attack statistics"
    echo -e "  ${CYAN}threats${RESET}                      Show top threat IPs"
    echo -e "  ${CYAN}events${RESET} [count]               Show recent events (default: 20)"
    echo
    echo -e "${BOLD}${WHITE}MANAGEMENT${RESET}"
    echo -e "  ${CYAN}install${RESET}                      Install manager and initialize PKI"
    echo -e "  ${CYAN}destroy${RESET}                      Stop and remove all containers"
    echo
    echo -e "${BOLD}${WHITE}SHELL${RESET}"
    echo -e "  ${CYAN}clear${RESET}                        Clear screen"
    echo -e "  ${CYAN}banner${RESET}                       Show banner"
    echo -e "  ${CYAN}version${RESET}                      Show version"
    echo -e "  ${CYAN}exit${RESET}                         Exit console"
    echo
}

# Show manager services and PKI status
cmd_status() {
    if ! ensure_compose_cmd; then return 1; fi
    echo
    echo -e "${BOLD}${WHITE}   MANAGER SERVICES${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"

    local entries
    entries=$("${compose_cmd[@]}" ps --format '{{.Service}}|{{.State}}|{{.Health}}' 2>/dev/null)
    if [ -z "$entries" ]; then
        warn "   No services running."
        return 0
    fi

    while IFS='|' read -r svc state health; do
        [ -z "$svc" ] && continue
        local icon color
        if echo "$state" | grep -Eqi "up|running"; then
            icon="●"; color="${GREEN}"
        else
            icon="○"; color="${RED}"
        fi
        printf "   ${color}%s${RESET}  %-24s  ${DIM}%s${RESET}\n" "$icon" "$svc" "$health"
    done <<< "$entries"
    echo
}

# Start the manager docker stack
cmd_start() {
    if ! ensure_compose_cmd; then return 1; fi
    info "Starting manager services..."
    if "${compose_cmd[@]}" up --detach --quiet-pull 2>&1; then
        success "Manager services started"
    else
        error "Failed to start services"
        return 1
    fi
}

# Stop the manager docker stack
cmd_stop() {
    if ! ensure_compose_cmd; then return 1; fi
    info "Stopping manager services..."
    "${compose_cmd[@]}" stop 2>/dev/null
    success "Manager services stopped"
}

# Restart the manager docker stack
cmd_restart() {
    cmd_stop && cmd_start
}

# Rebuild manager containers from images
cmd_build() {
    if ! ensure_compose_cmd; then return 1; fi
    info "Rebuilding manager containers..."
    "${compose_cmd[@]}" build --no-cache
    success "Containers rebuilt"
}

# Enroll a new agent with certificate and token
cmd_enroll() {
    if [ $# -lt 2 ]; then
        warn "Usage: enroll <agent-name> <agent-host>"
        return 1
    fi
    local agent_name="$1"
    local agent_host="$2"

    if ! _validate_name "$agent_name"; then
        error "Invalid agent name. Use only alphanumeric, hyphens, and underscores."
        return 1
    fi

    agent_host="${agent_host#https://}"
    agent_host="${agent_host#http://}"

    if [ ! -f "$PKI_DIR/ca.key" ]; then
        error "CA not initialized. Run 'install' first."
        return 1
    fi

    info "Enrolling agent '$agent_name' ($agent_host)..."

    _gen_cert "$agent_name" "dual" "$agent_host" "localhost" "127.0.0.1"

    local token
    token=$(openssl rand -hex 32)
    local expires
    expires=$(date -d "+10 minutes" -Iseconds 2>/dev/null || date -v+10M -Iseconds 2>/dev/null)

    python3 -c "
from pymongo import MongoClient
from datetime import datetime, timezone, timedelta
client = MongoClient('mongodb://127.0.0.1:27017')
db = client['melissae']
db['enrollment_tokens'].insert_one({
    'token': '$token',
    'agent_id': '$agent_name',
    'cert_dir': '/certs/$agent_name',
    'expires_at': '$expires',
    'created_at': datetime.now(timezone.utc).isoformat()
})
db['agents'].update_one(
    {'agent_id': '$agent_name'},
    {'\$set': {
        'agent_id': '$agent_name',
        'host': '$agent_host',
        'health_port': 8444,
        'status': 'pending',
        'registered_at': datetime.now(timezone.utc).isoformat()
    }},
    upsert=True
)
print('OK')
" 2>/dev/null

    if [ $? -ne 0 ]; then
        error "Failed to store enrollment token. Is MongoDB running?"
        return 1
    fi

    echo
    success "Enrollment token generated (expires in 10 minutes)"
    echo
    echo -e "${BOLD}${WHITE}   Run this on the agent:${RESET}"
    echo
    echo -e "   ${CYAN}./melissae-agent.sh install https://<manager-ip>:8443 $token${RESET}"
    echo
    echo -e "${DIM}   Replace <manager-ip> with this server's IP or hostname.${RESET}"
    echo -e "${DIM}   Agent name: $agent_name${RESET}"
    echo
}

# List registered agents with health status
cmd_agents() {
    echo
    echo -e "${BOLD}${WHITE}   REGISTERED AGENTS${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"

    python3 -c "
from pymongo import MongoClient
client = MongoClient('mongodb://127.0.0.1:27017', serverSelectionTimeoutMS=2000)
db = client['melissae']
agents = db['agents'].find()
found = False
for a in agents:
    found = True
    aid = a.get('agent_id', '?')
    host = a.get('host', '?')
    status = a.get('status', 'unknown')
    last_push = a.get('last_push', 'never')
    last_check = a.get('last_check', 'never')
    print(f'{aid}|{host}|{status}|{last_push}|{last_check}')
if not found:
    print('EMPTY')
" 2>/dev/null | while IFS='|' read -r aid host status last_push last_check; do
        if [ "$aid" = "EMPTY" ]; then
            info "   No agents registered. Use 'enroll' to add one."
            return
        fi
        local color="$GRAY"
        case "$status" in
            healthy)     color="$GREEN" ;;
            degraded)    color="$YELLOW" ;;
            unreachable) color="$RED" ;;
            enrolled|pending) color="$CYAN" ;;
        esac
        printf "   ${color}●${RESET}  %-16s  %-16s  %-12s  ${DIM}push: %s  check: %s${RESET}\n" \
            "$aid" "$host" "$status" "$last_push" "$last_check"
    done
    echo
}

# Revoke an agent certificate and unregister it
cmd_revoke() {
    if [ $# -eq 0 ]; then
        warn "Usage: revoke <agent-name>"
        return 1
    fi
    local agent_name="$1"

    warn "This will revoke the certificate and unregister agent '$agent_name'."
    read -p "Are you sure? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        info "Cancelled"
        return 0
    fi

    if ! _validate_name "$agent_name"; then
        error "Invalid agent name."
        return 1
    fi

    _revoke_cert "$agent_name"

    python3 -c "
from pymongo import MongoClient
client = MongoClient('mongodb://127.0.0.1:27017')
db = client['melissae']
db['agents'].delete_one({'agent_id': '$agent_name'})
print('OK')
" 2>/dev/null

    success "Agent '$agent_name' revoked and unregistered"
}

# List available honeypot module types
cmd_modules() {
    echo
    echo -e "${BOLD}${WHITE}   AVAILABLE HONEYPOT MODULES${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"
    printf "   ${DIM}%-18s %-8s %-12s %s${RESET}\n" "MODULE" "PORT" "CATEGORY" "DESCRIPTION"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"
    printf "   %-18s ${CYAN}%-8s${RESET} %-12s ${DIM}%s${RESET}\n" "ssh"              ":22"   "network"    "SSH Honeypot — OpenSSH-based login trapping"
    printf "   %-18s ${CYAN}%-8s${RESET} %-12s ${DIM}%s${RESET}\n" "ftp"              ":21"   "network"    "FTP Honeypot — vsftpd file transfer trapping"
    printf "   %-18s ${CYAN}%-8s${RESET} %-12s ${DIM}%s${RESET}\n" "http"             ":80"   "web"        "HTTP Honeypot — Nginx reverse proxy + Apache"
    printf "   %-18s ${CYAN}%-8s${RESET} %-12s ${DIM}%s${RESET}\n" "modbus"           ":502"  "ics"        "Modbus/TCP — Industrial control system honeypot"
    printf "   %-18s ${CYAN}%-8s${RESET} %-12s ${DIM}%s${RESET}\n" "mqtt"             ":1883" "iot"        "MQTT Broker — IoT message queue honeypot"
    printf "   %-18s ${CYAN}%-8s${RESET} %-12s ${DIM}%s${RESET}\n" "telnet"           ":23"   "network"    "Telnet Honeypot — login session trapping"
    printf "   %-18s ${RED}%-8s${RESET} %-12s ${DIM}%s${RESET}\n" "cve-2026-24061"   ":23"   "cve"        "CVE-2026-24061 — Telnet auth bypass (port 23 conflict)"
    echo
    echo -e "${DIM}   Agents manage modules via 'list', 'enable', 'disable' commands.${RESET}"
    echo -e "${DIM}   Use 'agent-exec <agent> start/stop <module>' for remote control.${RESET}"
    echo
}

# Send a remote command to an agent via mTLS
cmd_agent_exec() {
    if [ $# -lt 2 ]; then
        warn "Usage: agent-exec <agent-name> <action> [module]"
        echo -e "${DIM}  Actions: start, stop, restart, status${RESET}"
        echo -e "${DIM}  Module:  ssh, ftp, proxy, modbus, mqtt, telnet, all (default: all)${RESET}"
        return 1
    fi
    local agent_name="$1"
    local action="$2"
    local module="${3:-all}"

    if ! _validate_name "$agent_name"; then
        error "Invalid agent name."
        return 1
    fi

    case "$action" in
        start|stop|restart|status) ;;
        *) error "Invalid action '$action'. Allowed: start, stop, restart, status"; return 1 ;;
    esac

    local agent_info
    agent_info=$(python3 -c "
from pymongo import MongoClient
client = MongoClient('mongodb://127.0.0.1:27017', serverSelectionTimeoutMS=2000)
a = client['melissae']['agents'].find_one({'agent_id': '$agent_name'})
if a:
    print(f\"{a.get('host','')},{a.get('health_port',8444)}\")
else:
    print('NOT_FOUND')
" 2>/dev/null)

    if [ -z "$agent_info" ] || [ "$agent_info" = "NOT_FOUND" ]; then
        error "Agent '$agent_name' not found"
        return 1
    fi

    local agent_host agent_port
    agent_host=$(echo "$agent_info" | cut -d, -f1)
    agent_port=$(echo "$agent_info" | cut -d, -f2)

    local cert_file="$CERTS_DIR/manager/manager.crt"
    local key_file="$CERTS_DIR/manager/manager.key"
    local ca_file="$PKI_DIR/ca.crt"

    if [ ! -f "$cert_file" ] || [ ! -f "$key_file" ] || [ ! -f "$ca_file" ]; then
        error "Manager certificates not found. Run 'install' first."
        return 1
    fi

    info "Sending '$action' to agent '$agent_name' (module: $module)..."

    local response http_code body
    response=$(curl -s --max-time 30 \
        --cert "$cert_file" \
        --key "$key_file" \
        --cacert "$ca_file" \
        -X POST "https://${agent_host}:${agent_port}/command" \
        -H "Content-Type: application/json" \
        -d "{\"action\":\"$action\",\"module\":\"$module\"}" \
        -w "\n%{http_code}" 2>/dev/null)

    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" = "000" ]; then
        error "Agent '$agent_name' unreachable (${agent_host}:${agent_port})"
        return 1
    fi

    if [ "$http_code" != "200" ]; then
        error "Agent returned HTTP $http_code"
        echo -e "${DIM}$body${RESET}"
        return 1
    fi

    if [ "$action" = "status" ]; then
        echo
        echo -e "${BOLD}${WHITE}   AGENT '$agent_name' SERVICES${RESET}"
        echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"
        echo "$body" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for svc in data.get('services', []):
    name = svc.get('service', '?')
    state = svc.get('state', '?')
    icon = '●' if 'Up' in state else '○'
    color = '\033[0;32m' if 'Up' in state else '\033[0;31m'
    print(f'   {color}{icon}\033[0m  {name:<24}  \033[0;90m{state}\033[0m')
" 2>/dev/null
        echo
    else
        local ok
        ok=$(echo "$body" | python3 -c "import json,sys; print(json.load(sys.stdin).get('success','?'))" 2>/dev/null)
        if [ "$ok" = "True" ]; then
            success "Action '$action' completed on '$agent_name' (module: $module)"
        else
            warn "Action '$action' on '$agent_name' may have failed"
            echo -e "${DIM}$body${RESET}"
        fi
    fi
}

# Display recent logs from a specific agent
cmd_agent_logs() {
    if [ $# -eq 0 ]; then
        warn "Usage: agent-logs <agent-name> [count]"
        return 1
    fi
    local agent_name="$1"
    local count="${2:-20}"

    if ! _validate_name "$agent_name"; then
        error "Invalid agent name."
        return 1
    fi
    if ! _validate_int "$count"; then
        error "Count must be a number."
        return 1
    fi

    echo
    echo -e "${BOLD}${WHITE}   LOGS FROM AGENT: $agent_name${RESET} ${DIM}(last $count)${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"

    python3 -c "
from pymongo import MongoClient
client = MongoClient('mongodb://127.0.0.1:27017', serverSelectionTimeoutMS=2000)
db = client['melissae']
events = db['logs'].find({'agent_id': '$agent_name'}).sort('timestamp', -1).limit($count)
for e in events:
    ts = e.get('timestamp', '')
    proto = (e.get('protocol', '?'))[:6]
    ip = e.get('ip', 'unknown')
    action = (e.get('action', ''))[:30]
    print(f'{ts}|{proto}|{ip}|{action}')
" 2>/dev/null | while IFS='|' read -r ts proto ip action; do
        local color="$WHITE"
        case "$action" in
            *fail*|*denied*|*invalid*) color="$RED" ;;
            *success*|*accepted*) color="$GREEN" ;;
        esac
        printf "   ${DIM}%s${RESET}  %-8s  %-16s  ${color}%s${RESET}\n" "$ts" "$proto" "$ip" "$action"
    done
    echo
}

# Manage certificates (list or renew)
cmd_certs() {
    local subcmd="${1:-}"
    case "$subcmd" in
        list)
            echo
            echo -e "${BOLD}${WHITE}   ISSUED CERTIFICATES${RESET}"
            echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"
            if [ ! -d "$CERTS_DIR" ]; then
                warn "   No certificates found. Run 'install' first."
                return
            fi
            for dir in "$CERTS_DIR"/*/; do
                local name=$(basename "$dir")
                local cert="$dir/$name.crt"
                if [ -f "$cert" ]; then
                    local expiry
                    expiry=$(openssl x509 -in "$cert" -enddate -noout 2>/dev/null | cut -d= -f2)
                    local days_left
                    days_left=$(( ($(date -d "$expiry" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))
                    local color="$GREEN"
                    if [ "$days_left" -lt 30 ]; then color="$RED"
                    elif [ "$days_left" -lt 90 ]; then color="$YELLOW"
                    fi
                    printf "   %-20s  ${color}expires: %s (%d days)${RESET}\n" "$name" "$expiry" "$days_left"
                fi
            done
            echo
            ;;
        renew)
            local agent_name="${2:-}"
            if [ -z "$agent_name" ]; then
                warn "Usage: certs renew <agent-name>"
                return 1
            fi
            if ! _validate_name "$agent_name"; then
                error "Invalid agent name."
                return 1
            fi
            local host
            host=$(python3 -c "
from pymongo import MongoClient
client = MongoClient('mongodb://127.0.0.1:27017')
a = client['melissae']['agents'].find_one({'agent_id': '$agent_name'})
print(a.get('host', '') if a else '')
" 2>/dev/null)
            if [ -z "$host" ]; then
                error "Agent '$agent_name' not found"
                return 1
            fi
            info "Revoking old certificate..."
            _revoke_cert "$agent_name" 2>/dev/null
            info "Generating new certificate..."
            _gen_cert "$agent_name" "dual" "$host" "localhost" "127.0.0.1"
            success "Certificate renewed for '$agent_name'. Re-run enrollment on the agent."
            ;;
        *)
            warn "Usage: certs <list|renew>"
            ;;
    esac
}

# Display attack statistics from MongoDB
cmd_stats() {
    echo
    echo -e "${BOLD}${WHITE}   ATTACK STATISTICS${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"

    local mongo_stats
    mongo_stats=$(python3 -c "
from pymongo import MongoClient
from datetime import datetime
import sys
try:
    client = MongoClient('mongodb://127.0.0.1:27017', serverSelectionTimeoutMS=2000)
    db = client['melissae']
    total = db.logs.count_documents({})
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    today_count = db.logs.count_documents({'timestamp': {'\$gte': today}})
    pipeline = [{'\$group': {'_id': '\$protocol', 'count': {'\$sum': 1}}}, {'\$sort': {'count': -1}}]
    by_proto = list(db.logs.aggregate(pipeline))
    unique_ips = len(db.logs.distinct('ip'))
    ip_pipeline = [{'\$group': {'_id': '\$ip', 'count': {'\$sum': 1}}}, {'\$sort': {'count': -1}}, {'\$limit': 5}]
    top_ips = list(db.logs.aggregate(ip_pipeline))
    agents = db.agents.count_documents({})
    print(f'TOTAL:{total}')
    print(f'TODAY:{today_count}')
    print(f'UNIQUE_IPS:{unique_ips}')
    print(f'AGENTS:{agents}')
    for p in by_proto:
        print(f'PROTO:{p[\"_id\"]}:{p[\"count\"]}')
    for ip in top_ips:
        print(f'TOP_IP:{ip[\"_id\"]}:{ip[\"count\"]}')
except Exception as e:
    print(f'ERROR:{e}')
    sys.exit(1)
" 2>/dev/null)

    if [ $? -ne 0 ] || echo "$mongo_stats" | grep -q "^ERROR:"; then
        warn "Cannot connect to MongoDB."
        return 1
    fi

    local total today unique_ips agents_count
    total=$(echo "$mongo_stats" | grep "^TOTAL:" | cut -d: -f2)
    today=$(echo "$mongo_stats" | grep "^TODAY:" | cut -d: -f2)
    unique_ips=$(echo "$mongo_stats" | grep "^UNIQUE_IPS:" | cut -d: -f2)
    agents_count=$(echo "$mongo_stats" | grep "^AGENTS:" | cut -d: -f2)

    echo -e "   ${WHITE}Total Events:${RESET}    $total"
    echo -e "   ${WHITE}Today:${RESET}           $today"
    echo -e "   ${WHITE}Unique IPs:${RESET}      $unique_ips"
    echo -e "   ${WHITE}Active Agents:${RESET}   $agents_count"
    echo

    echo -e "${BOLD}${WHITE}   BY PROTOCOL${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"
    echo "$mongo_stats" | grep "^PROTO:" | while IFS=: read -r _ proto count; do
        printf "   %-12s %s\n" "$proto" "$count"
    done
    echo

    echo -e "${BOLD}${WHITE}   TOP ATTACKERS${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"
    echo "$mongo_stats" | grep "^TOP_IP:" | while IFS=: read -r _ ip count; do
        printf "   %-18s %s events\n" "$ip" "$count"
    done
    echo
}

# Display top threat IPs with scores
cmd_threats() {
    echo
    echo -e "${BOLD}${WHITE}   THREAT INTELLIGENCE${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"

    python3 -c "
from pymongo import MongoClient
client = MongoClient('mongodb://127.0.0.1:27017', serverSelectionTimeoutMS=2000)
db = client['melissae']
threats = db.threats.find().sort('protocol-score', -1).limit(15)
for t in threats:
    ip = t.get('ip', 'unknown')
    score = t.get('protocol-score', 0)
    reasons = ', '.join(t.get('reasons', [])[:2])
    agents = ', '.join(t.get('agents', []))
    print(f'{ip}|{score}|{agents}|{reasons}')
" 2>/dev/null | {
        printf "   ${DIM}%-18s %-8s %-12s %s${RESET}\n" "IP" "SCORE" "AGENTS" "REASONS"
        echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"
        while IFS='|' read -r ip score agents reasons; do
            local color="$GREEN"
            if [ "$score" -ge 70 ]; then color="$RED"
            elif [ "$score" -ge 40 ]; then color="$YELLOW"
            fi
            printf "   %-18s ${color}%-8s${RESET} %-12s ${DIM}%s${RESET}\n" "$ip" "$score" "$agents" "$reasons"
        done
    }
    echo
}

# Display recent events from the logs
cmd_events() {
    local count=${1:-20}
    if ! _validate_int "$count"; then
        error "Count must be a number."
        return 1
    fi
    echo
    echo -e "${BOLD}${WHITE}   RECENT EVENTS${RESET} ${DIM}(last $count)${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"

    python3 -c "
from pymongo import MongoClient
from datetime import datetime
client = MongoClient('mongodb://127.0.0.1:27017', serverSelectionTimeoutMS=2000)
db = client['melissae']
events = db.logs.find().sort('timestamp', -1).limit($count)
for e in events:
    ts = e.get('timestamp', '')
    if isinstance(ts, datetime): ts = ts.strftime('%H:%M:%S')
    proto = e.get('protocol', '?')[:6]
    ip = e.get('ip', 'unknown')
    action = e.get('action', '')[:30]
    agent = e.get('agent_id', '-')[:10]
    print(f'{ts}|{proto}|{ip}|{action}|{agent}')
" 2>/dev/null | while IFS='|' read -r ts proto ip action agent; do
        local color="$WHITE"
        case "$action" in
            *fail*|*denied*|*invalid*) color="$RED" ;;
            *success*|*accepted*) color="$GREEN" ;;
        esac
        printf "   ${DIM}%s${RESET}  %-8s  %-16s  ${color}%-30s${RESET}  ${DIM}%s${RESET}\n" "$ts" "$proto" "$ip" "$action" "$agent"
    done
    echo
}

# Stop and remove all manager containers
cmd_destroy() {
    warn "This will stop and remove ALL manager containers."
    read -p "Are you sure? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        info "Cancelled"
        return 0
    fi
    if ! ensure_compose_cmd; then return 1; fi
    "${compose_cmd[@]}" down 2>/dev/null
    success "Manager stack destroyed"
}

# Install the manager stack and initialize PKI
cmd_install() {
    echo
    info "Starting Melissae Manager installation..."
    echo

    info "Installing prerequisites..."
    sudo apt-get update > /dev/null 2>&1
    sudo apt-get install -y ca-certificates curl cron apache2-utils python3-pymongo openssl > /dev/null 2>&1
    success "Prerequisites installed"

    if command -v docker >/dev/null 2>&1 && docker --version >/dev/null 2>&1; then
        info "Docker already installed"
    else
        info "Installing Docker..."
        sudo install -m 0755 -d /etc/apt/keyrings > /dev/null 2>&1
        sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc > /dev/null 2>&1
        sudo chmod a+r /etc/apt/keyrings/docker.asc > /dev/null 2>&1
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null 2>&1
        sudo apt-get update > /dev/null 2>&1
        sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin > /dev/null 2>&1
        sudo systemctl enable --now docker > /dev/null 2>&1
        success "Docker installed"
    fi

    _init_ca

    local manager_ip
    manager_ip=$(hostname -I | awk '{print $1}')
    local manager_hostname
    manager_hostname=$(hostname -f 2>/dev/null || hostname)

    echo
    info "Manager certificate configuration"
    echo -e "  Detected IP:       ${WHITE}$manager_ip${RESET}"
    echo -e "  Detected hostname: ${WHITE}$manager_hostname${RESET}"
    echo
    read -p "Public FQDN (e.g. manager.example.com) [${manager_hostname}]: " manager_fqdn
    manager_fqdn=${manager_fqdn:-$manager_hostname}

    local san_args=("$manager_fqdn")
    if [ "$manager_fqdn" != "$manager_hostname" ]; then
        san_args+=("$manager_hostname")
    fi
    san_args+=("$manager_ip" "localhost" "127.0.0.1")

    info "Generating manager certificate (SANs: ${san_args[*]})..."
    _gen_cert "manager" "dual" "${san_args[@]}"

    echo
    info "Configure dashboard authentication"
    read -p "Username [melissae]: " dash_user
    dash_user=${dash_user:-melissae}
    while true; do
        read -s -p "Password: " dash_pass; echo
        read -s -p "Confirm: " dash_confirm; echo
        if [ -z "$dash_pass" ]; then
            warn "Password cannot be empty"
            continue
        fi
        if [ "$dash_pass" != "$dash_confirm" ]; then
            warn "Passwords don't match"
            continue
        fi
        break
    done
    htpasswd -Bbc "$WORKING_DIRECTORY/dashboard/conf/htpasswd" "$dash_user" "$dash_pass" > /dev/null 2>&1
    success "Dashboard credentials saved"

    info "Configuring cron jobs..."
    local current_cron
    current_cron=$(crontab -l 2>/dev/null || echo "")

    add_cron() {
        local cmd=$1
        local desc=$2
        if ! echo "$current_cron" | grep -Fq "$cmd"; then
            current_cron="$current_cron
$cmd"
            debug "Added: $desc"
        fi
    }

    add_cron "* * * * * /usr/bin/python3 $WORKING_DIRECTORY/scripts/threatIntel.py" "threatIntel"
    add_cron "0 */3 * * * /usr/bin/python3 $WORKING_DIRECTORY/scripts/purgeLogs.py" "purgeLogs"
    add_cron "* * * * * /usr/bin/python3 $WORKING_DIRECTORY/health_poller.py" "healthPoller"
    echo "$current_cron" | crontab -
    success "Cron jobs configured"

    echo
    info "Configuring admin SSH port..."
    local random_port=$((RANDOM % 10000 + 20000))
    sudo sed -i '/^Port /s/^/#/' /etc/ssh/sshd_config > /dev/null 2>&1
    echo "Port $random_port" | sudo tee -a /etc/ssh/sshd_config > /dev/null 2>&1
    success "SSH admin port: $random_port"

    read -p "Restart SSH now? (yes/no): " answer
    if [ "$answer" = "yes" ]; then
        sudo systemctl disable --now ssh.socket > /dev/null 2>&1
        sudo systemctl restart sshd > /dev/null 2>&1
        success "SSH restarted"
    fi

    echo
    success "Manager installation complete!"
    echo
    echo -e "${CYAN}Next steps:${RESET}"
    echo -e "  1. ${WHITE}sudo usermod -aG docker $USER${RESET} then re-login"
    echo -e "  2. ${WHITE}start${RESET} to launch manager services"
    echo -e "  3. ${WHITE}enroll <agent-name> <agent-ip>${RESET} to add agents"
    echo -e "  4. Access dashboard at: ${WHITE}https://$manager_ip/${RESET}"
    echo
}

# Main interactive CLI loop with command dispatch
main_loop() {
    print_banner

    if [ -t 0 ]; then
        bind 'set show-all-if-ambiguous on' 2>/dev/null
        bind 'set completion-ignore-case on' 2>/dev/null
    fi

    while true; do
        local prompt
        prompt=$(get_prompt)

        if ! read -e -p "$prompt" input; then
            echo
            break
        fi

        [ -n "$input" ] && history -s "$input"

        read -ra args <<< "$input"
        local cmd=${args[0]:-}
        local params=("${args[@]:1}")

        case "$cmd" in
            ""|"#"*)        continue ;;
            help|h|\?)      cmd_help ;;
            status|st)      cmd_status ;;
            start)          cmd_start ;;
            stop)           cmd_stop ;;
            restart)        cmd_restart ;;
            build)          cmd_build ;;
            enroll)         cmd_enroll "${params[@]}" ;;
            agents)         cmd_agents ;;
            agent-exec)     cmd_agent_exec "${params[@]}" ;;
            revoke)         cmd_revoke "${params[@]}" ;;
            agent-logs)     cmd_agent_logs "${params[@]}" ;;
            modules)        cmd_modules ;;
            certs)          cmd_certs "${params[@]}" ;;
            stats)          cmd_stats ;;
            threats)        cmd_threats ;;
            events)         cmd_events "${params[@]}" ;;
            install)        cmd_install ;;
            destroy)        cmd_destroy ;;
            clear|cls)      clear ;;
            banner)         print_banner ;;
            version|ver)    echo -e "${DIM}Melissae Manager v${VERSION}${RESET}" ;;
            exit|quit|q)    echo -e "${DIM}Goodbye.${RESET}"; break ;;
            *)              error "Unknown command: $cmd"; echo -e "${DIM}Type 'help' for available commands${RESET}" ;;
        esac
    done
}

main_loop
