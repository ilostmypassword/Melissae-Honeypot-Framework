#!/bin/bash

set -uo pipefail

WORKING_DIRECTORY=$(cd "$(dirname "$0")" && pwd)
cd "$WORKING_DIRECTORY" || exit 1
compose_cmd=()
COMPOSE_FILE="docker-compose.yml"
VERSION="2.1"
CONFIG_FILE="$WORKING_DIRECTORY/daemon/config.yml"
CERTS_DIR="$WORKING_DIRECTORY/certs"
LOGS_DIR="$WORKING_DIRECTORY/logs"
DATA_DIR="$WORKING_DIRECTORY/data"
PID_FILE="$WORKING_DIRECTORY/daemon/agent.pid"
DAEMON_LOG="$WORKING_DIRECTORY/daemon/agent.log"
VENV_PYTHON="$WORKING_DIRECTORY/daemon/.venv/bin/python"

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

# Display the ASCII art banner
print_banner() {
    clear
    echo -e "${CYAN}"
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
    echo -e "       ${CYAN}Melissae Agent${RESET}  ${DIM}v${VERSION}${RESET}"
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

# Count running agent containers
get_running_count() {
    ensure_compose_cmd 2>/dev/null || { echo "0"; return; }
    local count
    count=$("${compose_cmd[@]}" ps --format '{{.Service}}' 2>/dev/null | grep -c "melissae_" 2>/dev/null || true)
    echo "${count:-0}" | tr -d '[:space:]'
}

get_agent_id() {
    if [ -f "$CONFIG_FILE" ]; then
        grep "^agent_id:" "$CONFIG_FILE" 2>/dev/null | awk '{print $2}' | tr -d '"' || echo "?"
    else
        echo "?"
    fi
}

# Build the interactive shell prompt
get_prompt() {
    local running_count agent_id
    running_count=$(get_running_count 2>/dev/null || echo "?")
    agent_id=$(get_agent_id)
    echo -e "${BOLD}${CYAN}agent:${agent_id}${RESET} ${DIM}[${running_count} active]${RESET} ${CYAN}>${RESET} "
}

MODULE_REGISTRY=(
    "ssh|melissae_ssh|22|SSH Honeypot (OpenSSH)"
    "ftp|melissae_ftp|21|FTP Honeypot (vsftpd)"
    "http|melissae_proxy|80|HTTP Honeypot (Nginx + Apache)"
    "modbus|melissae_modbus|502|Modbus/TCP ICS Honeypot"
    "mqtt|melissae_mqtt|1883|MQTT Broker Honeypot"
    "telnet|melissae_telnet|23|Telnet Honeypot"
    "cve-2026-24061|melissae_cve_2026_24061|23|CVE-2026-24061 Telnet Auth Bypass"
)

# Get a field value from a module registry entry
_mod_field() {
    local name="$1" idx="$2"
    for entry in "${MODULE_REGISTRY[@]}"; do
        IFS='|' read -r n s p d <<< "$entry"
        if [ "$n" = "$name" ]; then
            case "$idx" in
                0) echo "$n" ;; 1) echo "$s" ;; 2) echo "$p" ;; 3) echo "$d" ;;
            esac
            return 0
        fi
    done
    return 1
}

# Check if a module is enabled in config
_mod_enabled() {
    local name="$1"
    if [ ! -f "$CONFIG_FILE" ]; then return 1; fi
    awk -v mod="$name" '
        /^  [a-zA-Z]/ { current = $1; gsub(/:/, "", current) }
        current == mod && /enabled:/ { print $2; exit }
    ' "$CONFIG_FILE" | grep -qi "true"
}

# Check if a module container is running
_mod_running() {
    local service="$1"
    ensure_compose_cmd 2>/dev/null || return 1
    "${compose_cmd[@]}" ps --format '{{.Service}}' 2>/dev/null | grep -qx "$service"
}

# Detect port conflicts between modules
_detect_conflicts() {
    local -A port_map
    local conflicts=()
    for entry in "${MODULE_REGISTRY[@]}"; do
        IFS='|' read -r name service port desc <<< "$entry"
        if _mod_enabled "$name"; then
            if [ -n "${port_map[$port]:-}" ]; then
                conflicts+=("Port $port: ${port_map[$port]} ↔ $name")
            else
                port_map[$port]="$name"
            fi
        fi
    done
    if [ ${#conflicts[@]} -gt 0 ]; then
        echo
        error "Port conflicts detected:"
        for c in "${conflicts[@]}"; do
            echo -e "   ${RED}⚠${RESET}  $c"
        done
        echo -e "${DIM}   Disable one of the conflicting modules with: disable <module>${RESET}"
        echo
        return 1
    fi
    return 0
}

# Display available commands and usage
cmd_help() {
    echo
    echo -e "${BOLD}${WHITE}CORE COMMANDS${RESET}"
    echo -e "  ${CYAN}status${RESET}                       Show all containers + daemon status"
    echo -e "  ${CYAN}start${RESET} [module|all]            Start honeypots + agent daemon"
    echo -e "  ${CYAN}stop${RESET} [module|all]             Stop modules"
    echo -e "  ${CYAN}restart${RESET}                      Restart all services"
    echo -e "  ${CYAN}build${RESET}                        Rebuild containers"
    echo
    echo -e "${BOLD}${WHITE}MODULES${RESET}"
    echo -e "  ${CYAN}list${RESET}                         List available modules with status"
    echo -e "  ${CYAN}enable${RESET} <module>               Enable a module in configuration"
    echo -e "  ${CYAN}disable${RESET} <module>              Disable a module in configuration"
    echo
    echo -e "${BOLD}${WHITE}MONITORING${RESET}"
    echo -e "  ${CYAN}buffer${RESET}                       Show SQLite buffer status"
    echo -e "  ${CYAN}test-connection${RESET}              Test mTLS connectivity to manager"
    echo -e "  ${CYAN}logs${RESET} <module> [count]         Show local raw logs for a module"
    echo -e "  ${CYAN}daemon-log${RESET} [count]            Show agent daemon log"
    echo
    echo -e "${BOLD}${WHITE}MANAGEMENT${RESET}"
    echo -e "  ${CYAN}install${RESET} <manager-url> <token> Install agent and enroll with manager"
    echo
    echo -e "${BOLD}${WHITE}SHELL${RESET}"
    echo -e "  ${CYAN}clear${RESET}                        Clear screen"
    echo -e "  ${CYAN}banner${RESET}                       Show banner"
    echo -e "  ${CYAN}version${RESET}                      Show version"
    echo -e "  ${CYAN}exit${RESET}                         Exit console"
    echo
}

# Install and enroll the agent with the manager
cmd_install() {
    if [ $# -lt 2 ]; then
        warn "Usage: install <manager-url> <enrollment-token>"
        echo -e "${DIM}  Example: install https://192.168.1.10:8443 a1b2c3d4e5...${RESET}"
        return 1
    fi
    local manager_url="$1"
    local token="$2"

    echo
    info "Starting Melissae Agent installation..."
    echo

    info "Installing prerequisites..."
    sudo apt-get update > /dev/null 2>&1
    sudo apt-get install -y ca-certificates curl jq openssl python3 > /dev/null 2>&1

    if ! command -v uv >/dev/null 2>&1; then
        info "Installing uv..."
        curl -LsSf https://astral.sh/uv/install.sh | sh > /dev/null 2>&1
        export PATH="$HOME/.local/bin:$PATH"
    fi

    info "Setting up Python environment..."
    uv venv "$WORKING_DIRECTORY/daemon/.venv" --quiet 2>/dev/null
    uv pip install --quiet -r "$WORKING_DIRECTORY/daemon/requirements.txt" -p "$WORKING_DIRECTORY/daemon/.venv/bin/python" 2>/dev/null
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

    info "Enrolling with manager..."
    mkdir -p "$CERTS_DIR"

    local enroll_url="${manager_url}/api/enroll"
    local curl_err
    curl_err=$(mktemp)
    local response
    response=$(curl -sk -X POST "$enroll_url" \
        -H "Content-Type: application/json" \
        -d "{\"token\": \"$token\"}" \
        -w "\n%{http_code}" 2>"$curl_err")

    local http_code body
    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" != "200" ]; then
        error "Enrollment failed (HTTP $http_code)"
        [ -s "$curl_err" ] && echo -e "${DIM}$(cat "$curl_err")${RESET}"
        echo "$body" | head -5
        rm -f "$curl_err"
        return 1
    fi
    rm -f "$curl_err"

    local agent_id
    agent_id=$(echo "$body" | jq -r '.agent_id' 2>/dev/null)
    if [ -z "$agent_id" ] || [ "$agent_id" = "null" ]; then
        error "Invalid enrollment response"
        return 1
    fi

    echo "$body" | jq -r '.ca_crt' 2>/dev/null | base64 -d > "$CERTS_DIR/ca.crt"
    echo "$body" | jq -r '.agent_crt' 2>/dev/null | base64 -d > "$CERTS_DIR/agent.crt"
    echo "$body" | jq -r '.agent_key' 2>/dev/null | base64 -d > "$CERTS_DIR/agent.key"
    chmod 600 "$CERTS_DIR/agent.key"

    if ! openssl x509 -in "$CERTS_DIR/agent.crt" -noout 2>/dev/null; then
        error "Invalid agent certificate received"
        return 1
    fi
    if ! openssl x509 -in "$CERTS_DIR/ca.crt" -noout 2>/dev/null; then
        error "Invalid CA certificate received"
        return 1
    fi

    success "Enrolled as '$agent_id' — certificates saved"

    info "Generating configuration..."
    mkdir -p "$DATA_DIR" "$LOGS_DIR"
    cat > "$CONFIG_FILE" << CFGEOF
agent_id: "$agent_id"

manager:
  url: "$manager_url"
  ca_cert: "$CERTS_DIR/ca.crt"

agent:
  cert: "$CERTS_DIR/agent.crt"
  key: "$CERTS_DIR/agent.key"
  health_port: 8444

push:
  interval_seconds: 10
  batch_size: 500
  retry_max_seconds: 300

buffer:
  db_path: "$DATA_DIR/buffer.db"
  max_size_mb: 512

logs_dir: "$LOGS_DIR"
state_path: "$DATA_DIR/parser_state.json"

modules:
  ssh:
    enabled: true
    log_path: "ssh/sshd.log"
  ftp:
    enabled: true
    log_path: "ftp/vsftpd.log"
  http:
    enabled: true
    log_path: "http/access.log"
  modbus:
    enabled: true
    log_path: "modbus/modbus.log"
  mqtt:
    enabled: true
    log_path: "mqtt/mosquitto.log"
  telnet:
    enabled: true
    log_path: "telnet/auth.log"
  cve-2026-24061:
    enabled: false
    log_path: "cve/CVE-2026-24061/auth.log"
CFGEOF
    success "Config written: $CONFIG_FILE"

    info "Testing mTLS connection to manager..."
    local test_result
    test_result=$(curl -sk -o /dev/null -w "%{http_code}" \
        --cert "$CERTS_DIR/agent.crt" \
        --key "$CERTS_DIR/agent.key" \
        --cacert "$CERTS_DIR/ca.crt" \
        "${manager_url}/api/ingest" 2>/dev/null)

    if [ "$test_result" = "405" ] || [ "$test_result" = "200" ] || [ "$test_result" = "400" ]; then
        success "mTLS connection verified (HTTP $test_result)"
    else
        warn "mTLS test returned HTTP $test_result — connection may not be ready yet"
    fi

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
    success "Agent installation complete!"
    echo
    echo -e "${CYAN}Next steps:${RESET}"
    echo -e "  1. ${WHITE}sudo usermod -aG docker $USER${RESET} then re-login"
    echo -e "  2. Review modules in ${WHITE}$CONFIG_FILE${RESET}"
    echo -e "  3. ${WHITE}start${RESET} to launch honeypots + agent daemon"
    echo
}

# Check if the agent daemon process is running
daemon_running() {
    [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

# Start the agent daemon in the background
start_daemon() {
    if daemon_running; then
        info "Agent daemon already running (PID $(cat "$PID_FILE"))"
        return 0
    fi
    if [ ! -f "$CONFIG_FILE" ]; then
        error "Agent not configured. Run 'install' first."
        return 1
    fi
    mkdir -p "$DATA_DIR" "$LOGS_DIR"
    info "Starting agent daemon on host..."
    if [ ! -f "$VENV_PYTHON" ]; then
        error "Python venv not found. Run 'install' first."
        return 1
    fi
    nohup "$VENV_PYTHON" "$WORKING_DIRECTORY/daemon/agent_daemon.py" \
        --config "$CONFIG_FILE" \
        >> "$DAEMON_LOG" 2>&1 &
    local pid=$!
    echo "$pid" > "$PID_FILE"
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
        success "Agent daemon started (PID $pid) — log: daemon/agent.log"
    else
        error "Agent daemon failed to start — check daemon/agent.log"
        rm -f "$PID_FILE"
        return 1
    fi
}

# Stop the running agent daemon
stop_daemon() {
    if ! daemon_running; then
        info "Agent daemon not running"
        return 0
    fi
    local pid
    pid=$(cat "$PID_FILE")
    info "Stopping agent daemon (PID $pid)..."
    kill "$pid" 2>/dev/null
    local i=0
    while kill -0 "$pid" 2>/dev/null && [ $i -lt 10 ]; do
        sleep 1
        i=$((i + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null
    fi
    rm -f "$PID_FILE"
    success "Agent daemon stopped"
}

# Show all containers and daemon status
cmd_status() {
    if ! ensure_compose_cmd; then return 1; fi
    echo
    echo -e "${BOLD}${WHITE}   AGENT DAEMON${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"
    if daemon_running; then
        echo -e "   ${GREEN}●${RESET}  daemon                    ${DIM}PID $(cat "$PID_FILE")${RESET}"
    else
        echo -e "   ${RED}○${RESET}  daemon                    ${DIM}not running${RESET}"
    fi
    echo
    echo -e "${BOLD}${WHITE}   HONEYPOT SERVICES${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"

    local entries
    entries=$("${compose_cmd[@]}" ps --format '{{.Service}}|{{.State}}|{{.Health}}' 2>/dev/null)
    if [ -z "$entries" ]; then
        warn "   No services running."
        echo
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

# List available modules with enabled/running status
cmd_list() {
    echo
    echo -e "${BOLD}${WHITE}   AVAILABLE MODULES${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"
    printf "   ${DIM}%-18s %-8s %-10s %-10s %s${RESET}\n" "MODULE" "PORT" "CONFIG" "STATUS" "DESCRIPTION"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"

    for entry in "${MODULE_REGISTRY[@]}"; do
        IFS='|' read -r name service port desc <<< "$entry"

        local cfg_icon cfg_text
        if [ ! -f "$CONFIG_FILE" ]; then
            cfg_icon="${GRAY}?${RESET}"; cfg_text="no config"
        elif _mod_enabled "$name"; then
            cfg_icon="${GREEN}✓${RESET}"; cfg_text="enabled"
        else
            cfg_icon="${GRAY}○${RESET}"; cfg_text="disabled"
        fi

        local run_icon run_text
        if _mod_running "$service" 2>/dev/null; then
            run_icon="${GREEN}●${RESET}"; run_text="running"
        else
            run_icon="${RED}○${RESET}"; run_text="stopped"
        fi

        printf "   %-18s %-8s ${cfg_icon} %-10s ${run_icon} %-10s ${DIM}%s${RESET}\n" \
            "$name" ":$port" "$cfg_text" "$run_text" "$desc"
    done

    echo
    _detect_conflicts 2>/dev/null || true
}

# Enable a module in the agent configuration
cmd_enable() {
    if [ $# -eq 0 ]; then
        warn "Usage: enable <module>"
        return 1
    fi
    local name="$1"
    if ! _mod_field "$name" 0 >/dev/null 2>&1; then
        error "Unknown module: $name"
        echo -e "${DIM}  Use 'list' to see available modules${RESET}"
        return 1
    fi
    if [ ! -f "$CONFIG_FILE" ]; then
        error "Config file not found. Run 'install' first."
        return 1
    fi
    sed -i "/^  $name:/,/enabled:/{s/enabled: false/enabled: true/}" "$CONFIG_FILE"
    success "Module '$name' enabled"

    _detect_conflicts 2>/dev/null || true
}

# Disable a module in the agent configuration
cmd_disable() {
    if [ $# -eq 0 ]; then
        warn "Usage: disable <module>"
        return 1
    fi
    local name="$1"
    if ! _mod_field "$name" 0 >/dev/null 2>&1; then
        error "Unknown module: $name"
        echo -e "${DIM}  Use 'list' to see available modules${RESET}"
        return 1
    fi
    if [ ! -f "$CONFIG_FILE" ]; then
        error "Config file not found. Run 'install' first."
        return 1
    fi
    sed -i "/^  $name:/,/enabled:/{s/enabled: true/enabled: false/}" "$CONFIG_FILE"
    success "Module '$name' disabled"
}

# Start honeypot modules and the agent daemon
cmd_start() {
    if ! ensure_compose_cmd; then return 1; fi
    local target="${1:-all}"

    if [ "$target" = "all" ]; then
        if ! _detect_conflicts; then
            error "Resolve port conflicts before starting. Use 'disable <module>' to fix."
            return 1
        fi

        mkdir -p "$LOGS_DIR"/{ssh,ftp,web,modbus,mqtt,telnet,cve/CVE-2026-24061}

        local services=()
        for entry in "${MODULE_REGISTRY[@]}"; do
            IFS='|' read -r name service port desc <<< "$entry"
            if _mod_enabled "$name"; then
                if [ "$name" = "http" ]; then
                    services+=(melissae_apache1 melissae_apache2 melissae_proxy)
                else
                    services+=("$service")
                fi
            fi
        done

        if [ ${#services[@]} -eq 0 ]; then
            warn "No modules enabled. Use 'enable <module>' or 'list' to see available modules."
            return 1
        fi

        info "Starting ${#services[@]} enabled services..."
        "${compose_cmd[@]}" up --detach --quiet-pull "${services[@]}" 2>&1
        start_daemon
    else
        local service
        service=$(_mod_field "$target" 1 2>/dev/null)
        if [ -z "$service" ]; then
            error "Unknown module: $target"
            echo -e "${DIM}  Use 'list' to see available modules${RESET}"
            return 1
        fi

        info "Starting $target..."
        if [ "$target" = "http" ]; then
            "${compose_cmd[@]}" up --detach --quiet-pull melissae_apache1 melissae_apache2 melissae_proxy 2>&1
        else
            "${compose_cmd[@]}" up --detach --quiet-pull "$service" 2>&1
        fi
    fi
    success "Services started"
}

# Stop running modules
cmd_stop() {
    if ! ensure_compose_cmd; then return 1; fi
    local target="${1:-all}"

    if [ "$target" = "all" ]; then
        stop_daemon
        info "Stopping honeypot containers..."
        "${compose_cmd[@]}" stop 2>/dev/null
    else
        local service
        service=$(_mod_field "$target" 1 2>/dev/null)
        if [ -z "$service" ]; then
            error "Unknown module: $target"
            echo -e "${DIM}  Use 'list' to see available modules${RESET}"
            return 1
        fi
        info "Stopping $target..."
        if [ "$target" = "http" ]; then
            "${compose_cmd[@]}" stop melissae_apache1 melissae_apache2 melissae_proxy 2>/dev/null
        else
            "${compose_cmd[@]}" stop "$service" 2>/dev/null
        fi
    fi
    success "Services stopped"
}

# Restart all agent services
cmd_restart() {
    cmd_stop && cmd_start
}

# Rebuild agent containers
cmd_build() {
    if ! ensure_compose_cmd; then return 1; fi
    info "Rebuilding honeypot containers..."
    "${compose_cmd[@]}" build --no-cache
    success "Containers rebuilt"
}

# Show SQLite buffer status
cmd_buffer() {
    local db_path="$WORKING_DIRECTORY/data/buffer.db"
    echo
    echo -e "${BOLD}${WHITE}   BUFFER STATUS${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"

    if [ ! -f "$db_path" ]; then
        info "   Buffer database not found (daemon not started yet?)"
        echo
        return
    fi

    local total pending size oldest
    total=$(sqlite3 "$db_path" "SELECT COUNT(*) FROM pending_logs;" 2>/dev/null || echo "?")
    pending=$(sqlite3 "$db_path" "SELECT COUNT(*) FROM pending_logs WHERE sent = 0;" 2>/dev/null || echo "?")
    size=$(du -sh "$db_path" 2>/dev/null | awk '{print $1}' || echo "?")
    oldest=$(sqlite3 "$db_path" "SELECT MIN(created_at) FROM pending_logs WHERE sent = 0;" 2>/dev/null || echo "none")

    echo -e "   ${WHITE}Total entries:${RESET}    $total"
    echo -e "   ${WHITE}Pending:${RESET}          $pending"
    echo -e "   ${WHITE}DB size:${RESET}          $size"
    echo -e "   ${WHITE}Oldest pending:${RESET}   $oldest"
    echo
}

# Test mTLS connectivity to the manager
cmd_test_connection() {
    if [ ! -f "$CONFIG_FILE" ]; then
        error "Agent not configured. Run 'install' first."
        return 1
    fi

    local manager_url
    manager_url=$(grep "url:" "$CONFIG_FILE" | head -1 | awk '{print $2}' | tr -d '"')

    if [ -z "$manager_url" ]; then
        error "Manager URL not found in config"
        return 1
    fi

    info "Testing mTLS connection to $manager_url..."

    local http_code
    http_code=$(curl -sk -o /dev/null -w "%{http_code}" \
        --cert "$CERTS_DIR/agent.crt" \
        --key "$CERTS_DIR/agent.key" \
        --cacert "$CERTS_DIR/ca.crt" \
        "${manager_url}/api/ingest" 2>/dev/null)

    case "$http_code" in
        200|400|405)
            success "Connection OK (HTTP $http_code)"
            ;;
        000)
            error "Connection failed — manager unreachable"
            return 1
            ;;
        *)
            warn "Unexpected response: HTTP $http_code"
            ;;
    esac

    info "Testing health endpoint locally..."
    local health_code
    health_code=$(curl -sk -o /dev/null -w "%{http_code}" \
        --cert "$CERTS_DIR/agent.crt" \
        --key "$CERTS_DIR/agent.key" \
        --cacert "$CERTS_DIR/ca.crt" \
        "https://127.0.0.1:8444/health" 2>/dev/null)

    if [ "$health_code" = "200" ] || [ "$health_code" = "000" ]; then
        if [ "$health_code" = "200" ]; then
            success "Health endpoint OK"
        else
            warn "Health endpoint not responding (daemon not started?)"
        fi
    else
        warn "Health endpoint: HTTP $health_code"
    fi
}

# Show local raw logs for a module
cmd_logs() {
    if [ $# -eq 0 ]; then
        warn "Usage: logs <module> [count]"
        echo -e "${DIM}  Modules: ssh, ftp, http, modbus, mqtt, telnet${RESET}"
        return 1
    fi
    local module="$1"
    local count="${2:-30}"

    local log_file=""
    case "$module" in
        ssh)              log_file="ssh/sshd.log" ;;
        ftp)              log_file="ftp/vsftpd.log" ;;
        http)             log_file="web/access.log" ;;
        modbus)           log_file="modbus/modbus.log" ;;
        mqtt)             log_file="mqtt/mosquitto.log" ;;
        telnet)           log_file="telnet/auth.log" ;;
        cve-2026-24061)   log_file="cve/CVE-2026-24061/auth.log" ;;
        *)                error "Unknown module: $module"; echo -e "${DIM}  Use 'list' to see available modules${RESET}"; return 1 ;;
    esac

    local full_path="$LOGS_DIR/$log_file"
    if [ ! -f "$full_path" ]; then
        warn "Log file not found: $full_path"
        return 1
    fi

    echo
    echo -e "${BOLD}${WHITE}   LOGS: $module${RESET} ${DIM}(last $count lines)${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"
    tail -n "$count" "$full_path" | while IFS= read -r line; do
        echo -e "   ${DIM}${line}${RESET}"
    done
    echo
}

# Show the agent daemon log
cmd_daemon_log() {
    local count="${1:-50}"
    if [ ! -f "$DAEMON_LOG" ]; then
        warn "Daemon log not found (daemon not started yet?)"
        return 1
    fi
    echo
    echo -e "${BOLD}${WHITE}   DAEMON LOG${RESET} ${DIM}(last $count lines)${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"
    tail -n "$count" "$DAEMON_LOG" | while IFS= read -r line; do
        echo -e "   ${DIM}${line}${RESET}"
    done
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
            ""|"#"*)         continue ;;
            help|h|\?)       cmd_help ;;
            status|st)       cmd_status ;;
            start)           cmd_start "${params[@]}" ;;
            stop)            cmd_stop "${params[@]}" ;;
            restart)         cmd_restart ;;
            build)           cmd_build ;;
            list|ls)         cmd_list ;;
            enable)          cmd_enable "${params[@]}" ;;
            disable)         cmd_disable "${params[@]}" ;;
            buffer|buf)      cmd_buffer ;;
            test-connection) cmd_test_connection ;;
            logs)            cmd_logs "${params[@]}" ;;
            daemon-log)      cmd_daemon_log "${params[@]}" ;;
            install)         cmd_install "${params[@]}" ;;
            clear|cls)       clear ;;
            banner)          print_banner ;;
            version|ver)     echo -e "${DIM}Melissae Agent v${VERSION}${RESET}" ;;
            exit|quit|q)     echo -e "${DIM}Goodbye.${RESET}"; break ;;
            *)               error "Unknown command: $cmd"; echo -e "${DIM}Type 'help' for available commands${RESET}" ;;
        esac
    done
}

main_loop

