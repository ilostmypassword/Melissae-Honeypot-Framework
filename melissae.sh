#!/bin/bash

set -uo pipefail

WORKING_DIRECTORY=$(cd "$(dirname "$0")" && pwd)
cd "$WORKING_DIRECTORY" || exit 1
compose_cmd=()
VERSION="1.0.0"

HONEYPOT_MODULES=(web ftp ssh modbus mqtt telnet)
CVE_MODULES=(cve-2026-24061)
ALL_MODULES=("${HONEYPOT_MODULES[@]}" "${CVE_MODULES[@]}")

declare -A PORT_OWNERS=(
    [23]="telnet cve-2026-24061"
)

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
    echo -e "       ${CYAN}Melissae Honeypot Framework${RESET}  ${DIM}v${VERSION}${RESET}"
    echo -e "       ${DIM}Type 'help' for available commands${RESET}"
    echo
}

print_mini_banner() {
    echo -e "${MAGENTA}─── MELISSAE ───${RESET}"
}

get_prompt() {
    local running_count
    running_count=$(get_running_count 2>/dev/null || echo "?")
    echo -e "${BOLD}${GREEN}melissae${RESET} ${DIM}[${running_count} active]${RESET} ${CYAN}>${RESET} "
}

info()    { echo -e "${BLUE}[*]${RESET} $1"; }
success() { echo -e "${GREEN}[✓]${RESET} $1"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $1"; }
error()   { echo -e "${RED}[✗]${RESET} $1"; }
debug()   { echo -e "${GRAY}[~]${RESET} $1"; }

ensure_compose_cmd() {
    if [ ${#compose_cmd[@]} -gt 0 ]; then return 0; fi
    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        compose_cmd=(docker compose)
    elif command -v docker-compose >/dev/null 2>&1; then
        compose_cmd=(docker-compose)
    else
        error "Docker Compose not found. Run 'install' first."
        return 1
    fi
}

get_running_count() {
    ensure_compose_cmd 2>/dev/null || { echo "0"; return; }
    local count
    count=$("${compose_cmd[@]}" ps --format '{{.Service}}' 2>/dev/null | grep -c "melissae_" 2>/dev/null || true)
    echo "${count:-0}" | tr -d '[:space:]'
}

cmd_help() {
    echo
    echo -e "${BOLD}${WHITE}CORE COMMANDS${RESET}"
    echo -e "  ${CYAN}status${RESET}                    Show all modules and their status"
    echo -e "  ${CYAN}start${RESET} <module|all>       Start module(s)"
    echo -e "  ${CYAN}stop${RESET} [module|all]        Stop module(s) or all if none specified"
    echo -e "  ${CYAN}restart${RESET} <module|all>     Restart module(s)"
    echo -e "  ${CYAN}build${RESET} <module|all>       Rebuild container(s)"
    echo
    echo -e "${BOLD}${WHITE}MONITORING${RESET}"
    echo -e "  ${CYAN}logs${RESET} <module> [lines]    Show logs for a module (default: 50 lines)"
    echo -e "  ${CYAN}tail${RESET} <module>            Follow logs in real-time (Ctrl+C to stop)"
    echo -e "  ${CYAN}stats${RESET}                    Show attack statistics from database"
    echo -e "  ${CYAN}threats${RESET}                  Show top threat IPs with scores"
    echo -e "  ${CYAN}events${RESET} [count]           Show recent events (default: 20)"
    echo
    echo -e "${BOLD}${WHITE}MANAGEMENT${RESET}"
    echo -e "  ${CYAN}install${RESET}                  Install dependencies and configure system"
    echo -e "  ${CYAN}destroy${RESET}                  Stop and remove all containers"
    echo -e "  ${CYAN}purge${RESET}                    Clear all logs (requires confirmation)"
    echo
    echo -e "${BOLD}${WHITE}SHELL${RESET}"
    echo -e "  ${CYAN}clear${RESET}                    Clear screen"
    echo -e "  ${CYAN}banner${RESET}                   Show banner"
    echo -e "  ${CYAN}version${RESET}                  Show version"
    echo -e "  ${CYAN}exit${RESET}, ${CYAN}quit${RESET}               Exit console"
    echo
    echo -e "${BOLD}${WHITE}AVAILABLE MODULES${RESET}"
    echo -e "  ${GREEN}Honeypots:${RESET}  $(IFS=' '; echo "${HONEYPOT_MODULES[*]}")"
    echo -e "  ${YELLOW}CVE:${RESET}        $(IFS=' '; echo "${CVE_MODULES[*]}")"
    echo
    echo -e "${DIM}Note: CVE modules may conflict with standard modules on same ports.${RESET}"
    echo
}

cmd_status() {
    if ! ensure_compose_cmd; then return 1; fi
    echo

    local services_all
    services_all=$("${compose_cmd[@]}" config --services 2>/dev/null)
    if [ -z "$services_all" ]; then
        warn "No modules found in compose configuration."
        return 0
    fi

    declare -A state_map health_map
    local entries
    entries=$("${compose_cmd[@]}" ps --format '{{.Service}}|{{.State}}|{{.Health}}' 2>/dev/null)
    if [ -n "$entries" ]; then
        while IFS='|' read -r svc state health; do
            [ -z "$svc" ] && continue
            state_map[$svc]=$state
            health_map[$svc]=$health
        done <<< "$entries"
    fi

    local honeypot_rows=() cve_rows=() system_rows=()

    for svc in $services_all; do
        local module="other"
        case "${svc,,}" in
            *cve*) module="cve" ;;
            *apache*|*proxy*) module="web" ;;
            *ssh*) module="ssh" ;;
            *ftp*) module="ftp" ;;
            *modbus*) module="modbus" ;;
            *mqtt*) module="mqtt" ;;
            *telnet*) module="telnet" ;;
            *dashboard*) module="dashboard" ;;
            *api*) module="api" ;;
            *mongo*) module="mongodb" ;;
        esac

        local state=${state_map[$svc]:-stopped}
        local health=${health_map[$svc]:-}
        local icon color

        if echo "$state" | grep -Eqi "up|running"; then
            icon="●"
            color="${GREEN}"
        else
            icon="○"
            color="${RED}"
        fi

        local row
        row=$(printf "${color}%s${RESET}  %-10s  %-24s  ${DIM}%s${RESET}" "$icon" "$module" "$svc" "$health")

        case "$module" in
            web|ssh|ftp|modbus|mqtt|telnet) honeypot_rows+=("$row") ;;
            cve) cve_rows+=("$row") ;;
            *) system_rows+=("$row") ;;
        esac
    done

    echo -e "${BOLD}${WHITE}   HONEYPOT MODULES${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"
    for r in "${honeypot_rows[@]}"; do
        echo -e "   $r"
    done

    if [ ${#cve_rows[@]} -gt 0 ]; then
        echo
        echo -e "${BOLD}${YELLOW}   CVE MODULES${RESET}"
        echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"
        for r in "${cve_rows[@]}"; do
            echo -e "   $r"
        done
    fi

    echo
    echo -e "${BOLD}${CYAN}   SYSTEM SERVICES${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"
    for r in "${system_rows[@]}"; do
        echo -e "   $r"
    done
    echo
}

declare -A MODULE_TO_SERVICE=(
    [telnet]="melissae_telnet"
    [cve-2026-24061]="melissae_cve_2026_24061"
)

get_running_port_modules() {
    local running=()
    if ! ensure_compose_cmd 2>/dev/null; then return; fi
    
    local running_services
    running_services=$("${compose_cmd[@]}" ps --format '{{.Service}}|{{.State}}' 2>/dev/null)
    
    for port in "${!PORT_OWNERS[@]}"; do
        local owners=(${PORT_OWNERS[$port]})
        for mod in "${owners[@]}"; do
            local svc="${MODULE_TO_SERVICE[$mod]:-}"
            [ -z "$svc" ] && continue
            if echo "$running_services" | grep -q "^${svc}|.*running"; then
                running+=("$mod")
            fi
        done
    done
    echo "${running[*]}"
}

check_port_conflicts() {
    local requested=("$@")
    
    local running_mods
    running_mods=$(get_running_port_modules)
    
    for port in "${!PORT_OWNERS[@]}"; do
        local owners=(${PORT_OWNERS[$port]})
        local found=()
        
        for mod in "${requested[@]}"; do
            for owner in "${owners[@]}"; do
                if [ "$mod" = "$owner" ]; then
                    found+=("$mod")
                fi
            done
        done
        
        for running_mod in $running_mods; do
            local already_in_found=0
            for f in "${found[@]}"; do
                [ "$f" = "$running_mod" ] && already_in_found=1
            done
            
            if [ $already_in_found -eq 0 ]; then
                for owner in "${owners[@]}"; do
                    if [ "$running_mod" = "$owner" ]; then
                        for req in "${requested[@]}"; do
                            for ow2 in "${owners[@]}"; do
                                if [ "$req" = "$ow2" ] && [ "$req" != "$running_mod" ]; then
                                    error "Port $port conflict: '$req' cannot start while '$running_mod' is running"
                                    warn "Stop '$running_mod' first: stop $running_mod"
                                    return 1
                                fi
                            done
                        done
                    fi
                done
            fi
        done
        
        if [ ${#found[@]} -gt 1 ]; then
            error "Port $port conflict: ${found[*]} cannot run together"
            return 1
        fi
    done
    return 0
}

get_services_for_module() {
    local module=$1
    case "$module" in
        all)
            echo "melissae_mongo melissae_api melissae_apache1 melissae_apache2 melissae_proxy melissae_dashboard melissae_ftp melissae_ssh melissae_modbus melissae_mqtt melissae_telnet"
            ;;
        web)
            echo "melissae_mongo melissae_api melissae_apache1 melissae_apache2 melissae_proxy melissae_dashboard"
            ;;
        ftp)
            echo "melissae_mongo melissae_api melissae_ftp melissae_dashboard"
            ;;
        ssh)
            echo "melissae_mongo melissae_api melissae_ssh melissae_dashboard"
            ;;
        modbus)
            echo "melissae_mongo melissae_api melissae_modbus melissae_dashboard"
            ;;
        mqtt)
            echo "melissae_mongo melissae_api melissae_mqtt melissae_dashboard"
            ;;
        telnet)
            echo "melissae_mongo melissae_api melissae_telnet melissae_dashboard"
            ;;
        cve-2026-24061)
            echo "melissae_mongo melissae_api melissae_cve_2026_24061 melissae_dashboard"
            ;;
        *)
            return 1
            ;;
    esac
}

cmd_start() {
    if [ $# -eq 0 ]; then
        warn "Usage: start <module|all> [module2 ...]"
        echo -e "${DIM}Available: $(IFS=' '; echo "${ALL_MODULES[*]}") all${RESET}"
        return 1
    fi

    if ! ensure_compose_cmd; then return 1; fi
    if ! check_port_conflicts "$@"; then return 1; fi

    local services=()
    for module in "$@"; do
        local mod_services
        mod_services=$(get_services_for_module "$module")
        if [ $? -ne 0 ] || [ -z "$mod_services" ]; then
            error "Unknown module: $module"
            return 1
        fi
        services+=($mod_services)
    done

    declare -A seen
    local unique_services=()
    for svc in "${services[@]}"; do
        if [ -z "${seen[$svc]:-}" ]; then
            unique_services+=("$svc")
            seen[$svc]=1
        fi
    done

    info "Starting ${#unique_services[@]} service(s)..."

    if "${compose_cmd[@]}" up --detach --quiet-pull "${unique_services[@]}" 2>&1; then
        success "Module(s) started: $*"
    else
        error "Failed to start some services"
        return 1
    fi
}

cmd_stop() {
    if ! ensure_compose_cmd; then return 1; fi

    if [ $# -eq 0 ] || [ "$1" = "all" ]; then
        info "Stopping all services..."
        "${compose_cmd[@]}" stop 2>/dev/null
        success "All services stopped"
    else
        local services=()
        for module in "$@"; do
            local mod_services
            mod_services=$(get_services_for_module "$module")
            if [ $? -ne 0 ] || [ -z "$mod_services" ]; then
                error "Unknown module: $module"
                return 1
            fi
            services+=($mod_services)
        done
        info "Stopping ${#services[@]} service(s)..."
        "${compose_cmd[@]}" stop "${services[@]}" 2>/dev/null
        success "Module(s) stopped: $*"
    fi
}

cmd_restart() {
    if [ $# -eq 0 ]; then
        warn "Usage: restart <module|all>"
        return 1
    fi
    cmd_stop "$@" && cmd_start "$@"
}

cmd_build() {
    if ! ensure_compose_cmd; then return 1; fi

    if [ $# -eq 0 ] || [ "$1" = "all" ]; then
        info "Rebuilding all containers..."
        "${compose_cmd[@]}" build --no-cache
        success "All containers rebuilt"
    else
        local services=()
        for module in "$@"; do
            local mod_services
            mod_services=$(get_services_for_module "$module")
            if [ -z "$mod_services" ]; then
                error "Unknown module: $module"
                return 1
            fi
            services+=($mod_services)
        done
        info "Rebuilding containers..."
        "${compose_cmd[@]}" build --no-cache "${services[@]}"
        success "Containers rebuilt: $*"
    fi
}

get_log_file_for_module() {
    local module=$1
    case "$module" in
        ssh)            echo "modules/ssh/logs/sshd.log" ;;
        web)            echo "modules/web/logs/access.log" ;;
        ftp)            echo "modules/ftp/logs/vsftpd.log" ;;
        modbus)         echo "modules/modbus/logs/modbus.log" ;;
        mqtt)           echo "modules/mqtt/logs/mosquitto.log" ;;
        telnet)         echo "modules/telnet/logs/auth.log" ;;
        cve-2026-24061) echo "modules/cve/CVE-2026-24061/logs/auth.log" ;;
        *)              return 1 ;;
    esac
}

cmd_logs() {
    if [ $# -eq 0 ]; then
        warn "Usage: logs <module> [lines]"
        echo -e "${DIM}Available: ${ALL_MODULES[*]}${RESET}"
        return 1
    fi

    local module=$1
    local lines=${2:-50}
    local logfile
    logfile=$(get_log_file_for_module "$module")

    if [ $? -ne 0 ] || [ -z "$logfile" ]; then
        error "Unknown module: $module"
        return 1
    fi

    if [ ! -f "$logfile" ]; then
        warn "Log file not found: $logfile"
        return 1
    fi

    echo -e "${DIM}── $logfile (last $lines lines) ──${RESET}"
    tail -n "$lines" "$logfile" | while read -r line; do
        # Color code by severity
        if echo "$line" | grep -Eiq 'fail|error|denied|invalid'; then
            echo -e "${RED}$line${RESET}"
        elif echo "$line" | grep -Eiq 'success|accepted|login'; then
            echo -e "${GREEN}$line${RESET}"
        else
            echo "$line"
        fi
    done
}

cmd_tail() {
    if [ $# -eq 0 ]; then
        warn "Usage: tail <module>"
        return 1
    fi

    local logfile
    logfile=$(get_log_file_for_module "$1")

    if [ -z "$logfile" ]; then
        error "Unknown module: $1"
        return 1
    fi

    if [ ! -f "$logfile" ]; then
        warn "Log file not found: $logfile"
        return 1
    fi

    info "Following $logfile (Ctrl+C to stop)..."
    tail -f "$logfile"
}

cmd_stats() {
    echo
    echo -e "${BOLD}${WHITE}   ATTACK STATISTICS${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"

    # Query MongoDB for stats
    local mongo_stats
    mongo_stats=$(python3 -c "
from pymongo import MongoClient
from datetime import datetime, timedelta
import sys
try:
    client = MongoClient('mongodb://127.0.0.1:27017', serverSelectionTimeoutMS=2000)
    db = client['melissae']

    total = db.logs.count_documents({})
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    today_count = db.logs.count_documents({'timestamp': {'\$gte': today}})

    # By protocol
    pipeline = [
        {'\$group': {'_id': '\$protocol', 'count': {'\$sum': 1}}},
        {'\$sort': {'count': -1}}
    ]
    by_proto = list(db.logs.aggregate(pipeline))

    # Unique IPs
    unique_ips = len(db.logs.distinct('ip'))

    # Top IPs
    ip_pipeline = [
        {'\$group': {'_id': '\$ip', 'count': {'\$sum': 1}}},
        {'\$sort': {'count': -1}},
        {'\$limit': 5}
    ]
    top_ips = list(db.logs.aggregate(ip_pipeline))

    print(f'TOTAL:{total}')
    print(f'TODAY:{today_count}')
    print(f'UNIQUE_IPS:{unique_ips}')
    for p in by_proto:
        print(f'PROTO:{p[\"_id\"]}:{p[\"count\"]}')
    for ip in top_ips:
        print(f'TOP_IP:{ip[\"_id\"]}:{ip[\"count\"]}')
except Exception as e:
    print(f'ERROR:{e}')
    sys.exit(1)
" 2>/dev/null)

    if [ $? -ne 0 ] || echo "$mongo_stats" | grep -q "^ERROR:"; then
        warn "Cannot connect to MongoDB. Is melissae_mongo running?"
        return 1
    fi

    local total today unique_ips
    total=$(echo "$mongo_stats" | grep "^TOTAL:" | cut -d: -f2)
    today=$(echo "$mongo_stats" | grep "^TODAY:" | cut -d: -f2)
    unique_ips=$(echo "$mongo_stats" | grep "^UNIQUE_IPS:" | cut -d: -f2)

    echo -e "   ${WHITE}Total Events:${RESET}    $total"
    echo -e "   ${WHITE}Today:${RESET}           $today"
    echo -e "   ${WHITE}Unique IPs:${RESET}      $unique_ips"
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

cmd_threats() {
    echo
    echo -e "${BOLD}${WHITE}   THREAT INTELLIGENCE${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"

    local threat_data
    threat_data=$(python3 -c "
from pymongo import MongoClient
import sys
try:
    client = MongoClient('mongodb://127.0.0.1:27017', serverSelectionTimeoutMS=2000)
    db = client['melissae']

    threats = db.threats.find().sort('protocol-score', -1).limit(15)
    for t in threats:
        ip = t.get('ip', 'unknown')
        score = t.get('protocol-score', 0)
        reasons = ', '.join(t.get('reasons', [])[:2])
        print(f'{ip}|{score}|{reasons}')
except Exception as e:
    print(f'ERROR:{e}')
    sys.exit(1)
" 2>/dev/null)

    if [ $? -ne 0 ] || echo "$threat_data" | grep -q "^ERROR:"; then
        warn "Cannot connect to MongoDB or no threat data."
        return 1
    fi

    if [ -z "$threat_data" ]; then
        info "No threat data available yet."
        return 0
    fi

    printf "   ${DIM}%-18s %-8s %s${RESET}\n" "IP" "SCORE" "REASONS"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"
    echo "$threat_data" | while IFS='|' read -r ip score reasons; do
        local color="$GREEN"
        if [ "$score" -ge 70 ]; then
            color="$RED"
        elif [ "$score" -ge 40 ]; then
            color="$YELLOW"
        fi
        printf "   %-18s ${color}%-8s${RESET} ${DIM}%s${RESET}\n" "$ip" "$score" "$reasons"
    done
    echo
}

cmd_events() {
    local count=${1:-20}
    echo
    echo -e "${BOLD}${WHITE}   RECENT EVENTS${RESET} ${DIM}(last $count)${RESET}"
    echo -e "${DIM}   ─────────────────────────────────────────────────${RESET}"

    python3 -c "
from pymongo import MongoClient
from datetime import datetime
import sys
try:
    client = MongoClient('mongodb://127.0.0.1:27017', serverSelectionTimeoutMS=2000)
    db = client['melissae']

    events = db.logs.find().sort('timestamp', -1).limit($count)
    for e in events:
        ts = e.get('timestamp', '')
        if isinstance(ts, datetime):
            ts = ts.strftime('%H:%M:%S')
        proto = e.get('protocol', '?')[:6]
        ip = e.get('ip', 'unknown')
        action = e.get('action', '')[:30]
        print(f'{ts}|{proto}|{ip}|{action}')
except Exception as e:
    print(f'ERROR:{e}')
    sys.exit(1)
" 2>/dev/null | while IFS='|' read -r ts proto ip action; do
        if [ "$proto" = "ERROR" ]; then
            warn "Cannot connect to MongoDB"
            return 1
        fi
        local color="$WHITE"
        case "$action" in
            *fail*|*denied*|*invalid*) color="$RED" ;;
            *success*|*accepted*) color="$GREEN" ;;
        esac
        printf "   ${DIM}%s${RESET}  %-8s  %-16s  ${color}%s${RESET}\n" "$ts" "$proto" "$ip" "$action"
    done
    echo
}

cmd_destroy() {
    warn "This will stop and remove ALL containers and networks."
    read -p "Are you sure? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        info "Cancelled"
        return 0
    fi

    if ! ensure_compose_cmd; then return 1; fi
    info "Destroying stack..."
    "${compose_cmd[@]}" down 2>/dev/null
    success "Stack destroyed"
}

cmd_purge() {
    warn "This will delete ALL log files."
    read -p "Are you sure? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        info "Cancelled"
        return 0
    fi

    info "Purging logs..."
    find modules -name "*.log" -type f -exec truncate -s 0 {} \; 2>/dev/null
    success "All logs purged"
}

cmd_install() {
    echo
    info "Starting Melissae installation..."
    echo

    info "Installing prerequisites..."
    sudo apt-get update > /dev/null 2>&1
    sudo apt-get install -y ca-certificates curl cron apache2-utils python3-pymongo > /dev/null 2>&1
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

    info "Setting log directory permissions..."
    for dir in modules/*/logs modules/cve/*/logs; do
        [ -d "$dir" ] && sudo chown -R "$USER":"$USER" "$dir" && sudo chmod -R 755 "$dir"
    done
    sudo chmod -R 777 modules/ssh/logs 2>/dev/null || true
    success "Permissions configured"

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
    
    add_cron "* * * * * /usr/bin/python3 $WORKING_DIRECTORY/scripts/logParser.py" "logParser"
    add_cron "* * * * * /usr/bin/python3 $WORKING_DIRECTORY/scripts/threatIntel.py" "threatIntel"
    add_cron "0 */3 * * * /usr/bin/python3 $WORKING_DIRECTORY/scripts/purgeLogs.py" "purgeLogs"
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
    else
        warn "Remember to restart SSH manually: sudo systemctl restart sshd"
    fi

    echo
    success "Installation complete!"
    echo
    echo -e "${CYAN}Next steps:${RESET}"
    echo -e "  1. Add yourself to docker group: ${WHITE}sudo usermod -aG docker $USER${RESET}"
    echo -e "  2. Log out and back in (or run: ${WHITE}newgrp docker${RESET})"
    echo -e "  3. Start modules: ${WHITE}start ssh${RESET} or ${WHITE}start all${RESET}"
    echo
}

setup_completion() {
    local commands="help status start stop restart build logs tail stats threats events install destroy purge clear banner version exit quit"
    local modules="${ALL_MODULES[*]} all"

    COMP_WORDBREAKS=${COMP_WORDBREAKS//:}
    
    complete_cmd() {
        local cur="${COMP_WORDS[COMP_CWORD]}"
        local cmd="${COMP_WORDS[0]}"
        
        if [ "$COMP_CWORD" -eq 0 ]; then
            COMPREPLY=($(compgen -W "$commands" -- "$cur"))
        else
            case "$cmd" in
                start|stop|restart|build|logs|tail)
                    COMPREPLY=($(compgen -W "$modules" -- "$cur"))
                    ;;
            esac
        fi
    }
    
    complete -F complete_cmd -o default melissae
}

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
            ""|"#"*)
                continue
                ;;
            help|h|\?)
                cmd_help
                ;;
            status|st)
                cmd_status
                ;;
            start)
                cmd_start "${params[@]}"
                ;;
            stop)
                cmd_stop "${params[@]}"
                ;;
            restart)
                cmd_restart "${params[@]}"
                ;;
            build)
                cmd_build "${params[@]}"
                ;;
            logs)
                cmd_logs "${params[@]}"
                ;;
            tail)
                cmd_tail "${params[@]}"
                ;;
            stats)
                cmd_stats
                ;;
            threats)
                cmd_threats
                ;;
            events)
                cmd_events "${params[@]}"
                ;;
            install)
                cmd_install
                ;;
            destroy)
                cmd_destroy
                ;;
            purge)
                cmd_purge
                ;;
            clear|cls)
                clear
                ;;
            banner)
                print_banner
                ;;
            version|ver)
                echo -e "${DIM}Melissae v${VERSION}${RESET}"
                ;;
            exit|quit|q)
                echo -e "${DIM}Goodbye.${RESET}"
                break
                ;;
            *)
                error "Unknown command: $cmd"
                echo -e "${DIM}Type 'help' for available commands${RESET}"
                ;;
        esac
    done
}

main_loop
