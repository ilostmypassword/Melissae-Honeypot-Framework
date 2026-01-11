#!/bin/bash

# Enable strict mode and safe IFS
set -euo pipefail
IFS=$'\n\t'
compose_cmd=()
WORKING_DIRECTORY=$(pwd)
important_notes=()
todo_notes=()
SLEEP_ENABLED=1

# Install required packages
install_prereqs() {
    print_message "Updating packages"
    sudo apt-get update > /dev/null 2>&1

    print_message "Installing prerequisite packages"
    sudo apt-get install ca-certificates curl cron apache2-utils -y > /dev/null 2>&1
}

# Install Docker engine, CLI, compose plugin, and pymongo client
install_docker_stack() {
    print_message "Installing Docker's GPG key"
    sudo install -m 0755 -d /etc/apt/keyrings > /dev/null 2>&1
    sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc > /dev/null 2>&1
    sudo chmod a+r /etc/apt/keyrings/docker.asc > /dev/null 2>&1

    print_message "Setting up Docker repository"
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null 2>&1

    print_message "Updating packages after adding Docker repository"
    sudo apt-get update > /dev/null 2>&1

    print_message "Installing Docker packages"
    DOCKER_PACKAGES=(docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin python3-pymongo)
    if ! sudo apt-get install "${DOCKER_PACKAGES[@]}" -y > /dev/null 2>&1; then
        print_message "Removing legacy docker-compose package and retrying"
        sudo apt-get remove -y docker-compose > /dev/null 2>&1 || true
        sudo apt-get install "${DOCKER_PACKAGES[@]}" -y > /dev/null 2>&1
    fi
}

# Resolve docker compose CLI
ensure_compose_cmd() {
    if [ ${#compose_cmd[@]} -gt 0 ]; then
        return 0
    fi

    if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        compose_cmd=(docker compose)
    elif command -v docker-compose >/dev/null 2>&1; then
        compose_cmd=(docker-compose)
    else
        print_message "docker compose / docker-compose is required."
        return 1
    fi
}

# Add a cron job if missing
add_cron_job() {
    local schedule=$1
    local cmd=$2
    local label=$3
    local current_cron
    current_cron=$(crontab -l 2>/dev/null || echo "")
    if echo "$current_cron" | grep -Fq "$cmd"; then
        print_message "$label already in crontab. Skipping."
        return
    fi
    (echo "$current_cron"; echo "$schedule $cmd") | crontab -
    print_message "$label added to crontab."
}

# Print ASCII banner
print_banner() {
    echo "
█▀▄▀█ ▄███▄   █    ▄█    ▄▄▄▄▄    ▄▄▄▄▄   ██   ▄███▄  
█ █ █ █▀   ▀  █    ██   █     ▀▄ █     ▀▄ █ █  █▀   ▀ 
█ ▄ █ ██▄▄    █    ██ ▄  ▀▀▀▀▄ ▄  ▀▀▀▀▄   █▄▄█ ██▄▄   
█   █ █▄   ▄▀ ███▄ ▐█  ▀▄▄▄▄▀   ▀▄▄▄▄▀    █  █ █▄   ▄▀
   █  ▀███▀       ▀ ▐                        █ ▀███▀  
  ▀                                         █         
                                           ▀          
    "
}

# Print generic info message
print_message() {
    echo -e "\e[33m[*] $1\e[0m"
    if [ "${SLEEP_ENABLED:-1}" -eq 1 ]; then sleep 1; fi
}

# Print success message
print_ok_message() {
    echo -e "\e[32m[*] $1\e[0m"
    if [ "${SLEEP_ENABLED:-1}" -eq 1 ]; then sleep 1; fi
}

# Collect an important note for the final summary
add_note() {
    important_notes+=("$1")
}

# Collect a TODO note for the final summary
add_todo_note() {
    todo_notes+=("$1")
}

# Print a list item
print_item() {
    echo -e "\e[36m  - $1\e[0m"
    if [ "${SLEEP_ENABLED:-1}" -eq 1 ]; then sleep 1; fi
}

# Display collected important notes
flush_important_notes() {
    if [ ${#important_notes[@]} -eq 0 ] && [ ${#todo_notes[@]} -eq 0 ]; then
        return
    fi
    for note in "${important_notes[@]}"; do
        echo -e "\e[32m\e[1m[OK] $note\e[0m"
        sleep 1
    done
    for note in "${todo_notes[@]}"; do
        echo -e "\e[34m\e[1m[TODO] $note\e[0m"
        sleep 1
    done
}

# Show help and usage
show_help() {
    local prev_sleep=${SLEEP_ENABLED:-1}
    SLEEP_ENABLED=0
    print_banner
    print_message "Usage: $0 [option] [modules...]"
    echo
    print_message "Options"
    print_item "help       Help menu"
    print_item "install    Install Melissae"
    print_item "start      Start modules"
    print_item "list       List deployed modules"
    print_item "destroy    Destroy the Stack"
    echo
    print_message "Available modules"
    print_item "all        Deploy all modules"
    print_item "web        Web stack + [Dashboard & MongoDB]"
    print_item "ftp        FTP + [Dashboard & MongoDB]"
    print_item "ssh        SSH + [Dashboard & MongoDB]"
    print_item "modbus     Modbus + [Dashboard & MongoDB]"
    print_item "mqtt       Mosquitto + [Dashboard & MongoDB]"
    echo
    print_message "Exemples"
    print_item "./melissae.sh install        # Installs Melissae"
    print_item "./melissae.sh start all      # Starts all modules"
    print_item "./melissae.sh list           # Lists deployed modules"
    print_item "./melissae.sh destroy        # Destroys the stack"
    SLEEP_ENABLED=$prev_sleep
}

# List running modules and their states
list_modules() {
    local prev_sleep=${SLEEP_ENABLED:-1}
    SLEEP_ENABLED=0
    print_banner
    if ! ensure_compose_cmd; then return 1; fi

    services_all=$("${compose_cmd[@]}" config --services 2>/dev/null)
    if [ -z "$services_all" ]; then
        print_message "No modules found in compose configuration."
        return 0
    fi

    declare -A state_map
    entries=$("${compose_cmd[@]}" ps --format '{{.Service}}|{{.State}}' 2>/dev/null)
    if [ -n "$entries" ]; then
        while IFS='|' read -r svc state; do
            [ -z "$svc" ] && continue
            state_map[$svc]=$state
        done <<< "$entries"
    fi

    honeypot_rows=()
    system_rows=()

    for svc in $services_all; do
        module="other"
        case "${svc,,}" in
            # Honeypot modules
            *apache*|*proxy*) module="web" ;;
            *ssh*) module="ssh" ;;
            *ftp*) module="ftp" ;;
            *modbus*) module="modbus" ;;
            *mqtt*) module="mqtt" ;;
            # System modules
            *dashboard*) module="dashboard" ;;
            *api*) module="api" ;;
            *mongo*) module="mongodb" ;;
        esac

        state=${state_map[$svc]:-down}
        icon="❌"
        if echo "$state" | grep -Eqi "up|running"; then
            icon="✅"
        fi

        row=$(printf "%-12s %-22s %-8s" "$module" "$svc" "$icon")

        case "$module" in
            web|ssh|ftp|modbus|mqtt) honeypot_rows+=("$row") ;;
            dashboard|api|mongodb) system_rows+=("$row") ;;
            *) system_rows+=("$row") ;;
        esac
    done

    print_message "Honeypot modules\n"
    printf "%-12s %-22s %-8s\n" "Module" "Service" "State"
    echo "---------------------------------------------"
    for r in "${honeypot_rows[@]}"; do
        echo "$r"
    done
    echo
    print_message "System modules\n"
    printf "%-12s %-22s %-8s\n" "Module" "Service" "State"
    echo "---------------------------------------------"
    for r in "${system_rows[@]}"; do
        echo "$r"
    done
    SLEEP_ENABLED=$prev_sleep
}

# Install dependencies, Docker, and configure basics
install() {
    print_banner
    install_prereqs

    print_message "Checking Docker installation"
    if command -v docker >/dev/null 2>&1 && docker --version >/dev/null 2>&1; then
        print_message "Docker already installed. Skipping package installation."
    else
        install_docker_stack
    fi

    print_message "Enabling and starting Docker service"
    sudo systemctl enable --now docker > /dev/null 2>&1 || true

    print_message "Setting safe permissions for log directories"
    sudo chown -R "$USER":"$USER" modules/web/logs modules/ftp/logs modules/modbus/logs modules/mqtt/logs
    sudo chmod -R 755 modules/web/logs modules/ftp/logs modules/modbus/logs modules/mqtt/logs
    sudo chmod -R 777 modules/ssh/logs

    print_message "Configuring dashboard basic authentication"
    HTPASSWD_FILE="$WORKING_DIRECTORY/dashboard/conf/htpasswd"
    read -p "Dashboard username [melissae]: " DASH_USER
    DASH_USER=${DASH_USER:-melissae}
    while true; do
        read -s -p "Dashboard password: " DASH_PASS
        echo
        read -s -p "Confirm password: " DASH_PASS_CONFIRM
        echo
        if [ -z "$DASH_PASS" ]; then
            print_message "Password cannot be empty."
            continue
        fi
        if [ "$DASH_PASS" != "$DASH_PASS_CONFIRM" ]; then
            print_message "Passwords do not match."
            continue
        fi
        break
    done
    htpasswd -Bbc "$HTPASSWD_FILE" "$DASH_USER" "$DASH_PASS" > /dev/null 2>&1
    unset DASH_PASS DASH_PASS_CONFIRM
    print_message "Dashboard credentials saved"
    add_note "Dashboard credentials stored at $HTPASSWD_FILE"

    print_message "Adding cleaning scripts to crontab"
    add_cron_job "* * * * *" "/usr/bin/python3 $WORKING_DIRECTORY/scripts/logParser.py" "logParser.py"
    add_cron_job "* * * * *" "/usr/bin/python3 $WORKING_DIRECTORY/scripts/threatIntel.py" "threatIntel.py"
    add_cron_job "0 0 * * *" "/usr/bin/python3 $WORKING_DIRECTORY/scripts/purgeLogs.py" "purgeLogs.py"


    print_message "Generating a random port for SSH"
    RANDOM_PORT=$((RANDOM % 10000 + 20000))

    current_user=${USER:-$(whoami)}

    ssh_forward_cmd="ssh -L 8080:localhost:9999 ${current_user}@IP -p $RANDOM_PORT"

    print_message "Modifying SSH configuration with the new port"
    sudo sed -i '/^Port /s/^/#/' /etc/ssh/sshd_config > /dev/null 2>&1
    echo "Port $RANDOM_PORT" | sudo tee -a /etc/ssh/sshd_config > /dev/null 2>&1

    add_note "SSH administration port configured on $RANDOM_PORT"

    read -p "Do you want to restart the SSH server now? (yes/no): " answer

    if [ "$answer" == "yes" ]; then
        print_message "Restarting the SSH server"
        sudo systemctl disable --now ssh.socket > /dev/null 2>&1
        sudo systemctl restart sshd > /dev/null 2>&1
        print_message "The SSH server has been restarted."
    else
        print_message "Warning: You need to restart the SSH server to apply the changes. Use 'sudo systemctl restart sshd' to restart later."
        add_note "Restart SSH manually to apply port $RANDOM_PORT (sudo systemctl restart sshd)"
    fi
    add_todo_note "Add your user to the docker group with 'sudo usermod -aG docker $current_user'"
    add_todo_note "Reconnect to the server with '$ssh_forward_cmd'"
    add_todo_note "Start the stack with './melissae.sh start [modules]'"
}

# Start selected modules
start() {
    print_banner
    if [ $# -eq 0 ]; then
        print_message "No module specified."
        return
    fi

    if ! ensure_compose_cmd; then return 1; fi

    modules=("$@")
    services=()

    for module in "${modules[@]}"; do
        case "$module" in
            all)
                services+=("melissae_mongo" "melissae_api" "melissae_apache1" "melissae_apache2" "melissae_proxy" "melissae_dashboard" "melissae_ftp" "melissae_ssh" "melissae_modbus" "melissae_mqtt")
                ;;
            web)
                services+=("melissae_mongo" "melissae_api" "melissae_apache1" "melissae_apache2" "melissae_proxy" "melissae_dashboard")
                ;;
            ftp)
                services+=("melissae_mongo" "melissae_api" "melissae_ftp" "melissae_dashboard")
                ;;
            ssh)
                services+=("melissae_mongo" "melissae_api" "melissae_ssh" "melissae_dashboard")
                ;;
            modbus)
                services+=("melissae_mongo" "melissae_api" "melissae_modbus" "melissae_dashboard")
                ;;
            mqtt)
                services+=("melissae_mongo" "melissae_api" "melissae_mqtt" "melissae_dashboard")
                ;;
            *)
                echo "Unknown module: $module"
                show_help
                exit 1
                ;;
        esac
    done

    declare -A seen
    unique_services=()
    for svc in "${services[@]}"; do
        if [ -z "${seen[$svc]:-}" ]; then
            unique_services+=("$svc")
            seen[$svc]=1
        fi
    done

    print_message "Starting services:"
    for svc in "${unique_services[@]}"; do
        print_item "$svc"
    done

    if output=$("${compose_cmd[@]}" up --detach --quiet-pull "${unique_services[@]}" 2>&1); then
        print_ok_message "Services started successfully."
    else
        echo "$output"
        return 1
    fi
}

# Stop and remove all containers
destroy() {
    print_banner
    print_message "Destroying containers..."
    if ! ensure_compose_cmd; then return 1; fi
    "${compose_cmd[@]}" down > /dev/null 2>&1
    print_ok_message "Containers destroyed"
}

if [ $# -eq 0 ]; then
    show_help
else
    case "$1" in
        help)
            show_help
            ;;
        install)
            install
            ;;
        start)
            shift
            start "$@"
            ;;
        list)
            list_modules
            ;;
        destroy)
            destroy
            ;;
        *)
            echo "Invalid option: $1"
            show_help
            exit 1
            ;;
    esac
fi

flush_important_notes
