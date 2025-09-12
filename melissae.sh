#!/bin/bash

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

print_message() {
    echo -e "\e[33m[*] $1\e[0m"
}

print_ok_message() {
    echo -e "\e[32m[*] $1\e[0m"
}

print_port_message() {
    echo -e "\e[32m\e[1mThe new SSH port is: $1\e[0m"
}

show_help() {
    print_banner
    echo "Usage: $0 [option] [modules...]"
    echo ""
    echo "Options:"
    echo "  help       Help menu"
    echo "  install    Install Melissae"
    echo "  start      Start modules"
    echo "  destroy    Destroy the Stack"
    echo ""
    echo "Modules available :"
    echo "  all        Deploy all modules"
    echo "  web        Web stack + Dashboard"
    echo "  ftp        FTP + Dashboard"
    echo "  ssh        SSH + Dashboard"
    echo "  modbus     Modbus + Dashboard"
    echo "  mqtt       Mosquitto + Dashboard"
    echo ""
    echo "Example :"
    echo "             ./melissae.sh start all"
}
install() {
    print_banner
    print_message "Updating packages"
    sudo apt-get update > /dev/null 2>&1

    print_message "Installing certificates, curl and cron"
    sudo apt-get install ca-certificates curl cron -y > /dev/null 2>&1

    print_message "Installing Docker's GPG key"
    sudo install -m 0755 -d /etc/apt/keyrings > /dev/null 2>&1
    sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc > /dev/null 2>&1
    sudo chmod a+r /etc/apt/keyrings/docker.asc > /dev/null 2>&1

    print_message "Setting up Docker repository"
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null 2>&1

    print_message "Updating packages again"
    sudo apt-get update > /dev/null 2>&1

    print_message "Installing Docker packages"
    sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-compose -y > /dev/null 2>&1

    print_message "Modifying permissions for directories and files"
    chmod -R 777 modules/web/logs
    chmod -R 777 modules/ssh/logs
    chmod -R 777 modules/ftp/logs
    chmod -R 777 modules/modbus/logs
    chmod -R 777 modules/mqtt/logs

    WORKING_DIRECTORY=$(pwd)

print_message "Adding cleaning scripts to crontabs"

CRONTAB_CONTENT=$(crontab -l 2>/dev/null || echo "")

if ! echo "$CRONTAB_CONTENT" | grep -q "$WORKING_DIRECTORY/scripts/logParser.py"; then
    (echo "$CRONTAB_CONTENT"; echo "* * * * * /usr/bin/python3 $WORKING_DIRECTORY/scripts/logParser.py") | crontab -
    print_message "Added logParser.py to crontab."
else
    print_message "logParser.py is already in crontab. Skipping."
fi

CRONTAB_CONTENT=$(crontab -l 2>/dev/null)

if ! echo "$CRONTAB_CONTENT" | grep -q "$WORKING_DIRECTORY/scripts/threatIntel.py"; then
    (echo "$CRONTAB_CONTENT"; echo "* * * * * /usr/bin/python3 $WORKING_DIRECTORY/scripts/threatIntel.py") | crontab -
    print_message "Added threatIntel.py to crontab."
else
    print_message "threatIntel.py is already in crontab. Skipping."
fi

    print_message "Generating a random port for SSH"
    RANDOM_PORT=$((RANDOM % 10000 + 20000))

    print_message "Modifying SSH configuration with the new port"
    sudo sed -i '/^Port /s/^/#/' /etc/ssh/sshd_config > /dev/null 2>&1
    echo "Port $RANDOM_PORT" | sudo tee -a /etc/ssh/sshd_config > /dev/null 2>&1

    print_port_message $RANDOM_PORT

    read -p "Do you want to restart the SSH server now? (yes/no): " answer

    if [ "$answer" == "yes" ]; then
        print_message "Restarting the SSH server"
        sudo systemctl disable --now ssh.socket > /dev/null 2>&1
        sudo systemctl restart sshd > /dev/null 2>&1
        print_message "The SSH server has been restarted."
        print_ok_message "Installation successful. You can start the stack with './melissae.sh start'."
    else
        print_message "Warning: You need to restart the SSH server to apply the changes. Use 'sudo systemctl restart sshd' to restart later."
    fi
}

start() {
    print_banner
    if [ $# -eq 0 ]; then
        print_message "No module specified."
        show_help
        return
    fi

    modules=("$@")
    services=()

    for module in "${modules[@]}"; do
        case "$module" in
            all)
                services+=("melissae_apache1" "melissae_apache2" "melissae_proxy" "melissae_dashboard" "melissae_ftp" "melissae_ssh" "melissae_modbus" "melissae_mqtt")
                ;;
            web)
                services+=("melissae_apache1" "melissae_apache2" "melissae_proxy" "melissae_dashboard")
                ;;
            ftp)
                services+=("melissae_ftp" "melissae_dashboard")
                ;;
            ssh)
                services+=("melissae_ssh" "melissae_dashboard")
                ;;
            modbus)
                services+=("melissae_modbus" "melissae_dashboard")
                ;;
            mqtt)
                services+=("melissae_mqtt" "melissae_dashboard")
                ;;
            *)
                echo "Unknown module : $module"
                show_help
                exit 1
                ;;
        esac
    done

    unique_services=($(echo "${services[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

    print_message "Strarting services : ${unique_services[*]}"
    docker-compose up --build --detach "${unique_services[@]}"
    print_ok_message "Services started successfully."
}

destroy() {
    print_banner
    print_message "Destroying containers..."
    docker-compose down > /dev/null 2>&1
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
        destroy)
            destroy
            ;;
        *)
            echo "Option invalide : $1"
            show_help
            exit 1
            ;;
    esac
fi
