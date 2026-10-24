#!/usr/bin/env bash
set -e

export PATH=$PATH:/usr/local/go/bin

REPO_OWNER="${SAHAND_REPO_OWNER:-sahand363}"
REPO_NAME="${SAHAND_REPO_NAME:-sahand-matrix}"
INSTALL_DIR="/opt/sahand-matrix"
CONFIG_FILE="${INSTALL_DIR}/config.env"
HUB_SERVICE="/etc/systemd/system/sahand-hub.service"
AGENT_SERVICE="/etc/systemd/system/sahand-agent.service"

CYAN='\033[1;36m'; PURPLE='\033[1;35m'; EMERALD='\033[1;32m'
AMBER='\033[1;33m'; CRIMSON='\033[1;31m'; MUTED='\033[0;90m'; RESET='\033[0m'

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${CRIMSON}[!] Run as root (sudo).${RESET}"; exit 1
    fi
}

get_public_ip() {
    curl -s4 --max-time 4 https://icanhazip.com || hostname -I | awk '{print $1}'
}

install_dependencies() {
    echo -e "${CYAN}[*] Installing system packages...${RESET}"
    apt-get update -y -qq
    apt-get install -y -qq curl wget git tar ca-certificates openssl iputils-ping > /dev/null

    if ! command -v go &> /dev/null; then
        echo -e "${CYAN}[*] Installing Go 1.23 toolchain...${RESET}"
        wget -q https://go.dev/dl/go1.23.2.linux-amd64.tar.gz -O /tmp/go.tar.gz
        rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
        ln -sf /usr/local/go/bin/go /usr/bin/go
        ln -sf /usr/local/go/bin/go /usr/local/bin/go
        rm -f /tmp/go.tar.gz
    fi
}

generate_secret_config() {
    mkdir -p "${INSTALL_DIR}"
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        SECRET_PATH=$(openssl rand -hex 8)
        AGENT_TOKEN=$(openssl rand -hex 16)
        PUBLIC_IP=$(get_public_ip)
        cat <<EOF > "${CONFIG_FILE}"
PANEL_PORT=8443
SECRET_PATH=${SECRET_PATH}
AGENT_TOKEN=${AGENT_TOKEN}
HUB_IP=${PUBLIC_IP}
EOF
        chmod 600 "${CONFIG_FILE}"
    fi
    source "${CONFIG_FILE}"
}

build_or_fetch_binaries() {
    install_dependencies
    mkdir -p "${INSTALL_DIR}/bin"
    echo -e "${CYAN}[*] Fetching latest Sahand Traffic Matrix source from GitHub...${RESET}"
    rm -rf "${INSTALL_DIR}/src"
    GIT_TERMINAL_PROMPT=0 git clone --depth 1 "https://github.com/${REPO_OWNER}/${REPO_NAME}.git" "${INSTALL_DIR}/src"
    cd "${INSTALL_DIR}/src"
    echo -e "${CYAN}[*] Compiling sahand-hub & sahand-agent binaries...${RESET}"
    /usr/local/go/bin/go mod tidy
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build -ldflags="-s -w" -o "${INSTALL_DIR}/bin/sahand-hub" ./cmd/sahand-hub
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build -ldflags="-s -w" -o "${INSTALL_DIR}/bin/sahand-agent" ./cmd/sahand-agent
    chmod +x "${INSTALL_DIR}/bin/sahand-hub" "${INSTALL_DIR}/bin/sahand-agent"

    # Install permanent 'sahand-menu' and 'sahand-matrix' commands
    cp "${INSTALL_DIR}/src/scripts/setup.sh" "${INSTALL_DIR}/setup.sh"
    chmod +x "${INSTALL_DIR}/setup.sh"
    ln -sf "${INSTALL_DIR}/setup.sh" /usr/local/bin/sahand-menu
    ln -sf "${INSTALL_DIR}/bin/sahand-hub" /usr/local/bin/sahand-matrix
}

install_hub_service() {
    require_root
    generate_secret_config
    build_or_fetch_binaries

    cat <<EOF > "${HUB_SERVICE}"
[Unit]
Description=Sahand Traffic Matrix Hub & Real Packet Sniffer
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${CONFIG_FILE}
ExecStart=${INSTALL_DIR}/bin/sahand-hub --daemon --port \${PANEL_PORT} --secret \${SECRET_PATH} --token \${AGENT_TOKEN}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable sahand-hub --now
    echo -e "${EMERALD}[✓] Installed! Type 'sahand-menu' anytime in SSH to open this menu.${RESET}"
    show_access_details
}

deploy_agent_only() {
    require_root
    build_or_fetch_binaries
    read -rp "Enter Peer/Hub IP Address: " PEER_IP
    read -rp "Enter Agent Auth Token: " TARGET_TOKEN
    read -rp "Select Server Role [1 = Iran S1 (CP1-CP3), 2 = Kharej S2 (CP4-CP6)]: " ROLE_NUM
    ROLE_FLAG="kharej"
    [[ "$ROLE_NUM" == "1" ]] && ROLE_FLAG="iran"

    cat <<EOF > "${AGENT_SERVICE}"
[Unit]
Description=Sahand Real Packet Sniffer Agent
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/bin/sahand-agent --role ${ROLE_FLAG} --peer ${PEER_IP} --token ${TARGET_TOKEN} --listen :9444
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable sahand-agent --now
    PUBLIC_IP=$(get_public_ip)
    echo -e "${EMERALD}[✓] Agent active! Local 3-Window View: http://${PUBLIC_IP}:9444/${RESET}"
}

update_matrix() {
    require_root
    build_or_fetch_binaries
    systemctl restart sahand-hub 2>/dev/null || true
    systemctl restart sahand-agent 2>/dev/null || true
    echo -e "${EMERALD}[✓] Updated & restarted! (Shortcut 'sahand-menu' is active).${RESET}"
}

uninstall_matrix() {
    require_root
    systemctl stop sahand-hub sahand-agent 2>/dev/null || true
    systemctl disable sahand-hub sahand-agent 2>/dev/null || true
    rm -f "${HUB_SERVICE}" "${AGENT_SERVICE}" /usr/local/bin/sahand-matrix /usr/local/bin/sahand-menu
    systemctl daemon-reload
    rm -rf "${INSTALL_DIR}"
    echo -e "${EMERALD}[✓] Uninstalled.${RESET}"
}

show_access_details() {
    if [[ -f "${CONFIG_FILE}" ]]; then
        source "${CONFIG_FILE}"
        echo -e "\n${PURPLE}=====================================================================${RESET}"
        echo -e " ${EMERALD}● Web Panel URL (HTTP/HTTPS) :${RESET} http://${HUB_IP}:${PANEL_PORT}/matrix/${SECRET_PATH}/"
        echo -e " ${CYAN}● Open Menu Shortcut in SSH  :${RESET} sahand-menu"
        echo -e " ${CYAN}● Open Terminal UI in SSH    :${RESET} sahand-matrix"
        echo -e " ${AMBER}● Agent Auth Token           :${RESET} ${AGENT_TOKEN}"
        echo -e "${PURPLE}=====================================================================${RESET}\n"
    fi
}

while true; do
    clear
    echo -e "${PURPLE}╔═══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${PURPLE}║${RESET}   ${CYAN}🕸  SAHAND TRAFFIC MATRIX${RESET} ${MUTED}// REAL PACKET & IRAN DPI LAB${RESET}          ${PURPLE}║${RESET}"
    echo -e "${PURPLE}╠═══════════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${PURPLE}║${RESET}  ${EMERALD}1)${RESET} Install / Reconfigure Central Hub & Panel (Primary Server)    ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}  ${CYAN}2)${RESET} Deploy Lightweight sahand-agent Only (2nd / Kharej Server)    ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}  ${CYAN}3)${RESET} Launch Live 6-Checkpoint Terminal UI (sahand-matrix)          ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}  ${AMBER}4)${RESET} Show Secure Panel Link & Agent Token                          ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}  ${AMBER}5)${RESET} Update Sahand Matrix (Pull Latest from GitHub)                ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}  ${CRIMSON}6)${RESET} Uninstall Sahand Matrix & Clean Up                            ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}  ${MUTED}0)${RESET} Exit                                                          ${PURPLE}║${RESET}"
    echo -e "${PURPLE}╚═══════════════════════════════════════════════════════════════════╝${RESET}"
    read -rp "Select an option [0-6]: " choice
    case "$choice" in
        1) install_hub_service ;;
        2) deploy_agent_only ;;
        3) /usr/local/bin/sahand-matrix ;;
        4) show_access_details ;;
        5) update_matrix ;;
        6) uninstall_matrix ;;
        0) exit 0 ;;
    esac
    read -rp "Press [ENTER] to return to menu..."
done
