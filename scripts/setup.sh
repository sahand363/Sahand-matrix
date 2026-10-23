#!/usr/bin/env bash
set -e

# ==============================================================================
# SAHAND TRAFFIC MATRIX - Automated Ubuntu Installer & Node Manager
# ==============================================================================

REPO_OWNER="${SAHAND_REPO_OWNER:-sahand363}"
REPO_NAME="${SAHAND_REPO_NAME:-sahand-matrix}"
INSTALL_DIR="/opt/sahand-matrix"
CONFIG_FILE="${INSTALL_DIR}/config.env"
HUB_SERVICE="/etc/systemd/system/sahand-hub.service"
AGENT_SERVICE="/etc/systemd/system/sahand-agent.service"

# ANSI Colors (Matching Netview Pro Dark/Cyan/Purple Palette)
CYAN='\033[1;36m'
PURPLE='\033[1;35m'
EMERALD='\033[1;32m'
AMBER='\033[1;33m'
CRIMSON='\033[1;31m'
MUTED='\033[0;90m'
RESET='\033[0m'

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${CRIMSON}[!] Error: This script must be run as root (sudo).${RESET}"
        exit 1
    fi
}

get_public_ip() {
    curl -s4 --max-time 4 https://icanhazip.com || hostname -I | awk '{print $1}'
}

install_dependencies() {
    echo -e "${CYAN}[*] Installing system packages and packet capture libraries...${RESET}"
    apt-get update -y -qq
    apt-get install -y -qq curl wget git tar libpcap-dev ca-certificates openssl iputils-ping > /dev/null

    if ! command -v go &> /dev/null; then
        echo -e "${CYAN}[*] Installing Go 1.23 toolchain...${RESET}"
        wget -q https://go.dev/dl/go1.23.2.linux-amd64.tar.gz -O /tmp/go.tar.gz
        rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
        ln -sf /usr/local/go/bin/go /usr/bin/go
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
GRPC_PORT=9443
SECRET_PATH=${SECRET_PATH}
AGENT_TOKEN=${AGENT_TOKEN}
HUB_IP=${PUBLIC_IP}
EOF
        chmod 600 "${CONFIG_FILE}"
    fi
    source "${CONFIG_FILE}"
}

build_or_fetch_binaries() {
    mkdir -p "${INSTALL_DIR}/bin"
    echo -e "${CYAN}[*] Fetching latest Sahand Traffic Matrix source from GitHub...${RESET}"
    rm -rf "${INSTALL_DIR}/src"
    if git clone --depth 1 "https://github.com/${REPO_OWNER}/${REPO_NAME}.git" "${INSTALL_DIR}/src" 2>/dev/null; then
        cd "${INSTALL_DIR}/src"
        echo -e "${CYAN}[*] Compiling sahand-hub & sahand-agent binaries...${RESET}"
        go mod tidy
        CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "${INSTALL_DIR}/bin/sahand-hub" ./cmd/sahand-hub
        CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "${INSTALL_DIR}/bin/sahand-agent" ./cmd/sahand-agent
        chmod +x "${INSTALL_DIR}/bin/sahand-hub" "${INSTALL_DIR}/bin/sahand-agent"
    else
        echo -e "${AMBER}[!] Could not clone https://github.com/${REPO_OWNER}/${REPO_NAME}. Check REPO_OWNER in setup.sh.${RESET}"
        exit 1
    fi
}

install_hub_service() {
    require_root
    install_dependencies
    generate_secret_config
    build_or_fetch_binaries

    cat <<EOF > "${HUB_SERVICE}"
[Unit]
Description=Sahand Traffic Matrix Hub & Web/Telemetry Server
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

    ln -sf "${INSTALL_DIR}/bin/sahand-hub" /usr/local/bin/sahand-matrix
    systemctl daemon-reload
    systemctl enable sahand-hub --now
    echo -e "${EMERALD}[✓] Sahand Hub & Local Agent installed and running!${RESET}"
    show_access_details
}

deploy_agent_only() {
    require_root
    install_dependencies
    build_or_fetch_binaries

    echo -e ""
    read -rp "Enter Central Hub IP Address: " TARGET_HUB_IP
    read -rp "Enter Central Hub Port [default: 8443]: " TARGET_HUB_PORT
    TARGET_HUB_PORT=${TARGET_HUB_PORT:-8443}
    read -rp "Enter Agent Auth Token (from Hub panel): " TARGET_TOKEN
    read -rp "Select Server Role [1 = Remote Edge (CP1-CP3), 2 = Iran Node (CP4-CP6)]: " NODE_ROLE

    ROLE_FLAG="remote"
    if [[ "$NODE_ROLE" == "2" ]]; then
        ROLE_FLAG="iran"
    fi

    cat <<EOF > "${AGENT_SERVICE}"
[Unit]
Description=Sahand Lightweight Packet & Ping Telemetry Agent
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/bin/sahand-agent --hub "${TARGET_HUB_IP}:${TARGET_HUB_PORT}" --token "${TARGET_TOKEN}" --role "${ROLE_FLAG}"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable sahand-agent --now
    echo -e "${EMERALD}[✓] sahand-agent (${ROLE_FLAG}) deployed and connected to ${TARGET_HUB_IP}:${TARGET_HUB_PORT}!${RESET}"
}

update_matrix() {
    require_root
    echo -e "${CYAN}[*] Updating Sahand Traffic Matrix binaries...${RESET}"
    build_or_fetch_binaries
    systemctl restart sahand-hub 2>/dev/null || true
    systemctl restart sahand-agent 2>/dev/null || true
    echo -e "${EMERALD}[✓] Update complete and services restarted.${RESET}"
}

uninstall_matrix() {
    require_root
    read -rp "Are you sure you want to completely remove Sahand Traffic Matrix? [y/N]: " CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        systemctl stop sahand-hub 2>/dev/null || true
        systemctl disable sahand-hub 2>/dev/null || true
        systemctl stop sahand-agent 2>/dev/null || true
        systemctl disable sahand-agent 2>/dev/null || true
        rm -f "${HUB_SERVICE}" "${AGENT_SERVICE}" /usr/local/bin/sahand-matrix
        systemctl daemon-reload
        rm -rf "${INSTALL_DIR}"
        echo -e "${EMERALD}[✓] Sahand Traffic Matrix completely uninstalled.${RESET}"
    fi
}

show_access_details() {
    if [[ -f "${CONFIG_FILE}" ]]; then
        source "${CONFIG_FILE}"
        echo -e ""
        echo -e "${PURPLE}=====================================================================${RESET}"
        echo -e " ${CYAN}🕸  SAHAND TRAFFIC MATRIX - ACCESS & AGENT CREDENTIALS${RESET}"
        echo -e "${PURPLE}=====================================================================${RESET}"
        echo -e " ${EMERALD}● Secure Web Panel URL :${RESET} https://${HUB_IP}:${PANEL_PORT}/matrix/${SECRET_PATH}/"
        echo -e " ${EMERALD}● Interactive TUI Cmd  :${RESET} sahand-matrix"
        echo -e " ${CYAN}● Agent Auth Token     :${RESET} ${AGENT_TOKEN}"
        echo -e " ${AMBER}● Remote Agent One-Liner (Run on 2nd Server):${RESET}"
        echo -e "   ${MUTED}sahand-agent --hub ${HUB_IP}:${PANEL_PORT} --token ${AGENT_TOKEN} --role iran${RESET}"
        echo -e "${PURPLE}=====================================================================${RESET}"
        echo -e ""
    else
        echo -e "${AMBER}[!] Hub is not installed yet. Select Option 1 first.${RESET}"
    fi
}

show_menu() {
    clear
    echo -e "${PURPLE}╔═══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${PURPLE}║${RESET}   ${CYAN}🕸  SAHAND TRAFFIC MATRIX${RESET} ${MUTED}// MULTI-CHECKPOINT DPI ANALYZER${RESET}       ${PURPLE}║${RESET}"
    echo -e "${PURPLE}╠═══════════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${PURPLE}║${RESET}  ${EMERALD}1)${RESET} Install / Reconfigure Central Hub & Panel (Primary Server)    ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}  ${CYAN}2)${RESET} Deploy Lightweight sahand-agent Only (2nd / Remote Server)    ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}  ${CYAN}3)${RESET} Launch Live 6-Checkpoint Terminal UI (TUI Dashboard)          ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}  ${AMBER}4)${RESET} Show Secure Panel Link & Agent Token                          ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}  ${AMBER}5)${RESET} Update Sahand Matrix (Pull Latest from GitHub)                ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}  ${CRIMSON}6)${RESET} Uninstall Sahand Matrix & Clean Up                            ${PURPLE}║${RESET}"
    echo -e "${PURPLE}║${RESET}  ${MUTED}0)${RESET} Exit                                                          ${PURPLE}║${RESET}"
    echo -e "${PURPLE}╚═══════════════════════════════════════════════════════════════════╝${RESET}"
    echo -e ""
    read -rp "Select an option [0-6]: " choice

    case "$choice" in
        1) install_hub_service ;;
        2) deploy_agent_only ;;
        3) /usr/local/bin/sahand-matrix ;;
        4) show_access_details ;;
        5) update_matrix ;;
        6) uninstall_matrix ;;
        0) exit 0 ;;
        *) echo -e "${CRIMSON}Invalid option.${RESET}" ;;
    esac
}

while true; do
    show_menu
    read -rp "Press [ENTER] to return to menu..."
done
