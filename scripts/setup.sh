#!/usr/bin/env bash
set -euo pipefail

REPO_Owner="sahand363"
REPO_NAME="Sahand-matrix"
INSTALL_DIR="/usr/local/bin"
CONF_DIR="/etc/sahand"
CONF_FILE="${CONF_DIR}/config.env"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
AMBER='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

mkdir -p "$CONF_DIR"
chmod 700 "$CONF_DIR"

# Load or initialize persistent configuration (Secret link never changes unless regenerated in menu)
if [[ -f "$CONF_FILE" ]]; then
  source "$CONF_FILE"
fi

NODE_ROLE="${NODE_ROLE:-main}"
HUB_PORT="${HUB_PORT:-8443}"
AGENT_PORT="${AGENT_PORT:-9444}"
SECRET_PATH="${SECRET_PATH:-$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 14)}"
SHARED_TOKEN="${SHARED_TOKEN:-$(head -c 18 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 22)}"
AUTH_USER="${AUTH_USER:-}"
AUTH_PASS="${AUTH_PASS:-}"
PEER_IP="${PEER_IP:-}"

save_config() {
  cat > "$CONF_FILE" <<EOF
NODE_ROLE="${NODE_ROLE}"
HUB_PORT="${HUB_PORT}"
AGENT_PORT="${AGENT_PORT}"
SECRET_PATH="${SECRET_PATH}"
SHARED_TOKEN="${SHARED_TOKEN}"
AUTH_USER="${AUTH_USER}"
AUTH_PASS="${AUTH_PASS}"
PEER_IP="${PEER_IP}"
EOF
  chmod 600 "$CONF_FILE"
}

get_public_ip() {
  curl -s4 --max-time 4 https://api.ipify.org || hostname -I | awk '{print $1}'
}

write_systemd_units() {
  save_config
  if [[ "$NODE_ROLE" == "main" ]]; then
    cat > /etc/systemd/system/sahand-hub.service <<EOF
[Unit]
Description=Sahand Matrix Hub (Main Server 6-Window Lab)
After=network.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/sahand-hub -daemon -port ${HUB_PORT} -secret ${SECRET_PATH} -token ${SHARED_TOKEN} -auth-user "${AUTH_USER}" -auth-pass "${AUTH_PASS}"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sahand-hub >/dev/null 2>&1 || true
    systemctl restart sahand-hub
  else
    cat > /etc/systemd/system/sahand-agent.service <<EOF
[Unit]
Description=Sahand Matrix Sentinel (Server 2/3 3-Window Node)
After=network.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/sahand-agent -role kharej -id server-2 -listen :${AGENT_PORT} -peer "${PEER_IP}" -token "${SHARED_TOKEN}" -secret "${SECRET_PATH}" -auth-user "${AUTH_USER}" -auth-pass "${AUTH_PASS}"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sahand-agent >/dev/null 2>&1 || true
    systemctl restart sahand-agent
  fi
}

print_access_urls() {
  local ip
  ip=$(get_public_ip)
  echo -e "\n${CYAN}=================================================================${NC}"
  if [[ "$NODE_ROLE" == "main" ]]; then
    echo -e "${GREEN}✔ MAIN SERVER (6-WINDOW MATRIX) ACTIVE:${NC}"
    echo -e "  🔗 HTTP URL  : ${AMBER}http://${ip}:${HUB_PORT}/matrix/${SECRET_PATH}/${NC}"
    echo -e "  🔒 HTTPS URL : ${AMBER}https://${ip}:${HUB_PORT}/matrix/${SECRET_PATH}/${NC}"
  else
    echo -e "${GREEN}✔ SERVER 2 / 3 SENTINEL (3-WINDOW VIEW) ACTIVE:${NC}"
    echo -e "  🔗 Secret URL: ${AMBER}http://${ip}:${AGENT_PORT}/sentinel/${SECRET_PATH}/${NC}"
    echo -e "  📡 Hub API   : ${CYAN}http://${ip}:${AGENT_PORT}/api/snapshot${NC}"
  fi
  if [[ -n "$AUTH_USER" ]]; then
    echo -e "  🔐 Auth      : ${GREEN}Enabled (Username: ${AUTH_USER})${NC}"
  else
    echo -e "  🔓 Auth      : ${CYAN}Passwordless (Protected by Persistent Random Secret Link)${NC}"
  fi
  echo -e "${CYAN}=================================================================${NC}\n"
}

download_or_build_binaries() {
  echo -e "${CYAN}[*] Fetching latest Sahand Matrix source & building binaries...${NC}"
  local tmp_dir="/tmp/sahand-build-$$"
  rm -rf "$tmp_dir"
  git clone --depth 1 "https://github.com/${REPO_Owner}/${REPO_NAME}.git" "$tmp_dir"

  if ! command -v go >/dev/null 2>&1; then
    echo -e "${AMBER}[*] Installing Go compiler...${NC}"
    curl -fsSL https://go.dev/dl/go1.23.2.linux-amd64.tar.gz -o /tmp/go.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    ln -sf /usr/local/go/bin/go /usr/bin/go
  fi

  cd "$tmp_dir"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "${INSTALL_DIR}/sahand-hub" ./cmd/sahand-hub
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "${INSTALL_DIR}/sahand-agent" ./cmd/sahand-agent
  cp -f "$tmp_dir/scripts/install.sh" "${INSTALL_DIR}/sahand-menu"
  chmod +x "${INSTALL_DIR}/sahand-hub" "${INSTALL_DIR}/sahand-agent" "${INSTALL_DIR}/sahand-menu"
  rm -rf "$tmp_dir"
}

install_menu() {
  while true; do
    echo -e "\n${CYAN}❖ SAHAND MATRIX // MANAGEMENT MENU (${NODE_ROLE^^} SERVER)${NC}"
    echo "  1) Install / Switch to Main Server (6-Window Hub)"
    echo "  2) Install / Switch to Server 2 / Server 3 (3-Window Sentinel)"
    echo "  3) Show My Secret Web Panel Link & Auth Status"
    echo "  4) Launch Terminal TUI Analyzer"
    echo "  5) Update Sahand Matrix from GitHub (Preserves Secret Link)"
    echo "  6) 🔄 Generate New Random Secret Link (Main Server or Sentinel)"
    echo "  7) 🔐 Set or Clear Web Panel Username & Password"
    echo "  8) Uninstall Sahand Matrix"
    echo "  0) Exit"
    read -rp "Select option [0-8]: " opt
    case "$opt" in
      1)
        NODE_ROLE="main"
        download_or_build_binaries
        write_systemd_units
        print_access_urls
        ;;
      2)
        NODE_ROLE="sentinel"
        read -rp "Enter Main Server IP (optional, for CP4 classification): " PEER_IP
        download_or_build_binaries
        write_systemd_units
        print_access_urls
        ;;
      3)
        print_access_urls
        ;;
      4)
        "${INSTALL_DIR}/sahand-hub"
        ;;
      5)
        download_or_build_binaries
        write_systemd_units
        echo -e "${GREEN}✔ Updated! Your existing secret link and settings were preserved.${NC}"
        print_access_urls
        ;;
      6)
        SECRET_PATH=$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 14)
        write_systemd_units
        echo -e "${GREEN}✔ Generated new random secret link!${NC}"
        print_access_urls
        ;;
      7)
        read -rp "Enter new Username (leave blank to disable password protection): " new_u
        if [[ -z "$new_u" ]]; then
          AUTH_USER=""
          AUTH_PASS=""
          echo -e "${AMBER}[*] Password protection disabled (using secret link only).${NC}"
        else
          read -rsp "Enter new Password: " new_p
          echo ""
          AUTH_USER="$new_u"
          AUTH_PASS="$new_p"
          echo -e "${GREEN}✔ Username & Password enabled!${NC}"
        fi
        write_systemd_units
        print_access_urls
        ;;
      8)
        systemctl stop sahand-hub sahand-agent >/dev/null 2>&1 || true
        systemctl disable sahand-hub sahand-agent >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/sahand-hub.service /etc/systemd/system/sahand-agent.service
        rm -f "${INSTALL_DIR}/sahand-hub" "${INSTALL_DIR}/sahand-agent" "${INSTALL_DIR}/sahand-menu"
        echo -e "${RED}✔ Sahand Matrix uninstalled.${NC}"
        exit 0
        ;;
      0) exit 0 ;;
    esac
  done
}

if [[ "${1:-}" == "--auto-main" ]]; then
  NODE_ROLE="main"
  download_or_build_binaries
  write_systemd_units
  print_access_urls
  exit 0
fi

install_menu
