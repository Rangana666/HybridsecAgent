#!/usr/bin/env bash
# ================================================================
#  HybridSec Agent v1.0.0 — One-Command Installer
#  ----------------------------------------------------------------
#  Run this single command on any fresh Linux server:
#
#    curl -sSL https://raw.githubusercontent.com/Rangana666/hybridsec-agent/main/install.sh | sudo bash
#
#  Or unattended (no prompts, for CI / automated deployments):
#
#    curl -sSL https://raw.githubusercontent.com/Rangana666/hybridsec-agent/main/install.sh | sudo bash -s -- --no-prompt
#
#  Supports: Ubuntu 20.04 / 22.04 / 24.04 · Debian 11 / 12
#            CentOS 8+ · RHEL 8+ · Amazon Linux 2
# ================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${CYAN}[INFO]${RESET}   $*"; }
success() { echo -e "${GREEN}[  OK]${RESET}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}   $*"; }
error()   { echo -e "${RED}[FAIL]${RESET}   $*"; exit 1; }
step()    { echo -e "\n${BOLD}──────────────────────────────────────${RESET}"; \
            echo -e "${BOLD} $*${RESET}"; \
            echo -e "${BOLD}──────────────────────────────────────${RESET}"; }

# ── Configuration ────────────────────────────────────────────────
REPO_URL="https://github.com/Rangana666/hybridsec-agent.git"
INSTALL_DIR="/opt/hybridsec"
SERVICE_NAME="hybridsec"
HTTP_PORT=5000
HTTPS_PORT=5443
NO_PROMPT=false
[[ "${1:-}" == "--no-prompt" ]] && NO_PROMPT=true

# ── Root check ───────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Must run as root.  Try:  sudo bash install.sh"

# ── Banner ────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}================================================================${RESET}"
echo -e "${BOLD}   HybridSec Agent  v1.0.0 — Installer${RESET}"
echo -e "${BOLD}   Linux Security Risk Analysis for Sri Lankan SMEs${RESET}"
echo -e "${BOLD}   https://github.com/Rangana666/hybridsec-agent${RESET}"
echo -e "${BOLD}================================================================${RESET}"
echo ""

# ── Confirm ───────────────────────────────────────────────────────
if [[ "$NO_PROMPT" == false ]]; then
    echo -e "  This will install HybridSec Agent to: ${BOLD}${INSTALL_DIR}${RESET}"
    read -rp "  Continue? [Y/n] " ans
    [[ "${ans,,}" == "n" ]] && { echo "Aborted."; exit 0; }
fi

# ────────────────────────────────────────────────────────────────
# STEP 1 — Detect OS and install system packages
# ────────────────────────────────────────────────────────────────
step "Step 1/7 — Installing system dependencies"

if command -v apt-get &>/dev/null; then
    info "Detected Debian/Ubuntu — using apt"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq \
        python3 python3-pip python3-venv python3-dev \
        git curl wget \
        nmap \
        ufw \
        openssl \
        build-essential libssl-dev libffi-dev \
        2>/dev/null
    # Lynis (not always in default repos)
    if ! command -v lynis &>/dev/null; then
        apt-get install -y -qq lynis 2>/dev/null || \
        (wget -qO /tmp/lynis.tar.gz \
            "https://downloads.cisofy.com/lynis/lynis-3.1.1.tar.gz" && \
         tar -xzf /tmp/lynis.tar.gz -C /usr/local/share/ && \
         ln -sf /usr/local/share/lynis/lynis /usr/local/bin/lynis && \
         rm /tmp/lynis.tar.gz) || warn "Lynis install failed — scanning will use fallback mode."
    fi

elif command -v yum &>/dev/null || command -v dnf &>/dev/null; then
    PKG=$(command -v dnf &>/dev/null && echo dnf || echo yum)
    info "Detected RHEL/CentOS — using $PKG"
    $PKG install -y -q \
        python3 python3-pip python3-devel \
        git curl wget \
        nmap \
        openssl \
        gcc libffi-devel openssl-devel \
        2>/dev/null
    # UFW not available on RHEL — use firewalld
    if ! command -v ufw &>/dev/null; then
        warn "UFW not available — IP blocking will use iptables directly."
    fi

else
    warn "Unknown package manager — skipping system package install."
    warn "Ensure python3, git, nmap, openssl are installed manually."
fi

success "System dependencies ready."

# ────────────────────────────────────────────────────────────────
# STEP 2 — Clone / update the repository
# ────────────────────────────────────────────────────────────────
step "Step 2/7 — Downloading HybridSec Agent from GitHub"

if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Repository already exists — pulling latest version..."
    git -C "$INSTALL_DIR" pull --quiet
    success "Repository updated."
elif [[ -d "$INSTALL_DIR" && -f "$INSTALL_DIR/run.py" ]]; then
    info "Files already in $INSTALL_DIR — using existing copy."
else
    info "Cloning from $REPO_URL ..."
    git clone --quiet --depth 1 "$REPO_URL" "$INSTALL_DIR"
    success "Repository cloned to $INSTALL_DIR"
fi

# ────────────────────────────────────────────────────────────────
# STEP 3 — Python virtual environment + dependencies
# ────────────────────────────────────────────────────────────────
step "Step 3/7 — Setting up Python environment"

info "Creating virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"
success "Virtual environment created."

info "Upgrading pip and installing wheels..."
pip install --quiet --upgrade pip setuptools wheel

info "Installing Python packages (using pre-built wheels — much faster)..."
# --prefer-binary skips source compilation; --no-cache-dir ensures fresh install
pip install \
    --prefer-binary \
    --no-cache-dir \
    --progress-bar on \
    -r "$INSTALL_DIR/requirements.txt"
success "Python packages installed."

# ────────────────────────────────────────────────────────────────
# STEP 4 — Create directories and set permissions
# ────────────────────────────────────────────────────────────────
step "Step 4/7 — Creating runtime directories"

mkdir -p "$INSTALL_DIR"/{logs,database,ssl,"data/reports","data/backups","data/rules","data/training"}
chmod 700 "$INSTALL_DIR/database"
chmod 700 "$INSTALL_DIR/ssl"
chmod 750 "$INSTALL_DIR/logs"
success "Directories created."

# ────────────────────────────────────────────────────────────────
# STEP 5 — Environment file + database initialisation
# ────────────────────────────────────────────────────────────────
step "Step 5/7 — Configuring environment"

if [[ ! -f "$INSTALL_DIR/.env" ]]; then
    info "Creating .env from template..."
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    SECRET=$("$INSTALL_DIR/venv/bin/python3" -c \
        "import secrets; print(secrets.token_hex(32))")
    sed -i "s|CHANGE-THIS-TO-A-RANDOM-32-CHAR-STRING|${SECRET}|g" "$INSTALL_DIR/.env"
    chmod 600 "$INSTALL_DIR/.env"
    success ".env created with a unique SECRET_KEY."
    warn "→ Edit $INSTALL_DIR/.env to add your OpenAI / Telegram / Email credentials."
else
    info ".env already exists — skipping (existing config preserved)."
fi

info "Initialising database..."
cd "$INSTALL_DIR"
"$INSTALL_DIR/venv/bin/python3" - << 'PYEOF'
import sys
sys.path.insert(0, ".")
from modules.module5_web.auth import init_db
init_db()
PYEOF
success "Database initialised  (default login: admin / Admin@HybridSec2025!)"

# ────────────────────────────────────────────────────────────────
# STEP 6 — Self-signed SSL certificate
# ────────────────────────────────────────────────────────────────
step "Step 6/7 — Generating SSL certificate"

if [[ ! -f "$INSTALL_DIR/ssl/hybridsec.crt" ]]; then
    if command -v openssl &>/dev/null; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
        openssl req -x509 -newkey rsa:4096 -nodes \
            -keyout "$INSTALL_DIR/ssl/hybridsec.key" \
            -out    "$INSTALL_DIR/ssl/hybridsec.crt" \
            -days 3650 \
            -subj "/C=LK/ST=Western/L=Colombo/O=HybridSec/CN=${SERVER_IP}" \
            -addext "subjectAltName=IP:${SERVER_IP},DNS:localhost" \
            2>/dev/null
        chmod 600 "$INSTALL_DIR/ssl/hybridsec.key"
        success "SSL certificate generated (CN=${SERVER_IP}, valid 10 years)."
    else
        warn "openssl not found — HTTPS will be unavailable. Run without --https."
    fi
else
    info "SSL certificate already exists — skipping."
fi

# ────────────────────────────────────────────────────────────────
# STEP 7 — Systemd service + firewall
# ────────────────────────────────────────────────────────────────
step "Step 7/7 — Installing systemd service"

cat > /etc/systemd/system/${SERVICE_NAME}.service << SERVICE_EOF
[Unit]
Description=HybridSec Agent — Linux Security Platform v1.0.0
Documentation=https://github.com/Rangana666/hybridsec-agent
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/run.py --https
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
TimeoutStopSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hybridsec
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICE_EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" --quiet
success "Systemd service installed and enabled."

# Firewall rules
if command -v ufw &>/dev/null; then
    info "Configuring UFW firewall rules..."
    ufw allow ${HTTP_PORT}/tcp  comment "HybridSec HTTP"  >/dev/null 2>&1 || true
    ufw allow ${HTTPS_PORT}/tcp comment "HybridSec HTTPS" >/dev/null 2>&1 || true
    success "Firewall rules added (ports ${HTTP_PORT} + ${HTTPS_PORT})."
elif command -v firewall-cmd &>/dev/null; then
    info "Configuring firewalld rules..."
    firewall-cmd --permanent --add-port=${HTTP_PORT}/tcp  >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=${HTTPS_PORT}/tcp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    success "Firewalld rules added."
fi

# ── Final summary ─────────────────────────────────────────────────
SERVER_IP=$(hostname -I | awk '{print $1}')
echo ""
echo -e "${BOLD}================================================================${RESET}"
echo -e "${GREEN}${BOLD}   HybridSec Agent — Installation Complete!${RESET}"
echo -e "${BOLD}================================================================${RESET}"
echo ""
echo -e "  ${BOLD}Dashboard URL:${RESET}  https://${SERVER_IP}:${HTTPS_PORT}/"
echo -e "  ${BOLD}HTTP fallback:${RESET}  http://${SERVER_IP}:${HTTP_PORT}/"
echo -e "  ${BOLD}Login:${RESET}          admin / Admin@HybridSec2025!"
echo -e "  ${BOLD}Config file:${RESET}    ${INSTALL_DIR}/.env"
echo -e "  ${BOLD}Logs:${RESET}           journalctl -u hybridsec -f"
echo -e "  ${BOLD}Service:${RESET}        systemctl {start|stop|restart|status} hybridsec"
echo ""
echo -e "  ${YELLOW}${BOLD}SECURITY — Do these steps now:${RESET}"
echo -e "  ${YELLOW}  1. Change the admin password on first login${RESET}"
echo -e "  ${YELLOW}  2. Add your OpenAI API key to ${INSTALL_DIR}/.env${RESET}"
echo -e "  ${YELLOW}  3. Add Telegram bot token for real-time alerts${RESET}"
echo ""

if [[ "$NO_PROMPT" == false ]]; then
    read -rp "  Start HybridSec now? [Y/n] " start_ans
    [[ "${start_ans,,}" == "n" ]] && { echo "  Run later:  systemctl start hybridsec"; echo ""; exit 0; }
fi

systemctl start "$SERVICE_NAME"
sleep 3

if systemctl is-active --quiet "$SERVICE_NAME"; then
    success "HybridSec is running!"
    echo -e "\n  Open your browser:  ${BOLD}https://${SERVER_IP}:${HTTPS_PORT}/${RESET}"
    echo -e "  (Accept the self-signed certificate warning in your browser)\n"
else
    warn "Service did not start cleanly."
    echo "  Check logs:  journalctl -u hybridsec -n 50 --no-pager"
fi
