#!/usr/bin/env bash
# ================================================================
#  HybridSec Agent — VPS Deploy Script
#  ----------------------------------------------------------------
#  This script runs ON THE VPS to pull + apply updates.
#  It is called automatically by GitHub Actions (deploy.yml).
#  You can also run it manually on the VPS:
#
#    sudo bash /opt/hybridsec/deploy/deploy_vps.sh
#
# ================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${CYAN}[INFO]${RESET}   $*"; }
success() { echo -e "${GREEN}[  OK]${RESET}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}   $*"; }
error()   { echo -e "${RED}[FAIL]${RESET}   $*"; exit 1; }

# ── Config ───────────────────────────────────────────────────────
INSTALL_DIR="/opt/hybridsec"
SERVICE_NAME="hybridsec"
BRANCH="main"

[[ $EUID -ne 0 ]] && error "Must run as root. Try: sudo bash deploy/deploy_vps.sh"
[[ ! -d "$INSTALL_DIR/.git" ]] && error "$INSTALL_DIR is not a git repo. Run install.sh first."

echo ""
echo -e "${BOLD}======================================================${RESET}"
echo -e "${BOLD}   HybridSec Agent — Manual VPS Deploy${RESET}"
echo -e "${BOLD}   Time: $(date)${RESET}"
echo -e "${BOLD}======================================================${RESET}"
echo ""

# ── Step 1: Pull latest code ──────────────────────────────────────
info "Pulling latest code from GitHub (branch: $BRANCH)..."
cd "$INSTALL_DIR"
git fetch --all --quiet
git reset --hard "origin/$BRANCH" --quiet
success "Code updated to latest commit: $(git log --oneline -1)"

# ── Step 2: Update Python packages ───────────────────────────────
info "Updating Python packages..."
"$INSTALL_DIR/venv/bin/pip" install \
    --quiet \
    --prefer-binary \
    --upgrade \
    -r "$INSTALL_DIR/requirements.txt"
success "Python packages updated."

# ── Step 3: Retrain ML model if needed ───────────────────────────
PREV_HASH=$(git stash list | head -1 | cut -d' ' -f1 2>/dev/null || echo "")
CHANGED=$(git diff HEAD@{1} HEAD --name-only 2>/dev/null || echo "")

if echo "$CHANGED" | grep -q "train_model.py\|requirements.txt"; then
    info "ML training script changed — retraining model..."
    cd "$INSTALL_DIR"
    "$INSTALL_DIR/venv/bin/python3" -m modules.module3_scoring.models.train_model
    success "ML model retrained."
else
    info "No ML changes — skipping model retrain."
fi

# ── Step 4: Restart service ───────────────────────────────────────
info "Restarting HybridSec service..."
systemctl daemon-reload
systemctl restart "$SERVICE_NAME"
sleep 4

# ── Step 5: Health check ──────────────────────────────────────────
if systemctl is-active --quiet "$SERVICE_NAME"; then
    success "HybridSec is running!"
    SERVER_IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo -e "${BOLD}======================================================${RESET}"
    echo -e "${GREEN}${BOLD}   ✅ DEPLOYMENT SUCCESSFUL${RESET}"
    echo -e "${BOLD}======================================================${RESET}"
    echo -e "  Dashboard:  ${BOLD}https://${SERVER_IP}:5443${RESET}"
    echo -e "  Logs:       journalctl -u hybridsec -f"
    echo ""
else
    error "Service failed to start! Check logs: journalctl -u hybridsec -n 50 --no-pager"
fi
