#!/usr/bin/env bash
# =============================================================================
# SOC Dashboard — Update Script
# รองรับทั้ง Docker และ Non-Docker (systemd + gunicorn)
#
# วิธีใช้:
#   sudo bash scripts/update.sh          # non-docker
#   sudo bash scripts/update.sh --docker # docker compose
# =============================================================================
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$APP_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

DOCKER_MODE=false
[[ "${1:-}" == "--docker" ]] && DOCKER_MODE=true

OLD_VERSION=$(cat VERSION 2>/dev/null || echo "unknown")

# ── 1. Pull latest code ───────────────────────────────────────────────────────
info "Pulling latest code from GitHub..."
git pull origin main
NEW_VERSION=$(cat VERSION 2>/dev/null || echo "unknown")
ok "Version: ${OLD_VERSION} → ${NEW_VERSION}"

# ── 2. Update & migrate ───────────────────────────────────────────────────────
if $DOCKER_MODE; then
    info "Rebuilding Docker image..."
    docker compose build app

    info "Running migrations..."
    docker compose run --rm app python manage.py migrate --noinput

    info "Collecting static files..."
    docker compose run --rm app python manage.py collectstatic --noinput

    info "Restarting app container..."
    docker compose up -d app
    ok "Docker stack updated"

else
    info "Installing Python dependencies..."
    venv/bin/pip install -r requirements.txt -q

    if [[ -f soc-bot/requirements.txt ]] && [[ -d soc-bot/venv ]]; then
        info "Installing soc-bot dependencies..."
        soc-bot/venv/bin/pip install -r soc-bot/requirements.txt -q
    fi

    info "Running migrations..."
    venv/bin/python manage.py migrate --noinput

    info "Collecting static files..."
    venv/bin/python manage.py collectstatic --noinput

    # ── Reload services ──────────────────────────────────────────────────────
    info "Reloading services..."

    # Gunicorn graceful reload (HUP)
    if [[ -f gunicorn.ctl ]]; then
        MASTER_PID=$(cat gunicorn.ctl 2>/dev/null || echo "")
        if [[ -n "$MASTER_PID" ]] && kill -0 "$MASTER_PID" 2>/dev/null; then
            kill -HUP "$MASTER_PID"
            ok "Gunicorn reloaded (PID $MASTER_PID)"
        else
            # fallback to systemctl
            systemctl restart soc-dashboard 2>/dev/null && ok "soc-dashboard restarted" || true
        fi
    else
        systemctl restart soc-dashboard 2>/dev/null && ok "soc-dashboard restarted" || true
    fi

    # soc-bot reload
    systemctl restart soc-bot 2>/dev/null && ok "soc-bot restarted" || true

    ok "Non-Docker stack updated"
fi

echo ""
ok "Update complete: ${OLD_VERSION} → ${NEW_VERSION}"
