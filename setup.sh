#!/usr/bin/env bash
# Demogorgon — one-command setup for beginners
#
#   bash setup.sh              Install + run the interactive setup wizard
#   bash setup.sh --no-setup   Install only (skip the wizard)
#
# The wizard walks you through: select provider → connect (API key + test)
# → pick a model. After it finishes you're ready to hunt.

set -euo pipefail
cd "$(dirname "$0")"

SKIP_WIZARD=0
for arg in "$@"; do
    case "$arg" in
        --no-setup) SKIP_WIZARD=1 ;;
        -h|--help)
            sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
    esac
done

echo "============================================"
echo "  Demogorgon — Autonomous Bug Bounty Hunter"
echo "  One-Command Setup"
echo "============================================"
echo ""

# ── Check Python version ──────────────────────────────────────────────────
PYTHON=""
for cmd in python3.14 python3.13 python3.12 python3.11 python3; do
    if command -v "$cmd" &>/dev/null; then
        version=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
            PYTHON="$cmd"
            echo "[+] Found Python $version at $(command -v "$cmd")"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "[-] Python 3.11+ required. Install from https://python.org"
    exit 1
fi

# ── Create virtual environment ────────────────────────────────────────────
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment..."
    "$PYTHON" -m venv venv
else
    echo "[+] Virtual environment already exists"
fi

# ── Activate ──────────────────────────────────────────────────────────────
# shellcheck disable=SC1091
source venv/bin/activate
echo "[+] Activated venv ($(python --version))"

# ── Install Demogorgon ────────────────────────────────────────────────────
echo "[+] Installing Demogorgon (this may take a minute)..."
pip install --upgrade pip >/dev/null 2>&1 || true
if ! pip install -e .; then
    echo "[!] Editable install failed — falling back to requirements.txt"
    pip install -r requirements.txt
fi

# ── Setup .env template ───────────────────────────────────────────────────
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "[+] Created .env from .env.example"
fi
chmod 600 .env 2>/dev/null || true

# ── Optional: Playwright browsers (for JS-heavy / browser crawling) ───────
if [ "$SKIP_WIZARD" -eq 0 ] && [ -t 0 ]; then
    read -r -p "[?] Install Playwright Chromium for browser crawling? [Y/n] " answer || answer="n"
    case "${answer:-Y}" in
        [Nn]*) echo "[-] Skipping browser install (run later: python -m playwright install chromium)" ;;
        *)
            echo "[+] Installing Playwright Chromium..."
            python -m playwright install chromium \
                || echo "[!] Playwright browser install failed — browser crawling unavailable (non-fatal)"
            ;;
    esac
fi

# ── Quick validation ──────────────────────────────────────────────────────
echo ""
echo "[+] Validating installation..."
python -c "
import httpx, rich, openai
print('  [+] Core imports OK')
" 2>/dev/null || echo "  [-] Some imports failed — check the pip output above"

# ── Interactive setup wizard ──────────────────────────────────────────────
echo ""
if [ "$SKIP_WIZARD" -eq 1 ]; then
    echo "[+] Skipping setup wizard (--no-setup)."
    echo "    Run it later: source venv/bin/activate && python -m demogorgon setup"
elif [ ! -t 0 ]; then
    echo "[!] Non-interactive terminal — skipping setup wizard."
    echo "    Run it later: source venv/bin/activate && python -m demogorgon setup"
else
    echo "============================================"
    echo "  Setup wizard: select provider → connect → model"
    echo "============================================"
    echo ""
    python -m demogorgon setup || true
fi

# ── Done ──────────────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo "  Setup complete!"
echo ""
echo "  Getting started:"
echo "    1. source venv/bin/activate"
echo "    2. python -m demogorgon doctor      # verify LLM works"
echo "    3. python -m demogorgon tools       # list security tools"
echo "    4. python -m demogorgon             # guided hunt: target → scope → program doc"
echo ""
echo "  In the guided hunt you will be asked:"
echo "    - Target URL/domain"
echo "    - Scope: upload a program document (drag & drop the"
echo "      policy .txt/.md/.pdf from HackerOne/Bugcrowd) or paste it"
echo "    - Authorization confirmation (you must be in-scope)"
echo ""
echo "  Re-run the wizard anytime:"
echo "    python -m demogorgon setup"
echo ""
echo "  Test with OWASP Juice Shop:"
echo "    docker run -d -p 3000:3000 bkimminich/juice-shop"
echo "    python -m demogorgon http://localhost:3000"
echo "============================================"
