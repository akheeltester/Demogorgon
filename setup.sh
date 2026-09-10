#!/usr/bin/env bash
# Demogorgon — One-command setup
# Usage: bash setup.sh

set -euo pipefail

echo "============================================"
echo "  Demogorgon — Autonomous Bug Bounty Hunter"
echo "  Setup Script"
echo "============================================"
echo ""

# ── Check Python version ──────────────────────────────────────────────────
PYTHON=""
for cmd in python3.13 python3.12 python3.11 python3; do
    if command -v "$cmd" &>/dev/null; then
        version=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
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
source venv/bin/activate
echo "[+] Activated venv ($(python --version))"

# ── Install dependencies ──────────────────────────────────────────────────
echo "[+] Installing dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

# ── Install Playwright browsers ───────────────────────────────────────────
echo "[+] Installing Playwright browsers..."
python -m playwright install chromium -q

# ── Setup .env ────────────────────────────────────────────────────────────
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "[+] Created .env from .env.example"
    echo "[!] Edit .env and add your OPENROUTER_API_KEY"
else
    echo "[+] .env already exists"
fi

# ── Quick validation ──────────────────────────────────────────────────────
echo ""
echo "[+] Validating installation..."
python -c "
import httpx, rich, openai, playwright, jwt, cryptography
print('  [+] All core imports OK')
" 2>/dev/null || echo "  [-] Some imports failed — check requirements.txt"

echo ""
echo "============================================"
echo "  Setup complete!"
echo ""
echo "  Quick start:"
echo "    1. Edit .env and add your API key"
echo "    2. Run: source venv/bin/activate"
echo "    3. Run: python -m demogorgon https://target.com"
echo ""
echo "  Test with OWASP Juice Shop:"
echo "    docker run -d -p 3000:3000 bkimminich/juice-shop"
echo "    python -m demogorgon http://localhost:3000"
echo "============================================"
