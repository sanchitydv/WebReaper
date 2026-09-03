#!/usr/bin/env bash
# ──────────────────────────────────────────────
#  WebReaper – Desktop Build Script (macOS/Linux)
# ──────────────────────────────────────────────
set -e

VENV=".venv"

echo "==> Detecting Python with Tk support..."
PYTHON=""
for candidate in /usr/local/bin/python3 python3 /opt/homebrew/bin/python3.12; do
  if "$candidate" -c "import tkinter" 2>/dev/null; then
    PYTHON="$candidate"
    break
  fi
done
if [[ -z "$PYTHON" ]]; then
  echo "ERROR: No Python with Tkinter found. On macOS, install python-tk: brew install python-tk"
  exit 1
fi
echo "  Using: $PYTHON"

echo "==> Creating virtual environment..."
"$PYTHON" -m venv "$VENV"
source "$VENV/bin/activate"

echo "==> Installing dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo "==> Building app with PyInstaller..."
pyinstaller WebReaper.spec --noconfirm --clean

echo ""
if [[ "$OSTYPE" == "darwin"* ]]; then
  echo "✓  Build complete. App bundle: dist/WebReaper.app"
  echo "   Double-click to run, or drag to /Applications."
else
  echo "✓  Build complete. Executable: dist/WebReaper/WebReaper"
fi
