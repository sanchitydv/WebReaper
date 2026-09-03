@echo off
REM ─────────────────────────────────────────
REM  WebReaper – Desktop Build Script (Windows)
REM ─────────────────────────────────────────

echo =^> Creating virtual environment...
python -m venv .venv
call .venv\Scripts\activate.bat

echo =^> Installing dependencies...
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo =^> Building app with PyInstaller...
pyinstaller WebReaper.spec --noconfirm --clean

echo.
echo Done! Executable: dist\WebReaper\WebReaper.exe
echo You can zip the dist\WebReaper folder and distribute it.
pause
