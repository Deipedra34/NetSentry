@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo NetSentry's environment isn't set up yet. Open a terminal once and run:
    echo.
    echo   python -m venv .venv
    echo   .venv\Scripts\pip install -r requirements-desktop.txt
    echo.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" -c "import webview" 2>nul
if errorlevel 1 (
    echo Setting up NetSentry's desktop app, one-time only, please wait...
    ".venv\Scripts\python.exe" -m pip install -r requirements-desktop.txt
)

start "" ".venv\Scripts\pythonw.exe" "%~dp0desktop_app.py"
