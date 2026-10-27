@echo off
cd /d "%~dp0.."

if not exist ".venv\Scripts\python.exe" (
    echo Run Install_Once.bat first.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" "src\desktop_app.py"

if errorlevel 1 pause
