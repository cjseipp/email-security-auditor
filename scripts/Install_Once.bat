@echo off
cd /d "%~dp0.."

where py >nul 2>nul
if not errorlevel 1 (
    py -3 -m venv .venv
) else (
    python -m venv .venv
)

if errorlevel 1 (
    echo Virtual environment setup failed.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" -m pip install -r requirements.txt

if errorlevel 1 (
    echo Dependency installation failed.
    pause
    exit /b 1
)

echo.
echo Setup complete.
echo Start the applications using:
echo scripts\Start_Desktop.bat
echo scripts\Start_Browser.bat
pause
