@echo off
cd /d "%~dp0.."

if not exist ".venv\Scripts\python.exe" (
    echo Run scripts\Install_Once.bat first.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" -m pip install pyinstaller
if errorlevel 1 (
    echo PyInstaller installation failed.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed --name CyberReadyAudit --paths src "src\desktop_app.py"
if errorlevel 1 (
    echo Build failed.
    pause
    exit /b 1
)

echo.
echo Build complete.
echo Executable location: dist\CyberReadyAudit.exe
pause
