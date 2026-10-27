@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (echo Run Install_Once.bat first & pause & exit /b 1)
".venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --windowed --name CyberReadyAudit desktop_app.py
if errorlevel 1 (echo Build failed & pause & exit /b 1)
echo Finished: dist\CyberReadyAudit.exe
pause
