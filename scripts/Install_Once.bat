@echo off
cd /d "%~dp0"
where python3 >nul 2>nul
if errorlevel 1 (
 echo Python 3 is not installed or not on PATH. Install Python from python.org.
 pause
 exit /b 1
)
python3 -m venv .venv
if errorlevel 1 (echo Virtual environment setup failed & pause & exit /b 1)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (echo Dependency installation failed & pause & exit /b 1)
echo Setup complete. Double-click Start_Browser.bat or Start_Desktop.bat
pause
