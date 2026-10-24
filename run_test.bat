@echo off
cd /d "%~dp0"
echo Starting Mock MFA Background Service if not already running...
tasklist /FI "IMAGENAME eq MockMfaService.exe" | find /i "MockMfaService.exe" >nul
if %errorlevel% neq 0 (
    start "" build\Release\MockMfaService.exe
    timeout /t 1 /nobreak >nul
)
echo Launching MFA Desktop Test Harness...
start "" build\Release\MfaTestHarness.exe
