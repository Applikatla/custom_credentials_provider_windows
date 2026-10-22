@echo off
setlocal enabledelayedexpansion

echo =====================================================================
echo    Custom MFA Windows Credential Provider - Uninstaller
echo =====================================================================
echo.

:: Check for Administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This uninstaller requires Administrator privileges.
    echo Please right-click uninstall.bat and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

set DLL_NAME=CustomMfaCredentialProvider.dll
set TARGET_PATH=%SystemRoot%\System32\%DLL_NAME%

if not exist "%TARGET_PATH%" (
    echo [*] %TARGET_PATH% is not installed.
) else (
    echo [*] Unregistering DLL with regsvr32...
    regsvr32.exe /u /s "%TARGET_PATH%"
    echo [+] COM unregistration complete.
    echo.

    echo [*] Removing DLL from System32...
    del /f /q "%TARGET_PATH%" 2>nul
    if exist "%TARGET_PATH%" (
        echo [!] Warning: Could not delete %TARGET_PATH% immediately.
        echo     It might still be locked in LogonUI.exe memory.
        echo     It will be deleted after the next restart.
    ) else (
        echo [+] DLL deleted successfully.
    )
)

echo.
echo =====================================================================
echo  Uninstallation Complete! Custom MFA provider removed.
echo =====================================================================
echo.
pause
