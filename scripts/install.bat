@echo off
setlocal enabledelayedexpansion

echo =====================================================================
echo    Custom MFA Windows Credential Provider - Installer
echo =====================================================================
echo.

:: Check for Administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This installer requires Administrator privileges.
    echo Please right-click install.bat and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

set SCRIPT_DIR=%~dp0
set DLL_NAME=CustomMfaCredentialProvider.dll
set TARGET_PATH=%SystemRoot%\System32\%DLL_NAME%

:: Look for the compiled DLL in common build folders
set SOURCE_DLL=
if exist "%SCRIPT_DIR%..\build\Release\%DLL_NAME%" (
    set SOURCE_DLL=%SCRIPT_DIR%..\build\Release\%DLL_NAME%
) else if exist "%SCRIPT_DIR%..\build\bin\Release\%DLL_NAME%" (
    set SOURCE_DLL=%SCRIPT_DIR%..\build\bin\Release\%DLL_NAME%
) else if exist "%SCRIPT_DIR%..\build\%DLL_NAME%" (
    set SOURCE_DLL=%SCRIPT_DIR%..\build\%DLL_NAME%
) else if exist "%SCRIPT_DIR%%DLL_NAME%" (
    set SOURCE_DLL=%SCRIPT_DIR%%DLL_NAME%
)

if "%SOURCE_DLL%"=="" (
    echo [ERROR] Could not find %DLL_NAME%!
    echo Please build the project using CMake first:
    echo   cmake -B build -A x64
    echo   cmake --build build --config Release
    echo.
    pause
    exit /b 1
)

echo [*] Found compiled DLL at:
echo     %SOURCE_DLL%
echo.

echo [*] Copying DLL to System32...
copy /Y "%SOURCE_DLL%" "%TARGET_PATH%" >nul
if %errorlevel% neq 0 (
    echo [ERROR] Failed to copy DLL to %TARGET_PATH%
    pause
    exit /b 1
)
echo [+] DLL copied successfully.
echo.

echo [*] Registering COM DLL with regsvr32...
regsvr32.exe /s "%TARGET_PATH%"
if %errorlevel% neq 0 (
    echo [ERROR] regsvr32 failed with error code %errorlevel%
    pause
    exit /b 1
)
echo [+] Successfully registered Custom MFA Credential Provider!
echo.
echo =====================================================================
echo  Installation Complete!
echo  - To test in desktop mode safely: run MfaTestHarness.exe
echo  - To test on lock screen: press Win + L (ensure MockMfaService runs)
echo =====================================================================
echo.
pause
