@echo off
setlocal

echo ===================================================
echo Setting up Visual Studio x64 Build Environment...
echo ===================================================
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to initialize vcvars64.bat
    exit /b %errorlevel%
)

set "PATH=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%PATH%"

echo ===================================================
echo Configuring CMake (x64 Release)...
echo ===================================================
cmake -B build -A x64
if %errorlevel% neq 0 (
    echo [ERROR] CMake configuration failed.
    exit /b %errorlevel%
)

echo ===================================================
echo Building with CMake...
echo ===================================================
cmake --build build --config Release
if %errorlevel% neq 0 (
    echo [ERROR] CMake build failed.
    exit /b %errorlevel%
)

echo ===================================================
echo Build Succeeded! Verifying output artifacts:
echo ===================================================
dir build\Release\*.dll build\Release\*.exe

exit /b 0
