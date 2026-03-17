@echo off
setlocal

:: PEDefeat v2.0 Build Script
:: Author: Khaled M. Alshammri | @ik0z

call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
)
if %ERRORLEVEL% NEQ 0 (
    call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
)
if %ERRORLEVEL% NEQ 0 (
    echo [-] Cannot find MSVC toolchain
    exit /b 1
)

if not exist bin mkdir bin
if not exist reports mkdir reports
if not exist tools mkdir tools
if not exist rules mkdir rules
if not exist plugins mkdir plugins

echo [*] Building PEDefeat v2.0...
cl.exe /nologo /std:c++17 /EHsc /O2 /Fe:bin\PEDefeat.exe PEDefeat_v2.cpp /link /SUBSYSTEM:CONSOLE

if %ERRORLEVEL% NEQ 0 (
    echo [-] Build FAILED!
    exit /b 1
)

echo [+] bin\PEDefeat.exe v2.0 built successfully!
echo.
echo Usage:
echo   bin\PEDefeat.exe ^<target^> --all --deep
echo   bin\PEDefeat.exe script.ps1 --html --verbose
echo   bin\PEDefeat.exe payload.exe --amsi --all
echo   bin\PEDefeat.exe implant.dll --defender --severity=high
echo   bin\PEDefeat.exe loader.bat --all
echo   bin\PEDefeat.exe agent.exe --deep --verbose
echo.
echo Tools are auto-detected from tools/ directory - no paths needed!
echo.
