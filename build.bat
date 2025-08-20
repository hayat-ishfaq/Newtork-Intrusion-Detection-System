@echo off
REM Windows Build Script for DNS NIDS

echo === DNS NIDS Windows Build Script ===
echo.

REM Check for Visual Studio
where cl.exe >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: Visual Studio C++ compiler not found
    echo Please run this from a Visual Studio Developer Command Prompt
    exit /b 1
)

REM Check for CMake
where cmake.exe >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: CMake not found
    echo Please install CMake and add it to PATH
    exit /b 1
)

echo Building DNS NIDS...
echo.

REM Create build directory
if not exist build mkdir build
cd build

REM Configure with CMake
echo Configuring with CMake...
cmake .. -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release

if %ERRORLEVEL% NEQ 0 (
    echo Error: CMake configuration failed
    exit /b 1
)

REM Build
echo Compiling...
cmake --build . --config Release

if %ERRORLEVEL% NEQ 0 (
    echo Error: Build failed
    exit /b 1
)

echo.
echo ✓ Build completed successfully
echo.
echo === Build Summary ===
echo Executable: build\Release\nids_dns.exe
echo Test suite: build\Release\test_nids_dns.exe
echo Configuration: rules\dns_rules.json
echo.
echo Usage examples:
echo   build\Release\nids_dns.exe -h                                    # Show help
echo   build\Release\nids_dns.exe -i "Local Area Connection" -v         # Live capture
echo   build\Release\nids_dns.exe -r sample.pcap -R rules\dns_rules.json # File analysis
echo.

pause
