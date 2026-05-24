@echo off
call "F:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
cd /d "%~dp0"

echo ========================================
echo   Compiling RXXL Open Source
echo ========================================

mkdir build 2>nul
cd build

echo [1/2] Compiling source files...
cl /std:c++17 /W4 /WX /EHsc /I ..\include /DCSC_PROTOCOL_VERSION="2.0" ^
    ..\src\CryptoCore.cpp ^
    ..\src\SecureChannel.cpp ^
    ..\src\AuthGateway.cpp ^
    ..\src\ApiRegistry.cpp ^
    ..\src\RuntimeEnvironmentValidator.cpp ^
    /link bcrypt.lib crypt32.lib advapi32.lib ^
    /OUT:csc_core_test.exe

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] Compilation completed successfully!
    echo Output: build\csc_core_test.exe
) else (
    echo.
    echo [FAILED] Compilation failed with errors!
    exit /b %ERRORLEVEL%
)