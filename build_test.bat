@echo off
call "F:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
cd /d "%~dp0"

echo ========================================
echo   CAS Core Security - Build and Test
echo ========================================

mkdir build 2>nul
cd build

echo.
echo [1/3] Compiling core library objects...
cl /std:c++17 /W4 /WX /EHsc /MD /I ..\include /DCSC_PROTOCOL_VERSION="2.0" /c ^
    ..\src\CryptoCore.cpp ^
    ..\src\SecureChannel.cpp ^
    ..\src\AuthGateway.cpp ^
    ..\src\ApiRegistry.cpp ^
    ..\src\RuntimeEnvironmentValidator.cpp

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [FAILED] Core library compilation failed!
    exit /b %ERRORLEVEL%
)

echo.
echo [2/3] Compiling test runner...
cl /std:c++17 /W4 /WX /EHsc /MD /I ..\include /I ..\src /DCSC_PROTOCOL_VERSION="2.0" ^
    ..\tests\test_runner.cpp ^
    CryptoCore.obj ^
    SecureChannel.obj ^
    AuthGateway.obj ^
    ApiRegistry.obj ^
    RuntimeEnvironmentValidator.obj ^
    /link bcrypt.lib crypt32.lib advapi32.lib ^
    /OUT:test_runner.exe

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [FAILED] Test runner compilation failed!
    exit /b %ERRORLEVEL%
)

echo.
echo [3/3] Running test suite...
echo.
test_runner.exe

set TEST_EXIT_CODE=%ERRORLEVEL%
echo.
if %TEST_EXIT_CODE% EQU 0 (
    echo [SUCCESS] All tests passed!
) else (
    echo [FAILED] Some tests failed with exit code %TEST_EXIT_CODE%!
)
exit /b %TEST_EXIT_CODE%