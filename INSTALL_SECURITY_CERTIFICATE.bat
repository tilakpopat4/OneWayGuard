@echo off
:: =========================================================================
:: OneWayGuard - Trusted Publisher Registration
:: Run this ONCE on external Windows PCs to eliminate Defender SmartScreen
:: =========================================================================
setlocal EnableDelayedExpansion

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Administrator privileges required to register the security certificate.
    echo [*] Attempting to elevate permissions...
    powershell -Command "Start-Process '%~0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo ========================================================================
echo        REGISTERING ONEWAYGUARD SECURITY CERTIFICATE AS TRUSTED
echo ========================================================================
echo.

if exist "OneWayGuard_Security_Certificate.cer" (
    echo [*] Adding certificate to Windows Trusted Root Certification Authorities...
    certutil -addstore -f "Root" "OneWayGuard_Security_Certificate.cer" >nul 2>&1
    
    echo [*] Adding certificate to Windows Trusted Publishers store...
    certutil -addstore -f "TrustedPublisher" "OneWayGuard_Security_Certificate.cer" >nul 2>&1
    
    echo.
    echo [+] SUCCESS: OneWayGuard is now registered as a TRUSTED PUBLISHER on this PC!
    echo [+] Microsoft Defender SmartScreen will no longer block OneWayGuard.
) else (
    echo [!] Error: OneWayGuard_Security_Certificate.cer not found in current folder.
)

echo.
echo [*] Unblocking application files from Internet Zone tags...
powershell -NoProfile -Command "Get-ChildItem -Path '%~dp0' -Recurse -ErrorAction SilentlyContinue | Unblock-File"
echo [+] All files unblocked successfully.
echo.
echo ========================================================================
echo You can now run OneWayGuard-Setup-Win64.exe or OneWayGuard.exe without any warnings!
echo ========================================================================
pause
