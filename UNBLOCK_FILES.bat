@echo off
echo [*] Removing Windows Mark-of-the-Web (Zone.Identifier) from all files...
powershell -NoProfile -Command "Get-ChildItem -Path '%~dp0' -Recurse -ErrorAction SilentlyContinue | Unblock-File"
echo [+] Complete! You can now launch OneWayGuard directly.
pause
