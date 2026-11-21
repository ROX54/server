@echo off
cd /d "%~dp0"
py -3 security_dashboard.py %*
if errorlevel 1 python security_dashboard.py %*
pause
