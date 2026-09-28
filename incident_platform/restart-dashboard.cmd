@echo off
rem Restart the demo dashboard. Usage: restart-dashboard [gpt ^| mock] [-Port 8001] [-NoBrowser]
rem Runs the PowerShell script with a per-process execution policy, so no system setting changes.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0restart-dashboard.ps1" %*
