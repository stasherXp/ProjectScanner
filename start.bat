@echo off
chcp 65001 >nul
cd /d "%~dp0"
python scanner.py
pause
