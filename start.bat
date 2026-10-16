@echo off
chcp 65001 >nul
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py scanner.py
    goto end
)

where python >nul 2>nul
if %errorlevel%==0 (
    python scanner.py
    goto end
)

echo.
echo [ERROR] Python not found.
echo Install Python 3.11+ from https://www.python.org/downloads/
echo Check "Add python.exe to PATH" during install.
echo.

:end
pause