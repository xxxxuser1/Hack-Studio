@echo off
title Ethical Hacking Toolkit

echo ========================================
echo ETHICAL HACKING TOOLKIT
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Python not found. Please install Python 3.x
    echo    Download from: https://www.python.org/downloads/
    pause
    exit /b
)

echo [+] Python found
echo.

REM Check if required files exist
if not exist "hacking_toolkit.py" (
    echo [-] hacking_toolkit.py not found
    pause
    exit /b
)

echo [+] Starting Ethical Hacking Toolkit...
echo.

python hacking_toolkit.py

echo.
echo [*] Toolkit execution completed
pause