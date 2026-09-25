@echo off
title SentinelAPI - AmiHacks 1.0 Launcher
color 0B
echo ====================================================================
echo                   SENTINEL-API : ZERO-TRUST AUDITOR
echo                 AmiHacks 1.0 - Track C (Deep-Tech)
echo ====================================================================
echo.

:: 1. Check Python installation
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not added to your system PATH!
    echo.
    echo Please install Python 3.10+ from https://www.python.org/downloads/
    echo [IMPORTANT] Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b
)

echo [*] Python detected successfully.
echo [*] Checking and installing required dependencies (FastAPI, Uvicorn, Requests)...
python -m pip install -r requirements.txt --quiet --disable-pip-version-check
if %errorlevel% neq 0 (
    echo [!] Standard install had a warning, retrying explicitly...
    python -m pip install fastapi uvicorn requests pyyaml python-pptx
)

echo.
echo [*] Starting SentinelAPI Servers and opening browser...
echo.
python run.py

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] The server closed unexpectedly. Please read the error message above.
    pause
)
