@echo off
title LogVault - Starting...
color 0A

echo.
echo  ============================================
echo       LogVault - Blockchain Log Simulator
echo  ============================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Python is not installed or not in PATH.
    echo  Please install Python from https://www.python.org/downloads/
    echo  Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo  [OK] Python found.

:: Install dependencies if Flask is missing
python -c "import flask" >nul 2>&1
if %errorlevel% neq 0 (
    echo  [INFO] Installing required packages...
    python -m pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo  [ERROR] Failed to install packages. Check your internet connection.
        pause
        exit /b 1
    )
    echo  [OK] Packages installed.
) else (
    echo  [OK] Dependencies already installed.
)

echo.
echo  [INFO] Starting LogVault server...
echo  [INFO] Open your browser at: http://localhost:5000
echo  [INFO] Other devices on the same network can use:
echo.

:: Show local IP address
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i "IPv4"') do (
    set IP=%%a
    setlocal enabledelayedexpansion
    set IP=!IP: =!
    echo             http://!IP!:5000
    endlocal
)

echo.
echo  [INFO] Press Ctrl+C to stop the server.
echo  ============================================
echo.

:: Open browser after a short delay (in background)
start "" cmd /c "timeout /t 2 >nul && start http://localhost:5000"

:: Start the Flask app
python app.py

echo.
echo  [INFO] Server stopped.
pause
