@echo off
REM SQL Injection Security Analysis Platform - Windows Launcher
REM Run from the sql_injection_analyzer directory

cd /d "%~dp0"
echo Starting SQL Injection Analyzer...
python main.py

if errorlevel 1 (
    echo.
    echo Error: Failed to start the application.
    echo Please ensure you have installed the required dependencies:
    echo pip install PyQt6 PyQtGraph matplotlib pandas numpy
    echo.
    pause
)
