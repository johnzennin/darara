#!/bin/bash
# SQL Injection Security Analysis Platform - Linux/macOS Launcher

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Starting SQL Injection Analyzer..."
python3 main.py

if [ $? -ne 0 ]; then
    echo ""
    echo "Error: Failed to start the application."
    echo "Please ensure you have installed the required dependencies:"
    echo "pip install PyQt6 PyQtGraph matplotlib pandas numpy"
    echo ""
fi
