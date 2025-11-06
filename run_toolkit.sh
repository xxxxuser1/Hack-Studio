#!/bin/bash

echo "========================================"
echo "ETHICAL HACKING TOOLKIT"
echo "========================================"
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null
then
    echo "[-] Python 3 not found. Please install Python 3.x"
    echo "   Ubuntu/Debian: sudo apt install python3"
    echo "   macOS: brew install python3"
    exit 1
fi

echo "[+] Python 3 found"
echo

# Check if required files exist
if [ ! -f "hacking_toolkit.py" ]; then
    echo "[-] hacking_toolkit.py not found"
    exit 1
fi

echo "[+] Starting Ethical Hacking Toolkit..."
echo

python3 hacking_toolkit.py

echo
echo "[*] Toolkit execution completed"