#!/bin/bash

set -e  # Stop on error

echo "========================================"
echo " Malware Unpacking and YARA Detection Setup Script"
echo "========================================"

# 1️⃣ Check Python
if ! command -v python3 &> /dev/null
then
    echo "Python3 not found. Please install Python 3.9+"
    exit 1
fi

echo "[+] Python found"

# 2️⃣ Create virtual environment (optional but recommended)
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv venv
fi

echo "[+] Activating virtual environment..."
source venv/bin/activate


# 4️⃣ Install dependencies
echo "[+] Installing Python dependencies..."
pip install -r requirements.txt

# 5️⃣ Create SQLite database
DB_FILE="rules.db"

if [ -f "$DB_FILE" ]; then
    echo "[!] rules.db already exists. Skipping DB creation."
else
    echo "[+] Creating SQLite database..."

    sqlite3 $DB_FILE <<EOF
DROP TABLE IF EXISTS rules;

CREATE TABLE rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,             
    rule_text TEXT NOT NULL,
    enabled INTEGER DEFAULT 1
);
EOF

    echo "[+] Database created for YARA rules"
fi

echo "========================================"
echo " Setup completed successfully"
echo "========================================"
echo "To activate environment:"
echo "source venv/bin/activate"
