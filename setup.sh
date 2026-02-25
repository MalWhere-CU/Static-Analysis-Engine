#!/bin/bash

set -e  # Stop on error

echo "===================================================="
echo " 🛡️  Malware Unpacking & YARA Detection Setup 🛡️"
echo "===================================================="

# 1️⃣ Check for System Dependencies
echo "[+] Checking system dependencies..."
dependencies=(python3 sqlite3 redis-server)
for cmd in "${dependencies[@]}"; do
    if ! command -v $cmd &> /dev/null; then
        echo "[!] Error: $cmd is not installed. Please install it (e.g., sudo apt install $cmd)"
        exit 1
    fi
done

# 2️⃣ Redis Service Check
if systemctl is-active --quiet redis-server; then
    echo "[+] Redis is running"
else
    echo "[!] Warning: Redis is installed but not running. Start it with: sudo systemctl start redis-server"
fi

# 3️⃣ Python Environment Setup
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv venv
fi

echo "[+] Activating virtual environment..."
source venv/bin/activate

# 4️⃣ Install Python Requirements
if [ -f "requirements.txt" ]; then
    echo "[+] Installing Python dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
else
    echo "[!] Warning: requirements.txt not found. Skipping pip install."
fi

# 5️⃣ Initialize .env file
if [ ! -f ".env" ]; then
    echo "[+] Creating .env template..."
    cat <<EOF > .env
OPENAI_API_KEY=your_key_here
DB_PATH=rules.db
REDIS_HOST=localhost
REDIS_PORT=6379
EOF
    echo "[!] IMPORTANT: Update your .env file with your OpenAI API Key!"
fi

# 6️⃣ Create/Update SQLite Database
DB_FILE="rules.db"
echo "[+] Initializing/Updating Database..."

sqlite3 $DB_FILE <<EOF
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,             
    rule_text TEXT NOT NULL,
    ai_explanation TEXT,      -- Added for DB-based persistence
    enabled INTEGER DEFAULT 1
);
EOF

# 7️⃣ Create necessary directories
mkdir -p test_samples
mkdir -p logs

echo "========================================"
echo " ✅ Setup completed successfully"
echo "========================================"
echo "1. Activate environment: source venv/bin/activate"
echo "2. Edit your .env file"
echo "3. Run your scanner: python3 main.py <sample_path>"