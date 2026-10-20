#!/bin/bash
set -e

# Initialize database if it doesn't exist
if [ ! -f "$DATABASE_PATH" ]; then
    echo "[*] Initializing database..."
    python init_db.py
    echo "[*] Database ready."
else
    echo "[*] Database already exists, skipping initialization."
fi

# Start the Flask application
echo "[*] Starting Kronos Analytics Engine on port $PORT..."
exec python app.py
