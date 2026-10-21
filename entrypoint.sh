#!/bin/bash
set -e

# Initialize or update database with runtime flag
echo "[*] Initializing database and setting flag..."
python init_db.py
echo "[*] Database ready."

# Start the Flask application
echo "[*] Starting Kronos Analytics Engine on port $PORT..."
exec python app.py
