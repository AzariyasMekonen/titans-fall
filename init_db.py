import sqlite3
import os
import sys

DATABASE = os.environ.get('DATABASE_PATH', '/app/data/kronos.db')
FLAG = os.environ.get('CHALLENGE_FLAG') or os.environ.get('FLAG') or 'AdwaCTF{kr0n0s_4lg_n0ne_bypass_m4st3r}'

def init_database():
    """Initialize the SQLite database with dummy analytics data and the hidden flag."""
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # ==================== Analytics Tables ====================

    # Telemetry data table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS telemetry_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            source TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            payload TEXT,
            severity TEXT DEFAULT 'INFO'
        )
    ''')

    # User metrics table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            metric_name TEXT NOT NULL,
            metric_value REAL,
            recorded_at TEXT NOT NULL
        )
    ''')

    # Session logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS session_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            user_agent TEXT,
            ip_hash TEXT,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            page_views INTEGER DEFAULT 0
        )
    ''')

    # Performance KPIs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS performance_kpi (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kpi_name TEXT NOT NULL,
            kpi_value REAL,
            department TEXT,
            quarter TEXT NOT NULL,
            year INTEGER NOT NULL
        )
    ''')

    # System configuration (decoy)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT
        )
    ''')

    # ==================== THE FLAG TABLE ====================
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS flag_vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flag_name TEXT NOT NULL,
            flag_value TEXT NOT NULL,
            classification TEXT DEFAULT 'TOP_SECRET',
            inserted_at TEXT NOT NULL
        )
    ''')

    # ==================== Populate with dummy data ====================

    # Telemetry events
    telemetry_data = [
        ('page_view', 'web-frontend', '2023-11-15T08:30:00Z', '{"page": "/dashboard"}', 'INFO'),
        ('api_call', 'mobile-app', '2023-11-15T08:31:22Z', '{"endpoint": "/v1/GetConfig"}', 'INFO'),
        ('error', 'backend-svc', '2023-11-15T08:32:10Z', '{"code": 500, "msg": "DB timeout"}', 'ERROR'),
        ('login', 'web-frontend', '2023-11-15T08:33:00Z', '{"method": "SSO"}', 'INFO'),
        ('page_view', 'web-frontend', '2023-11-15T08:34:15Z', '{"page": "/reports"}', 'INFO'),
        ('api_call', 'data-pipeline', '2023-11-15T08:35:00Z', '{"endpoint": "/v2/Query"}', 'INFO'),
        ('logout', 'web-frontend', '2023-11-15T08:40:00Z', '{"reason": "session_timeout"}', 'WARN'),
        ('health_check', 'monitoring', '2023-11-15T09:00:00Z', '{"status": "healthy"}', 'INFO'),
    ]
    cursor.executemany('INSERT INTO telemetry_events (event_type, source, timestamp, payload, severity) VALUES (?, ?, ?, ?, ?)', telemetry_data)

    # User metrics
    user_metrics_data = [
        ('USR-001', 'queries_executed', 142.0, '2023-11-15T00:00:00Z'),
        ('USR-001', 'data_exported_mb', 23.5, '2023-11-15T00:00:00Z'),
        ('USR-002', 'queries_executed', 87.0, '2023-11-15T00:00:00Z'),
        ('USR-002', 'dashboards_viewed', 12.0, '2023-11-15T00:00:00Z'),
        ('USR-003', 'queries_executed', 5.0, '2023-11-15T00:00:00Z'),
        ('USR-003', 'reports_generated', 2.0, '2023-11-15T00:00:00Z'),
    ]
    cursor.executemany('INSERT INTO user_metrics (user_id, metric_name, metric_value, recorded_at) VALUES (?, ?, ?, ?)', user_metrics_data)

    # Session logs
    session_data = [
        ('SES-a1b2c3', 'Mozilla/5.0 Chrome/119', 'hash_abc123', '2023-11-15T08:00:00Z', '2023-11-15T08:45:00Z', 15),
        ('SES-d4e5f6', 'Mozilla/5.0 Firefox/120', 'hash_def456', '2023-11-15T09:00:00Z', '2023-11-15T10:30:00Z', 32),
        ('SES-g7h8i9', 'Mozilla/5.0 Safari/17', 'hash_ghi789', '2023-11-15T10:00:00Z', None, 8),
    ]
    cursor.executemany('INSERT INTO session_logs (session_id, user_agent, ip_hash, started_at, ended_at, page_views) VALUES (?, ?, ?, ?, ?, ?)', session_data)

    # Performance KPIs
    kpi_data = [
        ('Revenue Growth', 12.5, 'Sales', 'Q3', 2023),
        ('Customer Retention', 94.2, 'Customer Success', 'Q3', 2023),
        ('API Uptime', 99.97, 'Engineering', 'Q3', 2023),
        ('Query Latency P99', 245.0, 'Engineering', 'Q3', 2023),
        ('Data Pipeline SLA', 99.5, 'Data Engineering', 'Q3', 2023),
    ]
    cursor.executemany('INSERT INTO performance_kpi (kpi_name, kpi_value, department, quarter, year) VALUES (?, ?, ?, ?, ?)', kpi_data)

    # System config (decoy data)
    config_data = [
        ('db.pool_size', '20', '2023-10-01T00:00:00Z'),
        ('cache.ttl_seconds', '300', '2023-10-01T00:00:00Z'),
        ('auth.token_expiry', '3600', '2023-10-01T00:00:00Z'),
        ('query.max_rows', '10000', '2023-10-01T00:00:00Z'),
        ('query.timeout_ms', '30000', '2023-10-01T00:00:00Z'),
    ]
    cursor.executemany('INSERT INTO system_config (key, value, updated_at) VALUES (?, ?, ?)', config_data)

    # ==================== INSERT / UPDATE THE FLAG ====================
    cursor.execute('DELETE FROM flag_vault WHERE flag_name = ?', ('KRONOS_PRIMARY',))
    cursor.execute('''
        INSERT INTO flag_vault (flag_name, flag_value, classification, inserted_at)
        VALUES (?, ?, ?, ?)
    ''', ('KRONOS_PRIMARY', FLAG, 'TOP_SECRET', '2023-01-15T00:00:00Z'))

    conn.commit()
    conn.close()
    print(f"[+] Database initialized at {DATABASE}")
    print(f"[+] Flag inserted into flag_vault table")
    print(f"[+] Tables created: telemetry_events, user_metrics, session_logs, performance_kpi, system_config, flag_vault")


if __name__ == '__main__':
    init_database()
