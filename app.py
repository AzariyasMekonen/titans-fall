import os
import json
import sqlite3
import base64
from flask import Flask, request, jsonify, send_from_directory, send_file

app = Flask(__name__, static_folder='static')

DATABASE = os.environ.get('DATABASE_PATH', '/app/data/kronos.db')
FLAG = os.environ.get('CHALLENGE_FLAG') or os.environ.get('FLAG') or 'ADWA{kr0n0s_4lg_n0ne_bypass_m4st3r}'

# Leaked config values (intentionally vulnerable)
VALID_TID = "9a8b7c6d-5e4f-3a2b-1c0d-e9f8a7b6c5d4"
VALID_AUD = "https://analytics.kronos.internal/api"
VALID_APPID = "c3f2e1d0-b9a8-7654-3210-fedcba987654"

# Local user mapping (intentionally vulnerable - plain username maps to admin)
LOCAL_USERS = {
    "admin": {"uid": 1, "role": "Admin", "name": "System Administrator"},
    "analyst": {"uid": 2, "role": "Viewer", "name": "Data Analyst"},
    "readonly": {"uid": 3, "role": "Viewer", "name": "Read Only User"},
}

# Valid routing targets
VALID_TARGETS = [
    "TestData", "CoreAnalytics", "TelemetryRaw", "UserMetrics",
    "SessionLogs", "EventStream", "AuditTrail", "PerformanceKPI",
    "RevenueData", "MarketingFunnel", "SupportTickets", "InventoryDB",
    "LogArchive_2021", "LogArchive_2022", "LogArchive_2023",
    "ComplianceAudit", "HRAnalytics", "FinanceReporting",
    "InfraMonitor", "SecurityEvents", "NetworkFlow",
    "CustomerSegment", "ProductTelemetry", "A_BTesting",
    "MLPipeline_Staging", "MLPipeline_Prod", "DataLake_Raw",
    "DataLake_Curated", "DataLake_Serving", "CacheLayer",
    # Decommissioned targets (return empty results)
    "Legacy_DW_2019", "Legacy_DW_2020", "OldCRM", "DeprecatedBI",
    "Sandbox_QA", "Sandbox_Dev", "MigrationTemp", "Archive_Deleted",
    "TestHarness_Old", "Demo_Environment", "POC_Analytics",
    "TempExport_Jan", "TempExport_Feb", "TempExport_Mar",
    "DecommNode_A", "DecommNode_B", "DecommNode_C",
    "RetiredCluster_1", "RetiredCluster_2", "RetiredCluster_3",
    "ObsoleteETL", "DeprecatedStream", "EndOfLife_Pipe",
    "Sunset_Dashboard", "Archived_Metrics", "Removed_Service",
]


def get_db(readonly=True):
    """Get a database connection. Use read-only mode for queries."""
    if readonly:
        conn = sqlite3.connect(f'file:{DATABASE}?mode=ro', uri=True)
    else:
        conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def base64url_decode(data):
    """Decode base64url-encoded data with padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def validate_jwt(auth_header):
    """
    Validate JWT claims but INTENTIONALLY skip signature verification.
    This is the core vulnerability: alg:none bypass.
    """
    if not auth_header or not auth_header.startswith('Bearer '):
        return None, "Missing or invalid Authorization header. Expected: Bearer <JWT>"

    token = auth_header[7:]  # Strip 'Bearer '
    parts = token.split('.')

    # Accept tokens with 2 parts (empty signature) or 3 parts
    if len(parts) < 2 or len(parts) > 3:
        return None, "Malformed JWT: expected header.payload or header.payload.signature"

    try:
        header = json.loads(base64url_decode(parts[0]))
        payload = json.loads(base64url_decode(parts[1]))
    except Exception as e:
        return None, f"Failed to decode JWT: {str(e)}"

    # VULNERABILITY: We check the header but do NOT verify the signature
    # This allows alg:none tokens to pass through
    if header.get('typ') != 'JWT':
        return None, "Invalid token type. Expected typ: JWT"

    # Validate organizational claims
    if payload.get('tid') != VALID_TID:
        return None, "Invalid Tenant ID (tid). Access denied."
    if payload.get('aud') != VALID_AUD:
        return None, "Invalid audience (aud). Token not issued for this service."
    if payload.get('appid') != VALID_APPID:
        return None, "Invalid application ID (appid). Unregistered application."

    # UPN local user mapping
    upn = payload.get('upn')
    if not upn:
        return None, "Missing upn claim. User principal name required."

    # VULNERABILITY: email-style UPNs are rejected, but plain usernames map directly
    if '@' in upn:
        return None, "User not recognized in local RBAC. Corporate directory sync pending."

    user = LOCAL_USERS.get(upn)
    if not user:
        return None, f"User '{upn}' not recognized in local RBAC."

    return {"user": user, "claims": payload}, None


# ==================== ROUTES ====================

@app.route('/')
def index():
    """Frontend lockout - always denies access."""
    return send_file('static/index.html')


@app.route('/robots.txt')
def robots():
    """robots.txt with a hint to the backup config."""
    return send_file('static/robots.txt', mimetype='text/plain')


@app.route('/backup/superset_config_2023.bak')
def leaked_config():
    """Leaked archived configuration file."""
    return send_file('static/superset_config_2023.bak', mimetype='text/plain')


@app.route('/swagger.json')
def swagger_json():
    """Exposed API documentation - lists all endpoints."""
    return send_file('static/swagger.json', mimetype='application/json')


@app.route('/api/docs')
def api_docs():
    """Alternative API docs endpoint."""
    return send_file('static/api_docs.html')


@app.route('/v1/GetConfig', methods=['GET'])
def get_config():
    """Returns service configuration (requires auth)."""
    auth_result, error = validate_jwt(request.headers.get('Authorization'))
    if error:
        return jsonify({"error": error, "status": "unauthorized"}), 401

    if auth_result['user']['role'] != 'Admin':
        return jsonify({"error": "Insufficient permissions. Admin role required."}), 403

    return jsonify({
        "service": "Kronos Analytics Engine",
        "version": "4.2.1",
        "environment": "production",
        "features": {
            "rawQueryExecution": True,
            "crossTenantAccess": False,
            "auditLogging": True,
        },
        "routing_targets_active": len([t for t in VALID_TARGETS if not any(x in t for x in ['Legacy', 'Decom', 'Retired', 'Obsolete', 'Deprecated', 'EndOfLife', 'Sunset', 'Archived', 'Removed', 'Old', 'Sandbox', 'Migration', 'Temp', 'Test', 'Demo', 'POC'])]),
        "routing_targets_total": len(VALID_TARGETS),
    })


@app.route('/v1/GetTables', methods=['GET'])
def get_tables():
    """Lists tables for a given routing target (requires auth)."""
    auth_result, error = validate_jwt(request.headers.get('Authorization'))
    if error:
        return jsonify({"error": error, "status": "unauthorized"}), 401

    target = request.args.get('routingTarget')
    if not target:
        return jsonify({"error": "Missing required parameter: routingTarget"}), 400

    if target not in VALID_TARGETS:
        return jsonify({"error": f"Unknown routing target: {target}"}), 404

    # Check if target is decommissioned
    decom_keywords = ['Legacy', 'Decom', 'Retired', 'Obsolete', 'Deprecated',
                      'EndOfLife', 'Sunset', 'Archived', 'Removed', 'Old',
                      'Sandbox', 'Migration', 'Temp', 'Demo', 'POC']
    if any(kw in target for kw in decom_keywords):
        return jsonify({"target": target, "status": "decommissioned", "tables": []}), 200

    try:
        db = get_db(readonly=True)
        cursor = db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row['name'] for row in cursor.fetchall()]
        db.close()
        return jsonify({"target": target, "tables": tables})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/v2/Query', methods=['POST'])
def query():
    """Execute raw SQL query against a routing target (requires auth + admin)."""
    auth_result, error = validate_jwt(request.headers.get('Authorization'))
    if error:
        return jsonify({"error": error, "status": "unauthorized"}), 401

    if auth_result['user']['role'] != 'Admin':
        return jsonify({
            "error": "Insufficient permissions. Admin role required for raw query execution.",
            "your_role": auth_result['user']['role'],
        }), 403

    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    routing_target = data.get('routingTarget')
    sql_query = data.get('query')

    if not routing_target:
        return jsonify({"error": "Missing required field: routingTarget"}), 400
    if not sql_query:
        return jsonify({"error": "Missing required field: query"}), 400

    if routing_target not in VALID_TARGETS:
        return jsonify({"error": f"Unknown routing target: {routing_target}"}), 404

    # Check if decommissioned
    decom_keywords = ['Legacy', 'Decom', 'Retired', 'Obsolete', 'Deprecated',
                      'EndOfLife', 'Sunset', 'Archived', 'Removed', 'Old',
                      'Sandbox', 'Migration', 'Temp', 'Demo', 'POC']
    if any(kw in routing_target for kw in decom_keywords):
        return jsonify({"target": routing_target, "status": "decommissioned", "results": []}), 200

    # Only allow SELECT statements (read-only enforcement)
    normalized = sql_query.strip().upper()
    if not normalized.startswith('SELECT'):
        return jsonify({"error": "Only SELECT queries are permitted on this endpoint."}), 403

    try:
        db = get_db(readonly=True)
        cursor = db.execute(sql_query)
        columns = [description[0] for description in cursor.description] if cursor.description else []
        rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
        db.close()
        return jsonify({
            "target": routing_target,
            "query": sql_query,
            "columns": columns,
            "results": rows,
            "row_count": len(rows),
        })
    except Exception as e:
        return jsonify({"error": f"Query execution failed: {str(e)}"}), 500


@app.route('/v1/Insert', methods=['POST'])
def insert():
    """Insert endpoint (requires auth + admin) - disabled in production."""
    auth_result, error = validate_jwt(request.headers.get('Authorization'))
    if error:
        return jsonify({"error": error, "status": "unauthorized"}), 401

    if auth_result['user']['role'] != 'Admin':
        return jsonify({"error": "Insufficient permissions. Admin role required."}), 403

    return jsonify({
        "error": "INSERT operations are temporarily disabled in production.",
        "status": "service_unavailable",
        "ticket": "OPS-4821: Awaiting DBA approval for write-path re-enablement",
    }), 503


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
