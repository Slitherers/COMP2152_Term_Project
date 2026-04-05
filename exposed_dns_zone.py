#  Author: Ifrad Hossain 101587843
#  Vulnerability: DNS Zone Transfer Leak
#  Target: dns.0x10.cloud
'''
This script checks for a DNS Zone Transfer vulnerability on dns.0x10.cloud.
It attempts to read the exposed zone file which lists all internal and external DNS records.
Allowing public AXFR requests is a significant security risk.
It exposes the entire network infrastructure, including hidden internal subdomains and IP addresses to attackers.
'''

import urllib.request
import urllib.error
import time

target_url = "https://dns.0x10.cloud/zone"
print("=" * 50)
print("Checking for DNS Zone Transfer Vulnerability")
print("=" * 50)
print(f"\n  Target: {target_url}")
print("  Scanning...")

time.sleep(0.15)

try:
    response = urllib.request.urlopen(target_url, timeout=5)
    
    if response.status == 200:
        content = response.read().decode('utf-8', errors='ignore')
        
        # Searching for keywords that indicate an AXFR leak or an exposed internal machine
        if "Zone transfer (AXFR)" in content or "db-master" in content:
            print("CRITICAL VULNERABILITY FOUND")
            print("Successfully accessed DNS Zone File information.")
            print("Security Risk: DNS Zone Transfer (AXFR) is publicly enabled.")
            print("This exposes internal infrastructure like 'db-master', 'vault', and 'internal', giving attackers a map of the network.")
            print("\n  --- Network Infrastructure Revealed ---")
            
            lines = content.split('\n')
            amount_to_show = 6
            found_count = 0
            
            print("  [Internal Domain Leaks]")
            for line in lines:
                if "10.0.1." in line and found_count < amount_to_show:
                    parts = line.split()
                    if len(parts) >= 2:
                        print(f"  Domain: {parts[0]:<25} Internal IP: {parts[-1]}")
                        found_count += 1
                        
            print("  ... (truncated for security) ...")
        else:
            print("[OK] DNS Zone File not found or AXFR restricted.")

except urllib.error.HTTPError as e:
    print(f"\n  [OK] Server denied access. HTTP Status: {e.code}")
except Exception as e:
    print(f"\n  [ERROR] Could not connect or retrieve data: {e}")

print("\n" + "=" * 50)
