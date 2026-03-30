# ============================================================
#  EXAMPLE 1: Check if a website uses HTTPS
#  Target: blog.0x10.cloud
#  Author: Instructor (starter example)
# ============================================================
#
#  Many websites should use HTTPS to encrypt data in transit.
#  If a site only uses HTTP, any data sent (including passwords)
#  can be intercepted by anyone on the same network.
#
#  This script checks whether a subdomain redirects to HTTPS
#  or stays on plain HTTP.
# ============================================================

import urllib.request

target = "http://blog.0x10.cloud"

print("=" * 50)
print("  HTTPS Check")
print("=" * 50)

try:
    response = urllib.request.urlopen(target)
    final_url = response.url
    status = response.status

    print(f"\n  Target:     {target}")
    print(f"  Status:     {status}")
    print(f"  Final URL:  {final_url}")

    if final_url.startswith("http://"):
        print("\n  [!] VULNERABILITY FOUND")
        print("  This site does not use HTTPS.")
        print("  Credentials and data are sent in cleartext.")
        print("  An attacker on the same network could intercept them.")
    else:
        print("\n  [OK] This site uses HTTPS. Data is encrypted.")

except Exception as e:
    print(f"\n  [ERROR] Could not connect: {e}")

print("\n" + "=" * 50)
