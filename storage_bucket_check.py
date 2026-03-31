# ============================================================
#  COMP2152 — Term Project: CTF Bug Bounty
#  Target: storage.0x10.cloud
#  Author: Paul Christian Yee
# ============================================================
#
#  VULNERABILITY: Public Bucket Listing (No Authentication)
#
#  I found that this storage bucket lets anyone list its files
#  without needing to log in. This is a misconfiguration,
#  buckets should be private so only authorized people can
#  see what's inside.
#
#  This script:
#  1. Sends a GET request to the storage URL
#  2. Checks if the response is an S3 bucket listing
#  3. Prints whether the bucket is publicly accessible or not
#
#  Technique: urllib to make the request, check for the
#             "ListBucketResult" tag in the XML response
# ============================================================

import urllib.request

TARGET = "https://storage.0x10.cloud/"

print("=" * 50)
print("Open Cloud Storage Bucket Check")
print(f"Target: {TARGET}")
print("=" * 50)

print(f"\nSending unauthenticated GET request...")

try:
    response = urllib.request.urlopen(TARGET, timeout=5)
    body = response.read().decode("utf-8")

    print(f"HTTP Status: {response.status}")

    # Check if the response contains the S3 bucket listing tag
    if "ListBucketResult" in body:
        print("\n[!] VULNERABILITY FOUND")
        print("The storage bucket listing is publicly accessible.")
        print("No authentication was required to list its contents.")
        print("Anyone on the internet can see all files in this bucket.")
        print()
        print("RECOMMENDED FIX:")
        print("Set the bucket access to private so only authorized")
        print("users can view or list the files inside it.")
    else:
        print("\n[OK] Bucket is not publicly listable.")

except Exception as e:
    print(f"\n[ERROR] Could not connect: {e}")

print("\n" + "=" * 50 + "\n")
