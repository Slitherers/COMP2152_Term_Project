
# Author: Luis Tello
# Vulnerability Name: Open Port Detection
# Target: admin.0x10.cloud
# Description: This script scans the target subdomain for open ports (22, 21, 23, 25, 6379, 27017, 3306) 
#             to identify potential entry points for attackers.

#[VULNERABILITY FOUND] Port 80 is OPEN on admin.0x10.cloud!
#SECURITY RISK: Port 80 (Service) is exposed.
#Attackers can use this to gain unauthorized access or intercept traffic.

import socket
import time

def check_vulnerability(targets_and_ports):
    """
    Checks for open ports on multiple subdomains and reports security risks.
    """
    print(f"--- Scanning Vulnerabilities for CTF Bug Bounty ---")
    print("Searching for open ports that could expose the server to unauthorized access...\n")

    vulnerabilities_found = 0

    for subdomain, ports in targets_and_ports:
        print(f"Scanning target: {subdomain}...")
        for port in ports:
            try:
                # Create a socket for TCP connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1) # 1-second timeout for each connection attempt

                # result will be 0 if the port is open
                result = sock.connect_ex((subdomain, port))

                if result == 0:
                    vulnerabilities_found += 1
                    service_name = "Telnet" if port == 2323 else "Service"
                    print(f"\n[VULNERABILITY FOUND] Port {port} is OPEN on {subdomain}!")
                    print(f"SECURITY RISK: Port {port} ({service_name}) is exposed.")
                    print(f"Attackers can use this to gain unauthorized access or intercept traffic.\n")
                
                sock.close()

                # Add a small delay (0.15s) between requests to respect the 10 req/s rate limit
                time.sleep(0.15)

            except socket.error as e:
                # Silently skip connection errors for cleaner output
                pass
            except Exception as e:
                print(f"An unexpected error occurred for {subdomain}:{port} -> {e}")

    print("\n--- Scan Summary ---")
    if vulnerabilities_found > 0:
        print(f"Total Critical Vulnerabilities Detected: {vulnerabilities_found}")
    else:
        print("No open ports were detected on the targets scanned.")
    print("--- Vulnerability Scan Completed ---")

if __name__ == "__main__":
    # Targets including common subdomains and non-standard ports
    targets_to_check = [
        ("admin.0x10.cloud", [22, 21, 23, 25, 80]),
        ("telnet.0x10.cloud", [23, 2323]),
        ("ftp.0x10.cloud", [21, 2121]),
        ("smtp.0x10.cloud", [25, 2525]),
        ("redis.0x10.cloud", [6379]),
        ("mongo.0x10.cloud", [27017])
    ]

    # Run the vulnerability check
    check_vulnerability(targets_to_check)