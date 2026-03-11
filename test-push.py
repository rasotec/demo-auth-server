#!/usr/bin/env python3
import sys
import sqlite3
import hmac
import hashlib
import time
import json
import urllib.parse
import urllib.request
from pathlib import Path

def usage():
    print(f"Usage: {sys.argv[0]} <otpauth-url> <otp>", file=sys.stderr)
    sys.exit(1)

if len(sys.argv) != 3:
    usage()

url, otp = sys.argv[1], sys.argv[2]

# ── Parse the otpauth:// URL ──────────────────────────────────────────────────

path, _, query = url.split("://", 1)[1].partition("?")
account = urllib.parse.unquote(path.split("/")[-1]).split(":", 1)[-1]
params = dict(urllib.parse.parse_qsl(query))

action = params.get("action", "setup")
if action != "login":
    print(f"Error: action={action!r}, expected action=login", file=sys.stderr)
    sys.exit(1)

session_id = params["session"]
endpoint   = params["endpoint"]
expires    = int(params["expires"])
qr_hmac    = params["hmac"]
issuer     = params.get("issuer", "")

print(f"Account  : {account}")
print(f"Session  : {session_id}")
print(f"Endpoint : {endpoint}")

# ── Look up TOTP secret from database ────────────────────────────────────────

db_path = Path(__file__).parent / "auth.db"
con = sqlite3.connect(db_path)
row = con.execute(
    "SELECT totp_secret FROM users WHERE username = ? AND totp_enabled = 1",
    (account,),
).fetchone()
con.close()

if not row:
    print(f"Error: no active 2FA found for user {account!r} in {db_path}", file=sys.stderr)
    sys.exit(1)

secret = row[0]

# ── Check session expiry ──────────────────────────────────────────────────────

now = int(time.time())
if expires <= now:
    print(f"Error: session expired {now - expires}s ago", file=sys.stderr)
    sys.exit(1)

print(f"Expires  : in {expires - now}s")

# ── Verify HMAC ───────────────────────────────────────────────────────────────

message = "\n".join([account, issuer, endpoint, str(expires), session_id]).encode()
computed_hmac = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()

print(f"HMAC     : {computed_hmac}")

if not hmac.compare_digest(computed_hmac, qr_hmac):
    print("Error: HMAC mismatch — QR code may have been tampered with", file=sys.stderr)
    print(f"  expected : {qr_hmac}", file=sys.stderr)
    print(f"  computed : {computed_hmac}", file=sys.stderr)
    sys.exit(1)

print("HMAC     : OK")

# ── Send push request ─────────────────────────────────────────────────────────

payload = json.dumps({
    "version": "1",
    "session": session_id,
    "account": account,
    "otp":     otp,
}).encode()

print(f"\nPOST {endpoint}")

req = urllib.request.Request(
    endpoint,
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)

try:
    with urllib.request.urlopen(req) as resp:
        body = resp.read().decode()
        print(f"Response : HTTP {resp.status} — {body}")
except urllib.error.HTTPError as e:
    body = e.read().decode()
    print(f"Response : HTTP {e.code} — {body}", file=sys.stderr)
    sys.exit(1)
