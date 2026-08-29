"""P3 probe 2: the browser authorization code flow, end to end, on a live 26.7.1.

Falsification target: the 2026-08-22 P3 spec claims no literal redirect_uri can
match the recorder's container because testcontainers assigns the port at run
time. security-admin-console's redirectUris is the *relative* "/admin/master/console/*",
so this probe sends the catalogue's literal http://localhost:8080/... to a server
answering on 8083 and records what happens.
"""

import base64
import hashlib
import json
import os
import sys
import urllib.parse

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import kc

JAR = "/tmp/p3-jar.txt"
SEC = ["Referrer-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
       "X-Frame-Options", "X-Robots-Tag"]
INTEREST = ["Cache-Control", "Content-Type", "Location", "Set-Cookie", "Content-Length"] + SEC


def verifier_and_challenge():
    v = base64.urlsafe_b64encode(os.urandom(48)).decode().rstrip("=")
    c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip("=")
    return v, c


# --- 1. Does a literal http://localhost:8080/... redirect_uri validate on :8083? ---
print("\n## 1. A literal off-port redirect_uri against a relative redirectUris pattern")
for uri in ["http://localhost:8080/admin/master/console/",
            "http://localhost:8083/admin/master/console/",
            "https://evil.example/callback"]:
    st, hd, bd = kc.curl("GET", "/realms/master/protocol/openid-connect/auth", query={
        "response_type": "code", "client_id": "security-admin-console",
        "redirect_uri": uri, "scope": "openid", "state": "xyz123",
        "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge_method": "S256",
    })
    loc = kc.get_header(hd, "Location")
    print(f"  redirect_uri={uri!r} -> {st} location={loc} bodylen={len(bd)}")


# --- 2. The happy path ---
print("\n## 2. GET /auth -> login form -> POST credentials -> Location carries code")
if os.path.exists(JAR):
    os.remove(JAR)
verifier, challenge = verifier_and_challenge()
print(f"  code_verifier  = {verifier}")
print(f"  code_challenge = {challenge}")

REDIRECT = kc.BASE + "/admin/master/console/"
st, hd, bd = kc.curl("GET", "/realms/master/protocol/openid-connect/auth", query={
    "response_type": "code", "client_id": "security-admin-console",
    "redirect_uri": REDIRECT, "scope": "openid", "state": "xyz123",
    "code_challenge": challenge, "code_challenge_method": "S256",
    "nonce": "n-0S6_WzA2Mj",
}, jar=JAR)
kc.show("GET /auth (200, the login page)", st, hd, bd, only=INTEREST, body_limit=0)
print("  every header, in order:")
for k, v in hd:
    print(f"    {k}: {v}")

f = kc.parse_form(bd)
print(f"\n  form action: {f.action}")
print(f"  form method: {f.method}")
print(f"  form inputs: {f.inputs}")
action = urllib.parse.urlparse(f.action)
print(f"  action path:  {action.path}")
print(f"  action query: {urllib.parse.parse_qs(action.query)}")
print(f"  login page body length: {len(bd)}")

# every form on the page, not just the first
import re as _re
print(f"  forms on the page: {_re.findall(r'<form[^>]*>', bd)}")
print(f"  inputs on the page: {_re.findall(r'<input[^>]*>', bd)}")

# --- 3. POST the credentials ---
fields = {n: (v or "") for n, t, v in f.inputs if n}
fields["username"] = "admin"
fields["password"] = "admin"
st, hd, bd = kc.curl("POST", action.path + ("?" + action.query if action.query else ""),
                     form=fields, jar=JAR)
kc.show("POST the login form", st, hd, bd, only=INTEREST, body_limit=0)
print("  every header, in order:")
for k, v in hd:
    print(f"    {k}: {v}")

loc = kc.get_header(hd, "Location")[0]
q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
print(f"\n  Location: {loc}")
print(f"  Location query keys, in order: {[p.split('=')[0] for p in urllib.parse.urlparse(loc).query.split('&')]}")
code = q["code"][0]
print(f"  code: {code}")
print(f"  code parts: {code.split('.')}")

# --- 4. Exchange the code ---
st, hd, bd = kc.curl("POST", "/realms/master/protocol/openid-connect/token", form={
    "grant_type": "authorization_code", "client_id": "security-admin-console",
    "redirect_uri": REDIRECT, "code": code, "code_verifier": verifier,
})
kc.show("POST /token authorization_code", st, hd, bd, only=INTEREST, body_limit=0)
print("  every header, in order:")
for k, v in hd:
    print(f"    {k}: {v}")
try:
    doc = json.loads(bd)
    print(f"  token response keys, in order: {list(doc.keys())}")
    print(f"  scope: {doc.get('scope')!r}  token_type: {doc.get('token_type')!r}")
    print(f"  expires_in: {doc.get('expires_in')}  refresh_expires_in: {doc.get('refresh_expires_in')}")
    print(f"  not-before-policy: {doc.get('not-before-policy')}")
    for name in ("access_token", "id_token", "refresh_token"):
        if name in doc:
            head, payload, _ = doc[name].split(".")
            pad = "=" * (-len(payload) % 4)
            print(f"  {name} header:  {base64.urlsafe_b64decode(head + '=' * (-len(head) % 4)).decode()}")
            print(f"  {name} claims:  {list(json.loads(base64.urlsafe_b64decode(payload + pad)).keys())}")
    open("/tmp/p3-code.json", "w").write(json.dumps({"code": code, "verifier": verifier}))
except Exception as e:
    print(f"  not JSON: {e}")

# --- 5. Replay the same code ---
st, hd, bd = kc.curl("POST", "/realms/master/protocol/openid-connect/token", form={
    "grant_type": "authorization_code", "client_id": "security-admin-console",
    "redirect_uri": REDIRECT, "code": code, "code_verifier": verifier,
})
kc.show("POST /token, the same code a second time", st, hd, bd, only=INTEREST)
