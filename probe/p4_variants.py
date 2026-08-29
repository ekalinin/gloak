"""P3 probe 4: PKCE, the login POST, response modes carrying a real code,
and every token-endpoint rejection of an authorization code."""

import base64
import hashlib
import json
import os
import re
import sys
import urllib.parse

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import kc

REDIRECT = "http://localhost:9999/callback"
SEC = ["Referrer-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
       "X-Frame-Options", "X-Robots-Tag"]
AUTH = "/realms/master/protocol/openid-connect/auth"
TOKEN = "/realms/master/protocol/openid-connect/token"


def pkce():
    v = base64.urlsafe_b64encode(os.urandom(48)).decode().rstrip("=")
    c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip("=")
    return v, c


def login(jar, client_id="gloak-probe-browser", **over):
    """GET /auth, parse the form, POST credentials. Returns the final response."""
    q = {"response_type": "code", "client_id": client_id,
         "redirect_uri": REDIRECT, "scope": "openid", "state": "xyz123"}
    q.update(over)
    q = {k: v for k, v in q.items() if v is not None}
    st, hd, bd = kc.curl("GET", AUTH, query=q, jar=jar)
    if st != 200:
        return st, hd, bd, None
    f = kc.parse_form(bd)
    a = urllib.parse.urlparse(f.action)
    fields = {n: (v or "") for n, t, v in f.inputs if n}
    return a, f, bd, jar


def submit(a, fields, jar):
    return kc.curl("POST", a.path + ("?" + a.query if a.query else ""),
                   form=fields, jar=jar)


def hdrs(label, st, hd, bd, limit=400):
    print(f"\n### {label}")
    print(f"  status: {st}")
    for name in ("Location", "Content-Type", "Cache-Control", "Content-Security-Policy", "Pragma"):
        v = kc.get_header(hd, name)
        if v:
            print(f"  {name}: {v[0][:400]}")
    present = [h for h in SEC if kc.get_header(hd, h)]
    print(f"  security headers: present={present} absent={[h for h in SEC if h not in present]}")
    for c in kc.get_header(hd, "Set-Cookie"):
        print(f"  Set-Cookie: {kc._mask_arg(c)[:220]}")
    if len(bd) < limit:
        print(f"  body: {bd}")
    else:
        print(f"  body length: {len(bd)}")


def code_from(hd):
    loc = kc.get_header(hd, "Location")[0]
    p = urllib.parse.urlparse(loc)
    q = urllib.parse.parse_qs(p.query or p.fragment)
    return q.get("code", [None])[0], loc


print("\n## B. PKCE")
for client, method in [("gloak-probe-browser", "plain"),
                       ("gloak-probe-browser", "S256"),
                       ("gloak-probe-browser-plain", "S256"),
                       ("gloak-probe-browser-plain", "plain")]:
    v, c = pkce()
    challenge = v if method == "plain" else c
    st, hd, bd = kc.curl("GET", AUTH, query={
        "response_type": "code", "client_id": client, "redirect_uri": REDIRECT,
        "scope": "openid", "state": "xyz123",
        "code_challenge": challenge, "code_challenge_method": method})
    loc = kc.get_header(hd, "Location")
    print(f"  client={client} method={method} -> {st} {loc[0] if loc else '(login page)'}")

# A real plain-PKCE login, then exchange with the right and the wrong verifier.
print("\n## C. plain PKCE end to end")
jar = "/tmp/p3-jar-plain.txt"
if os.path.exists(jar):
    os.remove(jar)
v, _ = pkce()
a, f, bd, _ = login(jar, code_challenge=v, code_challenge_method="plain")
fields = {n: (val or "") for n, t, val in f.inputs if n}
fields.update({"username": "admin", "password": "admin"})
st, hd, bd = submit(a, fields, jar)
code, loc = code_from(hd)
print(f"  Location: {loc}")
st, hd, bd = kc.curl("POST", TOKEN, form={
    "grant_type": "authorization_code", "client_id": "gloak-probe-browser",
    "redirect_uri": REDIRECT, "code": code, "code_verifier": v})
hdrs("exchange with the plain verifier", st, hd, bd, limit=0)
print(f"  keys: {list(json.loads(bd).keys()) if st == 200 else bd}")

print("\n## D. the S256 verifier mismatch, and the other token rejections")
jar = "/tmp/p3-jar-mm.txt"
if os.path.exists(jar):
    os.remove(jar)
v, c = pkce()
a, f, bd, _ = login(jar, code_challenge=c, code_challenge_method="S256")
fields = {n: (val or "") for n, t, val in f.inputs if n}
fields.update({"username": "admin", "password": "admin"})
st, hd, bd = submit(a, fields, jar)
code, loc = code_from(hd)
other, _ = pkce()
st, hd, bd = kc.curl("POST", TOKEN, form={
    "grant_type": "authorization_code", "client_id": "gloak-probe-browser",
    "redirect_uri": REDIRECT, "code": code, "code_verifier": other})
hdrs("verifier mismatch", st, hd, bd)

st, hd, bd = kc.curl("POST", TOKEN, form={
    "grant_type": "authorization_code", "client_id": "gloak-probe-browser",
    "redirect_uri": REDIRECT, "code": code})
hdrs("no code_verifier at all (after the mismatch)", st, hd, bd)


def fresh_code(**over):
    j = f"/tmp/p3-jar-{os.urandom(4).hex()}.txt"
    a, f, bd, _ = login(j, **over)
    fl = {n: (val or "") for n, t, val in f.inputs if n}
    fl.update({"username": "admin", "password": "admin"})
    st, hd, bd = submit(a, fl, j)
    return code_from(hd)[0]


st, hd, bd = kc.curl("POST", TOKEN, form={
    "grant_type": "authorization_code", "client_id": "gloak-probe-browser",
    "redirect_uri": "http://localhost:9999/other", "code": fresh_code()})
hdrs("wrong redirect_uri at the token endpoint", st, hd, bd)

st, hd, bd = kc.curl("POST", TOKEN, form={
    "grant_type": "authorization_code", "client_id": "gloak-probe-browser",
    "code": fresh_code()})
hdrs("no redirect_uri at the token endpoint", st, hd, bd)

st, hd, bd = kc.curl("POST", TOKEN, form={
    "grant_type": "authorization_code", "client_id": "gloak-probe-browser-conf",
    "redirect_uri": REDIRECT, "code": fresh_code()})
hdrs("a code minted for another client", st, hd, bd)

st, hd, bd = kc.curl("POST", TOKEN, form={
    "grant_type": "authorization_code", "client_id": "gloak-probe-browser",
    "redirect_uri": REDIRECT, "code": "not-a-code"})
hdrs("a malformed code", st, hd, bd)

st, hd, bd = kc.curl("POST", TOKEN, form={
    "grant_type": "authorization_code", "client_id": "gloak-probe-browser",
    "redirect_uri": REDIRECT})
hdrs("no code at all", st, hd, bd)

print("\n## E. the login form's own rejections")
jar = "/tmp/p3-jar-wrong.txt"
if os.path.exists(jar):
    os.remove(jar)
a, f, bd, _ = login(jar)
fields = {n: (val or "") for n, t, val in f.inputs if n}
fields.update({"username": "admin", "password": "wrong"})
st, hd, bd = submit(a, fields, jar)
hdrs("wrong password", st, hd, bd, limit=0)
print(f"  error text: {re.findall(r'kc-feedback-text[^>]*>(.*?)<', bd, re.S)}")
f2 = kc.parse_form(bd)
print(f"  re-served form action: {f2.action}")
print(f"  re-served inputs: {f2.inputs}")

print("\n## F. prompt=none WITH a session")
jar = "/tmp/p3-jar-sess.txt"
if os.path.exists(jar):
    os.remove(jar)
a, f, bd, _ = login(jar)
fields = {n: (val or "") for n, t, val in f.inputs if n}
fields.update({"username": "admin", "password": "admin"})
submit(a, fields, jar)
st, hd, bd = kc.curl("GET", AUTH, query={
    "response_type": "code", "client_id": "gloak-probe-browser",
    "redirect_uri": REDIRECT, "scope": "openid", "state": "second",
    "prompt": "none"}, jar=jar)
hdrs("prompt=none with a live session", st, hd, bd)

print("\n## G. response_mode carrying a real code")
for mode in ("query", "fragment", "form_post"):
    j = f"/tmp/p3-jar-{mode}.txt"
    if os.path.exists(j):
        os.remove(j)
    a, f, bd, _ = login(j, response_mode=mode)
    fl = {n: (val or "") for n, t, val in f.inputs if n}
    fl.update({"username": "admin", "password": "admin"})
    st, hd, bd = submit(a, fl, j)
    hdrs(f"login POST, response_mode={mode}", st, hd, bd, limit=1200)
