"""P3 probe 8: pinning the header split. Which 302s carry X-Frame-Options and
Content-Security-Policy, and what the realm declares."""

import json
import os
import sys
import urllib.parse

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import kc

REDIRECT = "http://localhost:9999/callback"
AUTH = "/realms/master/protocol/openid-connect/auth"
SEC = ["Referrer-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
       "X-Frame-Options", "X-Robots-Tag", "Content-Security-Policy"]

tok = kc.admin_token()
st, hd, bd = kc.curl("GET", "/admin/realms/master",
                     headers={"Authorization": f"Bearer {tok}"})
print("\n### the realm's browserSecurityHeaders")
print(json.dumps(json.loads(bd)["browserSecurityHeaders"], indent=1))


def line(label, hd, st):
    have = [h for h in SEC if kc.get_header(hd, h)]
    print(f"  {label:52s} {st}  " +
          "".join("Y" if h in have else "." for h in SEC))


print("\n  columns: Referrer-Policy / HSTS / X-Content-Type-Options / "
      "X-Frame-Options / X-Robots-Tag / Content-Security-Policy")

# /auth error redirect
st, hd, bd = kc.curl("GET", AUTH, query={
    "client_id": "gloak-probe-browser", "redirect_uri": REDIRECT, "scope": "openid"})
line("GET /auth 302 error redirect", hd, st)

# /auth login page
jar = "/tmp/p3-jar-hdr.txt"
if os.path.exists(jar):
    os.remove(jar)
st, hd, bd = kc.curl("GET", AUTH, query={
    "response_type": "code", "client_id": "gloak-probe-browser",
    "redirect_uri": REDIRECT, "scope": "openid", "state": "xyz123"}, jar=jar)
line("GET /auth 200 login page", hd, st)

f = kc.parse_form(bd)
a = urllib.parse.urlparse(f.action)
fl = {n: (v or "") for n, t, v in f.inputs if n}
fl.update({"username": "admin", "password": "admin"})
st, hd, bd = kc.curl("POST", a.path + "?" + a.query, form=fl, jar=jar)
line("POST /login-actions/authenticate 302 success", hd, st)

# replay the same login POST: an error 302 out of login-actions
st, hd, bd = kc.curl("POST", a.path + "?" + a.query, form=fl, jar=jar)
loc = kc.get_header(hd, "Location")
line("POST /login-actions/authenticate 302 error", hd, st)
print(f"     -> {loc[0] if loc else ''}")

# wrong password: a 200 page out of login-actions
jar2 = "/tmp/p3-jar-hdr2.txt"
if os.path.exists(jar2):
    os.remove(jar2)
st, hd, bd = kc.curl("GET", AUTH, query={
    "response_type": "code", "client_id": "gloak-probe-browser",
    "redirect_uri": REDIRECT, "scope": "openid", "state": "xyz123"}, jar=jar2)
f = kc.parse_form(bd)
a = urllib.parse.urlparse(f.action)
fl = {n: (v or "") for n, t, v in f.inputs if n}
fl.update({"username": "admin", "password": "wrong"})
st, hd, bd = kc.curl("POST", a.path + "?" + a.query, form=fl, jar=jar2)
line("POST /login-actions/authenticate 200 wrong password", hd, st)

# the 400 pages
st, hd, bd = kc.curl("GET", AUTH, query={
    "response_type": "code", "client_id": "gloak-probe-browser",
    "redirect_uri": "https://evil.example/x", "scope": "openid"})
line("GET /auth 400 invalid redirect_uri page", hd, st)

# for contrast, the token endpoint
st, hd, bd = kc.curl("POST", "/realms/master/protocol/openid-connect/token",
                     form={"grant_type": "authorization_code",
                           "client_id": "gloak-probe-browser",
                           "redirect_uri": REDIRECT, "code": "nope"})
line("POST /token 400", hd, st)
