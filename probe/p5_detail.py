"""P3 probe 5: does the error page churn, what is the code's third part, and
what the golden would have to pin."""

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
AUTH = "/realms/master/protocol/openid-connect/auth"
TOKEN = "/realms/master/protocol/openid-connect/token"

tok = kc.admin_token()
auth = {"Authorization": f"Bearer {tok}"}

st, hd, bd = kc.curl("GET", "/admin/realms/master/clients",
                     query={"clientId": "gloak-probe-browser"}, headers=auth)
uuid = json.loads(bd)[0]["id"]
print(f"\n### gloak-probe-browser internal UUID: {uuid}")

print("\n## H. is the 400 error page stable within one container?")
bodies = []
for _ in range(2):
    st, hd, bd = kc.curl("GET", AUTH, query={
        "response_type": "code", "client_id": "gloak-probe-browser",
        "redirect_uri": "https://evil.example/callback", "scope": "openid"})
    bodies.append(bd)
print(f"  two recordings identical: {bodies[0] == bodies[1]}  ({len(bodies[0])} bytes)")
print(f"  resource hashes in the page: {sorted(set(re.findall(r'/resources/([a-z0-9]+)/', bodies[0])))}")
print(f"  message: {re.findall(r'id=\"kc-page-title\">(.*?)<', bodies[0], re.S)}")
print(f"  <p .*?instruction.*?>: {re.findall(r'<p[^>]*>(.*?)</p>', bodies[0], re.S)[:3]}")
open("/tmp/p3-error-page.html", "w").write(bodies[0])

print("\n## I. each 400's distinguishing text")
for label, over in [("bad redirect_uri", {"redirect_uri": "https://evil.example/callback"}),
                    ("no redirect_uri", {"redirect_uri": None}),
                    ("unknown client_id", {"client_id": "nosuchclient"}),
                    ("no client_id", {"client_id": None}),
                    ("standard flow disabled", {"client_id": "admin-cli"})]:
    q = {"response_type": "code", "client_id": "gloak-probe-browser",
         "redirect_uri": REDIRECT, "scope": "openid", "state": "xyz123"}
    q.update(over)
    q = {k: v for k, v in q.items() if v is not None}
    st, hd, bd = kc.curl("GET", AUTH, query=q)
    title = re.findall(r'id="kc-page-title">(.*?)</h1>', bd, re.S)
    print(f"  {label}: {st} {len(bd)}B title={[t.strip() for t in title]}")

print("\n## J. the code's third part against the client UUID")
jar = "/tmp/p3-jar-uuid.txt"
if os.path.exists(jar):
    os.remove(jar)
st, hd, bd = kc.curl("GET", AUTH, query={
    "response_type": "code", "client_id": "gloak-probe-browser",
    "redirect_uri": REDIRECT, "scope": "openid", "state": "xyz123"}, jar=jar)
f = kc.parse_form(bd)
a = urllib.parse.urlparse(f.action)
fl = {n: (v or "") for n, t, v in f.inputs if n}
fl.update({"username": "admin", "password": "admin"})
st, hd, bd = kc.curl("POST", a.path + "?" + a.query, form=fl, jar=jar)
loc = kc.get_header(hd, "Location")[0]
q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
code = q["code"][0]
parts = code.split(".")
print(f"  code parts: {parts}")
print(f"  part[1] == session_state: {parts[1] == q['session_state'][0]}")
print(f"  part[2] == client UUID:   {parts[2] == uuid}")

print("\n## K. no state, no scope, no nonce")
for label, over in [("no state", {"state": None}),
                    ("no scope", {"scope": None}),
                    ("scope without openid", {"scope": "profile"})]:
    j = f"/tmp/p3-jar-{os.urandom(3).hex()}.txt"
    qq = {"response_type": "code", "client_id": "gloak-probe-browser",
          "redirect_uri": REDIRECT, "scope": "openid", "state": "xyz123"}
    qq.update(over)
    qq = {k: v for k, v in qq.items() if v is not None}
    st, hd, bd = kc.curl("GET", AUTH, query=qq, jar=j)
    if st != 200:
        print(f"  {label}: {st} {kc.get_header(hd, 'Location')}")
        continue
    ff = kc.parse_form(bd)
    aa = urllib.parse.urlparse(ff.action)
    fll = {n: (v or "") for n, t, v in ff.inputs if n}
    fll.update({"username": "admin", "password": "admin"})
    st, hd, bd = kc.curl("POST", aa.path + "?" + aa.query, form=fll, jar=j)
    L = kc.get_header(hd, "Location")[0]
    print(f"  {label}: {st} query keys = {[p.split('=')[0] for p in urllib.parse.urlparse(L).query.split('&')]}")

print("\n## L. a confidential client's code exchange, and its access token claims")
jar = "/tmp/p3-jar-conf.txt"
if os.path.exists(jar):
    os.remove(jar)
st, hd, bd = kc.curl("GET", AUTH, query={
    "response_type": "code", "client_id": "gloak-probe-browser-conf",
    "redirect_uri": REDIRECT, "scope": "openid", "state": "xyz123"}, jar=jar)
f = kc.parse_form(bd)
a = urllib.parse.urlparse(f.action)
fl = {n: (v or "") for n, t, v in f.inputs if n}
fl.update({"username": "admin", "password": "admin"})
st, hd, bd = kc.curl("POST", a.path + "?" + a.query, form=fl, jar=jar)
code = urllib.parse.parse_qs(urllib.parse.urlparse(kc.get_header(hd, "Location")[0]).query)["code"][0]

st, hd, bd = kc.curl("POST", TOKEN, form={
    "grant_type": "authorization_code", "client_id": "gloak-probe-browser-conf",
    "redirect_uri": REDIRECT, "code": code})
print(f"  no secret: {st} {bd[:200]}")

st, hd, bd = kc.curl("POST", TOKEN, form={
    "grant_type": "authorization_code", "client_id": "gloak-probe-browser-conf",
    "client_secret": "gloak-probe-secret", "redirect_uri": REDIRECT, "code": code})
print(f"  with the secret: {st}")
if st == 200:
    doc = json.loads(bd)
    print(f"  keys: {list(doc.keys())}")
    print(f"  scope: {doc['scope']!r}")
    for name in ("access_token", "id_token", "refresh_token"):
        p = doc[name].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        print(f"  {name} claims: {list(claims.keys())}")
        if name == "access_token":
            print(f"    aud={claims.get('aud')!r} typ={claims.get('typ')!r} "
                  f"azp={claims.get('azp')!r} acr={claims.get('acr')!r} "
                  f"allowed-origins={claims.get('allowed-origins')!r}")

print("\n## M. the public client's own access token claim set")
jar = "/tmp/p3-jar-pub.txt"
if os.path.exists(jar):
    os.remove(jar)
st, hd, bd = kc.curl("GET", AUTH, query={
    "response_type": "code", "client_id": "gloak-probe-browser",
    "redirect_uri": REDIRECT, "scope": "openid", "state": "xyz123",
    "nonce": "n-0S6_WzA2Mj"}, jar=jar)
f = kc.parse_form(bd)
a = urllib.parse.urlparse(f.action)
fl = {n: (v or "") for n, t, v in f.inputs if n}
fl.update({"username": "admin", "password": "admin"})
st, hd, bd = kc.curl("POST", a.path + "?" + a.query, form=fl, jar=jar)
code = urllib.parse.parse_qs(urllib.parse.urlparse(kc.get_header(hd, "Location")[0]).query)["code"][0]
st, hd, bd = kc.curl("POST", TOKEN, form={
    "grant_type": "authorization_code", "client_id": "gloak-probe-browser",
    "redirect_uri": REDIRECT, "code": code})
doc = json.loads(bd)
for name in ("access_token", "id_token", "refresh_token"):
    p = doc[name].split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    print(f"  {name} claims: {list(claims.keys())}")
