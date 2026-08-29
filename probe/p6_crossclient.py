"""P3 probe 6: correcting probe 4's cross-client reading.

Probe 4 exchanged a code at a *confidential* client with no secret and read the
401 as "a code minted for another client is refused". Probe 5 then measured a
confidential client with no secret answering the same 401 for a code that was
its own, so probe 4 measured client authentication, not the code. Redone here
with two public clients, where nothing but the code differs.
"""

import json
import os
import sys
import urllib.parse

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import kc

REDIRECT = "http://localhost:9999/callback"
AUTH = "/realms/master/protocol/openid-connect/auth"
TOKEN = "/realms/master/protocol/openid-connect/token"

tok = kc.admin_token()
auth = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}
kc.curl("POST", "/admin/realms/master/clients", headers=auth, body=json.dumps(
    {"clientId": "gloak-probe-browser-two", "enabled": True, "publicClient": True,
     "standardFlowEnabled": True, "redirectUris": [REDIRECT]}))


def code_for(client_id):
    jar = f"/tmp/p3-jar-{os.urandom(3).hex()}.txt"
    st, hd, bd = kc.curl("GET", AUTH, query={
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT,
        "scope": "openid", "state": "xyz123"}, jar=jar)
    f = kc.parse_form(bd)
    a = urllib.parse.urlparse(f.action)
    fl = {n: (v or "") for n, t, v in f.inputs if n}
    fl.update({"username": "admin", "password": "admin"})
    st, hd, bd = kc.curl("POST", a.path + "?" + a.query, form=fl, jar=jar)
    loc = kc.get_header(hd, "Location")[0]
    return urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["code"][0]


c = code_for("gloak-probe-browser")
st, hd, bd = kc.curl("POST", TOKEN, form={
    "grant_type": "authorization_code", "client_id": "gloak-probe-browser-two",
    "redirect_uri": REDIRECT, "code": c})
print(f"\n### a public client redeeming another public client's code: {st}")
print(f"  {bd}")

# And the control: the same code at the client it was minted for.
c2 = code_for("gloak-probe-browser")
st, hd, bd = kc.curl("POST", TOKEN, form={
    "grant_type": "authorization_code", "client_id": "gloak-probe-browser",
    "redirect_uri": REDIRECT, "code": c2})
print(f"\n### control, the same request at the right client: {st}")

# Replaying the login POST: is session_code single-use?
print("\n### replaying the login form POST with a spent session_code")
jar = "/tmp/p3-jar-replay.txt"
if os.path.exists(jar):
    os.remove(jar)
st, hd, bd = kc.curl("GET", AUTH, query={
    "response_type": "code", "client_id": "gloak-probe-browser",
    "redirect_uri": REDIRECT, "scope": "openid", "state": "xyz123"}, jar=jar)
f = kc.parse_form(bd)
a = urllib.parse.urlparse(f.action)
fl = {n: (v or "") for n, t, v in f.inputs if n}
fl.update({"username": "admin", "password": "admin"})
st1, hd1, _ = kc.curl("POST", a.path + "?" + a.query, form=fl, jar=jar)
st2, hd2, bd2 = kc.curl("POST", a.path + "?" + a.query, form=fl, jar=jar)
print(f"  first POST:  {st1} {kc.get_header(hd1, 'Location')[0][:90] if kc.get_header(hd1,'Location') else ''}")
print(f"  second POST: {st2} {kc.get_header(hd2, 'Location') or kc.get_header(hd2, 'Content-Type')}")
import re
print(f"  second body title: {re.findall(r'id=.kc-page-title.>(.*?)<', bd2, re.S)}")
print(f"  second body instruction: {re.findall(r'<p[^>]*>(.*?)</p>', bd2, re.S)[:2]}")
print(f"  second body length: {len(bd2)}")
