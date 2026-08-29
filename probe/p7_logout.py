"""P3 probe 7: RP-initiated logout, the other half of P3's scope."""

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
LOGOUT = "/realms/master/protocol/openid-connect/logout"
SEC = ["Referrer-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
       "X-Frame-Options", "X-Robots-Tag"]

tok = kc.admin_token()
auth = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}
kc.curl("PUT", "/admin/realms/master/clients", headers=auth, body="{}")  # no-op, keeps argv honest

# post.logout.redirect.uris has to be registered for the redirect to validate.
st, hd, bd = kc.curl("GET", "/admin/realms/master/clients",
                     query={"clientId": "gloak-probe-browser"},
                     headers={"Authorization": f"Bearer {tok}"})
c = json.loads(bd)[0]
c.setdefault("attributes", {})["post.logout.redirect.uris"] = REDIRECT
kc.curl("PUT", f"/admin/realms/master/clients/{c['id']}", headers=auth, body=json.dumps(c))


def full_login(jar):
    st, hd, bd = kc.curl("GET", AUTH, query={
        "response_type": "code", "client_id": "gloak-probe-browser",
        "redirect_uri": REDIRECT, "scope": "openid", "state": "xyz123"}, jar=jar)
    f = kc.parse_form(bd)
    a = urllib.parse.urlparse(f.action)
    fl = {n: (v or "") for n, t, v in f.inputs if n}
    fl.update({"username": "admin", "password": "admin"})
    st, hd, bd = kc.curl("POST", a.path + "?" + a.query, form=fl, jar=jar)
    code = urllib.parse.parse_qs(urllib.parse.urlparse(kc.get_header(hd, "Location")[0]).query)["code"][0]
    st, hd, bd = kc.curl("POST", TOKEN, form={
        "grant_type": "authorization_code", "client_id": "gloak-probe-browser",
        "redirect_uri": REDIRECT, "code": code})
    return json.loads(bd)


def report(label, st, hd, bd):
    print(f"\n### {label}")
    print(f"  status: {st}")
    for n in ("Location", "Content-Type", "Cache-Control", "Content-Security-Policy"):
        v = kc.get_header(hd, n)
        if v:
            print(f"  {n}: {v[0][:260]}")
    present = [h for h in SEC if kc.get_header(hd, h)]
    print(f"  security headers: present={present} absent={[h for h in SEC if h not in present]}")
    for ck in kc.get_header(hd, "Set-Cookie"):
        print(f"  Set-Cookie: {kc._mask_arg(ck)[:160]}")
    if len(bd) < 400:
        print(f"  body: {bd}")
    else:
        print(f"  body length: {len(bd)}  title={re.findall(r'id=.kc-page-title.>(.*?)<', bd, re.S)}")
        print(f"  paragraphs: {[p.strip()[:120] for p in re.findall(r'<p[^>]*>(.*?)</p>', bd, re.S)][:3]}")


jar = "/tmp/p3-jar-lo1.txt"
if os.path.exists(jar):
    os.remove(jar)
t = full_login(jar)
kc.mask(t["id_token"], "id_token")
report("logout with id_token_hint and post_logout_redirect_uri",
       *kc.curl("GET", LOGOUT, query={"id_token_hint": t["id_token"],
                                      "post_logout_redirect_uri": REDIRECT,
                                      "state": "bye"}, jar=jar))

jar = "/tmp/p3-jar-lo2.txt"
if os.path.exists(jar):
    os.remove(jar)
t = full_login(jar)
report("logout with no id_token_hint, with post_logout_redirect_uri",
       *kc.curl("GET", LOGOUT, query={"post_logout_redirect_uri": REDIRECT,
                                      "client_id": "gloak-probe-browser"}, jar=jar))

jar = "/tmp/p3-jar-lo3.txt"
if os.path.exists(jar):
    os.remove(jar)
t = full_login(jar)
report("logout with nothing at all", *kc.curl("GET", LOGOUT, jar=jar))

jar = "/tmp/p3-jar-lo4.txt"
if os.path.exists(jar):
    os.remove(jar)
t = full_login(jar)
kc.mask(t["id_token"], "id_token2")
report("logout with a bad post_logout_redirect_uri",
       *kc.curl("GET", LOGOUT, query={"id_token_hint": t["id_token"],
                                      "post_logout_redirect_uri": "https://evil.example/x"}, jar=jar))

jar = "/tmp/p3-jar-lo5.txt"
if os.path.exists(jar):
    os.remove(jar)
t = full_login(jar)
kc.mask(t["refresh_token"], "refresh_token")
report("POST /logout with a refresh token (back-channel style)",
       *kc.curl("POST", LOGOUT, form={"client_id": "gloak-probe-browser",
                                      "refresh_token": t["refresh_token"]}))
