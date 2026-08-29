"""P3 probe 3: a recorder-controlled client, and every error shape.

The 2026-08-22 spec says no literal redirect_uri can match the recorder's
container. Probe 2 confirmed that for security-admin-console, whose registered
pattern is host-relative. This probe tests the escape the spec proposed:
register a client whose redirect pattern is an absolute literal the catalogue
chooses. Nothing ever follows the redirect, so the URI need not be reachable.
"""

import base64
import hashlib
import json
import os
import sys
import urllib.parse

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import kc

REDIRECT = "http://localhost:9999/callback"
SEC = ["Referrer-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
       "X-Frame-Options", "X-Robots-Tag"]

tok = kc.admin_token()
auth = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}


def ensure_client(client_id, extra):
    body = {"clientId": client_id, "enabled": True, "publicClient": True,
            "standardFlowEnabled": True, "redirectUris": [REDIRECT],
            "webOrigins": ["*"]}
    body.update(extra)
    st, hd, bd = kc.curl("POST", "/admin/realms/master/clients",
                         headers=auth, body=json.dumps(body))
    print(f"  create {client_id}: {st}")
    return client_id


# A public client with no PKCE policy, and one pinned to plain.
ensure_client("gloak-probe-browser", {})
ensure_client("gloak-probe-browser-plain",
              {"attributes": {"pkce.code.challenge.method": "plain"}})
ensure_client("gloak-probe-browser-conf",
              {"publicClient": False, "secret": "gloak-probe-secret"})

# What are security-admin-console's attributes? Probe 2 measured a lightweight
# access token claim set from it, which is not what a normal client issues.
st, hd, bd = kc.curl("GET", "/admin/realms/master/clients",
                     query={"clientId": "security-admin-console"},
                     headers={"Authorization": f"Bearer {tok}"})
print("\n### security-admin-console attributes")
print(json.dumps(json.loads(bd)[0].get("attributes"), indent=1))


def authorize(**over):
    q = {"response_type": "code", "client_id": "gloak-probe-browser",
         "redirect_uri": REDIRECT, "scope": "openid", "state": "xyz123"}
    q.update(over)
    q = {k: v for k, v in q.items() if v is not None}
    return kc.curl("GET", "/realms/master/protocol/openid-connect/auth", query=q)


def report(label, st, hd, bd, *, show_body=True):
    print(f"\n### {label}")
    print(f"  status: {st}")
    loc = kc.get_header(hd, "Location")
    if loc:
        p = urllib.parse.urlparse(loc[0])
        print(f"  Location base: {p.scheme}://{p.netloc}{p.path}")
        print(f"  Location query: {p.query}")
        print(f"  Location fragment: {p.fragment}")
    ct = kc.get_header(hd, "Content-Type")
    print(f"  Content-Type: {ct}")
    print(f"  Cache-Control: {kc.get_header(hd, 'Cache-Control')}")
    print(f"  Content-Security-Policy: {kc.get_header(hd, 'Content-Security-Policy')}")
    present = [h for h in SEC if kc.get_header(hd, h)]
    print(f"  security headers present: {present}")
    print(f"  security headers absent:  {[h for h in SEC if h not in present]}")
    print(f"  body length: {len(bd)}")
    if show_body and len(bd) < 300:
        print(f"  body: {bd}")
    elif show_body and "<title>" in bd:
        import re
        print(f"  title: {re.findall(r'<title>(.*?)</title>', bd, re.S)}")
        print(f"  message: {re.findall(r'kc-content-wrapper.*?</div>', bd, re.S)[:1]}")


print("\n## A. The authorization endpoint's error shapes")
report("no response_type", *authorize(response_type=None))
report("unsupported response_type=foo", *authorize(response_type="foo"))
report("response_type=token (implicit, flow disabled)", *authorize(response_type="token"))
report("unsupported scope", *authorize(scope="openid nosuchscope"))
report("bad redirect_uri", *authorize(redirect_uri="https://evil.example/callback"))
report("no redirect_uri at all", *authorize(redirect_uri=None))
report("unknown client_id", *authorize(client_id="nosuchclient"))
report("prompt=none, no session", *authorize(prompt="none"))
report("response_mode=fragment, prompt=none", *authorize(prompt="none", response_mode="fragment"))
report("response_mode=form_post, prompt=none", *authorize(prompt="none", response_mode="form_post"))
report("response_mode=query, prompt=none", *authorize(prompt="none", response_mode="query"))
report("no client_id", *authorize(client_id=None))
report("code_challenge_method=S256, no code_challenge", *authorize(code_challenge_method="S256"))
report("code_challenge_method=bogus", *authorize(code_challenge="abc", code_challenge_method="bogus"))
report("unknown realm", *kc.curl("GET", "/realms/nosuchrealm/protocol/openid-connect/auth",
                                 query={"response_type": "code", "client_id": "gloak-probe-browser",
                                        "redirect_uri": REDIRECT}))
report("POST /auth (the endpoint also accepts POST?)",
       *kc.curl("POST", "/realms/master/protocol/openid-connect/auth",
                form={"response_type": "code", "client_id": "gloak-probe-browser",
                      "redirect_uri": REDIRECT, "scope": "openid", "state": "xyz123"}))
report("disabled-flow client (admin-cli, standard flow off)",
       *authorize(client_id="admin-cli", redirect_uri="http://localhost:9999/callback"))
