"""P3 probe 1: what the bootstrapped clients allow, and what GET /auth serves."""

import json
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import kc

tok = kc.admin_token()
auth = {"Authorization": f"Bearer {tok}"}

st, hd, bd = kc.curl("GET", "/admin/realms/master/clients", headers=auth)
print("\n### bootstrapped clients: redirect and flow configuration")
for c in json.loads(bd):
    print(json.dumps({
        "clientId": c["clientId"],
        "publicClient": c.get("publicClient"),
        "standardFlowEnabled": c.get("standardFlowEnabled"),
        "directAccessGrantsEnabled": c.get("directAccessGrantsEnabled"),
        "rootUrl": c.get("rootUrl"),
        "baseUrl": c.get("baseUrl"),
        "redirectUris": c.get("redirectUris"),
        "webOrigins": c.get("webOrigins"),
        "attributes.pkce": c.get("attributes", {}).get("pkce.code.challenge.method"),
    }))

# GET /auth on security-admin-console with the console's own redirect_uri.
st, hd, bd = kc.curl("GET", "/realms/master/protocol/openid-connect/auth", query={
    "response_type": "code",
    "client_id": "security-admin-console",
    "redirect_uri": kc.BASE + "/admin/master/console/",
    "scope": "openid",
    "state": "xyz123",
})
kc.show("GET /auth security-admin-console", st, hd, bd, body_limit=0)
print("  all headers:")
for k, v in hd:
    print(f"    {k}: {v}")

f = kc.parse_form(bd)
print(f"\n  form action: {f.action}")
print(f"  form method: {f.method}")
print(f"  form inputs: {f.inputs}")
print(f"  body length: {len(bd)}")
