import pathlib

p = pathlib.Path("internal/conformance/catalog_oidc_pending.go")
s = p.read_text()

old = '''		AssertHeaders: []string{"Content-Type", "Cache-Control"},
	},
	{
		ID: "oidc/authorization/prompt-none-no-session",'''
new = '''		AssertHeaders:   []string{"Content-Type", "Cache-Control"},
		VolatileHeaders: []string{"Set-Cookie"},
	},
	{
		ID: "oidc/authorization/prompt-none-no-session",'''
assert old in s
s = s.replace(old, new)

old = '''		AssertHeaders: []string{"Location", "Cache-Control"},
		// Measured: this redirect is the one response in the whole browser'''
new = '''		AssertHeaders: []string{"Location", "Cache-Control"},
		// AUTH_SESSION_ID and KC_AUTH_SESSION_HASH are minted per request. The
		// attributes on them are contract and are recorded in the observed
		// spec rather than here; nothing asserts this header either way, and
		// left unmasked it churns the golden on every recording.
		VolatileHeaders: []string{"Set-Cookie"},
		// Measured: this redirect is the one response in the whole browser'''
assert old in s
s = s.replace(old, new)

old = '''		AssertHeaders: []string{"Location", "Cache-Control"},
		// The same omission the authorization endpoint's redirect has.'''
new = '''		AssertHeaders: []string{"Location", "Cache-Control"},
		// A fresh AUTH_SESSION_ID, plus KEYCLOAK_IDENTITY and KEYCLOAK_SESSION
		// cleared with Max-Age=0. Per-request, so masked.
		VolatileHeaders: []string{"Set-Cookie"},
		// The same omission the authorization endpoint's redirect has.'''
assert old in s
s = s.replace(old, new)

p.write_text(s)
print("ok")
