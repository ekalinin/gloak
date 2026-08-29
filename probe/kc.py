"""Probe helper for measuring a live Keycloak 26.7.1.

Every request is issued through run(), which prints the argv it is about to
execute and then executes that same list. The printed line is derived from the
list, never hand-written, so the transcript cannot drift from the request.
Long credential-shaped values are masked in the printed line only.
"""

import html.parser
import json
import re
import subprocess
import sys
import urllib.parse

BASE = "http://localhost:8083"

# Values worth masking in the printed argv: anything that looks like a JWT, and
# whatever the caller registers with mask().
_MASKED = {}


def mask(value, name):
    if value:
        _MASKED[value] = "{{" + name + "}}"


def _mask_arg(a):
    for value, name in _MASKED.items():
        a = a.replace(value, name)
    return re.sub(r"ey[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "{{jwt}}", a)


def run(args):
    """Print the argv, then execute that exact argv. Returns (status, headers, body)."""
    print("$ " + " ".join(_shquote(_mask_arg(a)) for a in args), file=sys.stderr)
    p = subprocess.run(args, capture_output=True)
    head = p.stderr.decode("utf-8", "replace")
    body = p.stdout.decode("utf-8", "replace")
    status, headers = _parse_head(head)
    return status, headers, body


def _shquote(s):
    if re.fullmatch(r"[A-Za-z0-9_@%+=:,./-]+", s or ""):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


def _parse_head(head):
    """Parse curl -D - output. Returns the final response's status and headers."""
    blocks = [b for b in head.split("\r\n\r\n") if b.strip()]
    if not blocks:
        return 0, []
    lines = blocks[-1].split("\r\n")
    status = int(lines[0].split(" ")[1]) if len(lines[0].split(" ")) > 1 else 0
    headers = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
    return status, headers


def curl(method, path, *, query=None, form=None, body=None, headers=None,
         jar=None, base=BASE, follow=False):
    url = base + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    args = ["curl", "-s", "-D", "/dev/stderr", "-o", "/dev/stdout", "-X", method]
    if not follow:
        args.append("--no-location")
    for k, v in (headers or {}).items():
        args += ["-H", f"{k}: {v}"]
    if form is not None:
        for k, v in form.items():
            args += ["--data-urlencode", f"{k}={v}"]
    elif body is not None:
        args += ["-H", "Content-Type: application/json", "--data-binary", body]
    if jar:
        args += ["-b", jar, "-c", jar]
    args.append(url)
    return run(args)


def get_header(headers, name):
    return [v for k, v in headers if k.lower() == name.lower()]


class _FormParser(html.parser.HTMLParser):
    """Finds the first <form> and every <input> inside it."""

    def __init__(self):
        super().__init__()
        self.action = None
        self.method = None
        self.inputs = []
        self._in_form = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and self.action is None:
            self._in_form = True
            self.action = a.get("action")
            self.method = a.get("method")
        elif tag == "input" and self._in_form:
            self.inputs.append((a.get("name"), a.get("type"), a.get("value")))

    def handle_endtag(self, tag):
        if tag == "form":
            self._in_form = False


def parse_form(body):
    p = _FormParser()
    p.feed(body)
    return p


def show(label, status, headers, body, *, only=None, body_limit=600):
    print(f"\n### {label}")
    print(f"status: {status}")
    for k, v in headers:
        if only and k.lower() not in {o.lower() for o in only}:
            continue
        print(f"  {k}: {_mask_arg(v)}")
    if body_limit:
        text = _mask_arg(body)
        print("  body: " + (text[:body_limit] + ("..." if len(text) > body_limit else "")))


def admin_token():
    st, hd, bd = curl("POST", "/realms/master/protocol/openid-connect/token", form={
        "grant_type": "password", "client_id": "admin-cli",
        "username": "admin", "password": "admin",
    })
    tok = json.loads(bd)["access_token"]
    mask(tok, "admin_token")
    return tok
