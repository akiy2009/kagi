"""End-to-end checks for the OIDC features added on top of the core:

  * RFC 8628 Device Authorization Grant (approval, denial, polling, slow_down)
  * OpenID Connect `claims` request parameter (validation and filtering)
  * RFC 7592 Dynamic Client Management (read, update, secret rotation, delete)
  * OpenID Connect Back-Channel Logout (signed logout token delivery)

Start the server with the demo client and a registration token:

    KAGI_SEED_DEMO=1 KAGI_REGISTRATION_TOKEN=reg-secret KAGI_DEVICE_INTERVAL=1 \\
    KAGI_DB=kagi-complete-e2e.db cargo run
    KAGI_DB=kagi-complete-e2e.db KAGI_REGISTRATION_TOKEN=reg-secret \\
    python scripts/e2e_complete_oidc.py

For PostgreSQL / Supabase, seed through psycopg2 instead:

    KAGI_DATABASE_URL=postgresql://... KAGI_REGISTRATION_TOKEN=reg-secret \\
    python scripts/e2e_complete_oidc.py
"""

import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import urllib.parse as up
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as acu

BASE = os.environ.get("KAGI_BASE", "http://localhost:8080")
DB = os.environ.get("KAGI_DB", "kagi-complete-e2e.db")
DATABASE_URL = os.environ.get("KAGI_DATABASE_URL")
DEMO = "demo-web"
DEMO_REDIRECT = "http://localhost:3000/callback"
REG = os.environ.get("KAGI_REGISTRATION_TOKEN")

fails = []
def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {str(detail)[:600]}"))
    if not cond:
        fails.append(name)

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def unb64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

RS = requests.Session()
RS.max_redirects = 1

def req(method, path, data=None, headers=None, base=BASE):
    return RS.request(method, base + path, data=data, headers=dict(headers or {}),
                      allow_redirects=False)

def req3(method, path, data=None, headers=None, base=BASE):
    r = req(method, path, data, headers, base)
    return r.status_code, r.headers, r.content

def form_post(path, data, headers=None):
    r = req("POST", path, data, headers)
    try:
        body = json.loads(r.content)
    except Exception:
        body = None
    return r.status_code, r.headers, body, r.content

def dcr_headers():
    headers = {"Content-Type": "application/json"}
    if REG:
        headers["Authorization"] = "Bearer " + REG
    return headers

def register(body):
    r = req("POST", "/register", json.dumps(body), dcr_headers())
    try:
        parsed = json.loads(r.content)
    except Exception:
        parsed = None
    return r.status_code, parsed, r.content

def pkce():
    verifier = b64u(secrets.token_bytes(48))
    return verifier, b64u(hashlib.sha256(verifier.encode()).digest())

def authorize_code(client_id, redirect_uri, scope, claims=None, prompt=None):
    """PAR -> /authorize -> (consent) and return (code, verifier, detail)."""
    verifier, challenge = pkce()
    params = {
        "client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code",
        "scope": scope, "state": "st-" + secrets.token_hex(4), "nonce": "n-" + secrets.token_hex(4),
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    if claims is not None:
        params["claims"] = claims if isinstance(claims, str) else json.dumps(claims)
    if prompt:
        params["prompt"] = prompt
    s, h, j, b = form_post("/par", params, {"Cookie": SESSION_COOKIE})
    if s != 201 or not j:
        return None, verifier, (s, b)
    r = req("GET", "/authorize?" + up.urlencode({"client_id": client_id, "request_uri": j["request_uri"]}),
            headers={"Cookie": SESSION_COOKIE})
    loc = r.headers.get("Location", "")
    if loc.startswith("/consent?rid="):
        rid = up.parse_qs(up.urlparse(loc).query)["rid"][0]
        page = req("GET", "/consent?rid=" + rid, headers={"Cookie": SESSION_COOKIE}).content.decode()
        inputs = dict(re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page))
        r = req("POST", "/consent",
                {"rid": rid, "csrf": inputs.get("csrf", ""), "decision": "allow"},
                headers={"Cookie": SESSION_COOKIE})
        loc = r.headers.get("Location", "")
    code = up.parse_qs(up.urlparse(loc).query).get("code", [""])[0]
    return code, verifier, (r.status_code, loc)

# ---------------------------------------------------------------- seed session
sid = secrets.token_urlsafe(32)
sid_hash = hashlib.sha256(sid.encode()).hexdigest()
now = int(time.time())
if DATABASE_URL:
    import psycopg2
    con = psycopg2.connect(DATABASE_URL)
    cur = con.cursor()
    cur.execute("""INSERT INTO users (id,username,display_name,email,email_verified,created_at)
                   VALUES (%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (id) DO UPDATE SET username=excluded.username,
                     display_name=excluded.display_name, email=excluded.email,
                     email_verified=excluded.email_verified""",
                ("user-alice", "alice", "Alice Example", "alice@example.com", 1, now))
    cur.execute("""INSERT INTO sessions (id,user_id,auth_time,amr,acr,expires_at,created_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (id) DO UPDATE SET auth_time=excluded.auth_time,
                     expires_at=excluded.expires_at""",
                (sid_hash, "user-alice", now, '["passkey"]', "urn:kagi:acr:passkey", now + 3600, now))
    con.commit(); con.close()
else:
    con = sqlite3.connect(DB, timeout=10)
    con.execute("INSERT OR REPLACE INTO users (id,username,display_name,email,email_verified,created_at) VALUES (?,?,?,?,?,?)",
                ("user-alice", "alice", "Alice Example", "alice@example.com", 1, now))
    con.execute("INSERT OR REPLACE INTO sessions (id,user_id,auth_time,amr,acr,expires_at,created_at) VALUES (?,?,?,?,?,?,?)",
                (sid_hash, "user-alice", now, '["passkey"]', "urn:kagi:acr:passkey", now + 3600, now))
    con.commit(); con.close()
SESSION_COOKIE = "kagi_sid=" + sid

jwks = json.loads(req("GET", "/jwks.json").content)

def verify_jwt(token):
    hdr_b, pay_b, sig_b = token.split(".")
    header = json.loads(unb64(hdr_b))
    key = next((k for k in jwks["keys"] if k.get("kid") == header.get("kid")), None)
    if key is None:
        return None
    pub = ec.EllipticCurvePublicNumbers(
        int.from_bytes(unb64(key["x"]), "big"),
        int.from_bytes(unb64(key["y"]), "big"),
        ec.SECP256R1(),
    ).public_key()
    sig = unb64(sig_b)
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    pub.verify(acu.encode_dss_signature(r, s), (hdr_b + "." + pay_b).encode(),
               ec.ECDSA(hashes.SHA256()))
    return json.loads(unb64(pay_b))

# ---------------------------------------------------------------- device flow
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

def device_start(scope="openid profile email offline_access"):
    s, h, j, b = form_post("/device_authorization", {"client_id": DEMO, "scope": scope})
    return s, j, b

s, dev, b = device_start()
check("device authorization", s == 200 and dev and dev.get("device_code") and dev.get("user_code"), b)
check("device verification_uri", dev.get("verification_uri", "").endswith("/device") and
      dev.get("verification_uri_complete", "").startswith(dev.get("verification_uri", "")), dev)
check("device user_code is unambiguous",
      re.fullmatch(r"[A-Z2-9]{4}-[A-Z2-9]{4}", dev.get("user_code", "")) is not None and
      not any(c in dev.get("user_code", "") for c in "01IO"), dev.get("user_code"))
check("device lifetime and interval", dev.get("expires_in", 0) > 0 and dev.get("interval", 0) >= 1, dev)

user_code = dev["user_code"]
s, h, j, b = form_post("/token", {"grant_type": DEVICE_GRANT, "device_code": dev["device_code"],
                                  "client_id": DEMO})
check("device pending", s == 400 and j.get("error") == "authorization_pending", b)

# A separate grant exercises slow_down without delaying the approved grant.
s, dev2, b = device_start("openid")
check("second device authorization", s == 200 and dev2 and dev2.get("device_code"), b)
form_post("/token", {"grant_type": DEVICE_GRANT, "device_code": dev2["device_code"], "client_id": DEMO})
s, h, j, b = form_post("/token", {"grant_type": DEVICE_GRANT, "device_code": dev2["device_code"],
                                  "client_id": DEMO})
check("device slow_down", s == 400 and j.get("error") == "slow_down", b)
s, h, j, b = form_post("/token", {"grant_type": DEVICE_GRANT, "device_code": "not-a-real-code",
                                  "client_id": DEMO})
check("device unknown code rejected", s == 400 and j.get("error") == "invalid_grant", b)
s, h, j, b = form_post("/device_authorization", {"scope": "openid"})
check("device requires client authentication", s == 401, b)

# Browser verification: reject a wrong code, then approve the real one.
r = req("GET", "/device?" + up.urlencode({"user_code": user_code}), headers={"Cookie": SESSION_COOKIE})
page = r.content.decode()
rid = re.search(r'name="rid" value="([^"]+)"', page)
csrf = re.search(r'name="csrf" value="([^"]+)"', page)
check("device approval page", r.status_code == 200 and rid is not None and csrf is not None, page[:300])
s, h, b = req3("POST", "/device", {"rid": rid.group(1) if rid else "", "csrf": csrf.group(1) if csrf else "",
                                  "user_code": "AAAA-BBBB", "decision": "allow"},
              headers={"Cookie": SESSION_COOKIE})
check("device wrong user_code rejected", s == 400, (s, b[:300]))
s, h, b = req3("POST", "/device", {"rid": rid.group(1) if rid else "", "csrf": csrf.group(1) if csrf else "",
                                  "user_code": user_code, "decision": "allow"},
              headers={"Cookie": SESSION_COOKIE})
check("device approval succeeds", s == 200 and "許可" in b.decode(), (s, b[:300]))

time.sleep(1.2)
s, h, j, b = form_post("/token", {"grant_type": DEVICE_GRANT, "device_code": dev["device_code"],
                                  "client_id": DEMO})
check("device token issued", s == 200 and j and j.get("access_token") and j.get("id_token")
      and j.get("refresh_token") and j.get("token_type") == "Bearer", b)
if j and j.get("id_token"):
    claims = verify_jwt(j["id_token"])
    check("device id_token", claims and claims.get("sub") == "user-alice"
          and claims.get("aud") == DEMO and claims.get("amr") == ["passkey"]
          and claims.get("acr") == "urn:kagi:acr:passkey", claims)
    s, h, b = req3("GET", "/userinfo", headers={"Authorization": "Bearer " + j["access_token"]})
    ui = json.loads(b)
    check("device access token works", s == 200 and ui.get("sub") == "user-alice", (s, ui))
s, h, j, b = form_post("/token", {"grant_type": DEVICE_GRANT, "device_code": dev["device_code"],
                                  "client_id": DEMO})
check("device code is single use", s == 400 and j.get("error") == "expired_token", b)

# Denial path.
s, dev3, b = device_start("openid")
check("third device authorization", s == 200 and dev3 and dev3.get("device_code"), b)
r = req("GET", "/device?" + up.urlencode({"user_code": dev3["user_code"]}), headers={"Cookie": SESSION_COOKIE})
page = r.content.decode()
rid3 = re.search(r'name="rid" value="([^"]+)"', page)
csrf3 = re.search(r'name="csrf" value="([^"]+)"', page)
s, h, b = req3("POST", "/device", {"rid": rid3.group(1) if rid3 else "", "csrf": csrf3.group(1) if csrf3 else "",
                                  "user_code": dev3["user_code"], "decision": "deny"},
              headers={"Cookie": SESSION_COOKIE})
check("device denial page", s == 200 and "拒否" in b.decode(), (s, b[:300]))
s, h, j, b = form_post("/token", {"grant_type": DEVICE_GRANT, "device_code": dev3["device_code"],
                                  "client_id": DEMO})
check("denied device grant rejected", s == 400 and j.get("error") == "access_denied", b)

# ---------------------------------------------------------------- claims
def par_claims(claims, scope="openid profile email", client=DEMO, redirect=DEMO_REDIRECT):
    verifier, challenge = pkce()
    params = {
        "client_id": client, "redirect_uri": redirect, "response_type": "code", "scope": scope,
        "code_challenge": challenge, "code_challenge_method": "S256",
        "claims": claims if isinstance(claims, str) else json.dumps(claims),
    }
    return form_post("/par", params, {"Cookie": SESSION_COOKIE})

s, h, j, b = par_claims({"id_token": {"password": None}})
check("claims rejects unknown claim names", s == 400 and j.get("error") == "invalid_request", b)
s, h, j, b = par_claims({"id_token": {"acr": {"values": ["urn:example:unknown"]}}})
check("claims rejects unsupported acr", s == 400 and j.get("error") == "invalid_request", b)
s, h, j, b = par_claims("{" * 5000)
check("claims rejects oversized values", s == 400 and j.get("error") == "invalid_request", b)
s, h, j, b = par_claims({"id_token": {"email": {"value": "x"}}})
check("claims rejects value outside acr", s == 400, b)

code, verifier, detail = authorize_code(
    DEMO, DEMO_REDIRECT, "openid profile email",
    claims={"id_token": {"email": {"essential": True}}, "userinfo": {"name": None}},
)
check("claims flow issues a code", bool(code), detail)
s, h, j, b = form_post("/token", {"grant_type": "authorization_code", "code": code,
                                  "redirect_uri": DEMO_REDIRECT, "client_id": DEMO,
                                  "code_verifier": verifier})
check("claims token exchange", s == 200 and j and j.get("id_token"), b)
if j and j.get("id_token"):
    claims = verify_jwt(j["id_token"])
    check("claims filters the id_token", claims and claims.get("email") == "alice@example.com"
          and "name" not in claims, claims)
    s, h, b = req3("GET", "/userinfo", headers={"Authorization": "Bearer " + j["access_token"]})
    ui = json.loads(b)
    check("claims filters userinfo", s == 200 and ui.get("name") == "Alice Example"
          and "email" not in ui and "preferred_username" not in ui, ui)

# Essential email is impossible when the email scope was not granted. Consent for
# the wider scope above is remembered, so this reaches the grant check directly.
code, verifier, detail = authorize_code(
    DEMO, DEMO_REDIRECT, "openid profile",
    claims={"id_token": {"email": {"essential": True}}},
)
loc = detail[1] if isinstance(detail, tuple) else ""
check("claims essential claim outside scope denied",
      not code and "error=access_denied" in loc, detail)

# ---------------------------------------------------------------- client management
status, reg, raw = register({
    "client_name": "e2e-management",
    "redirect_uris": ["http://localhost:9999/cb"],
    "grant_types": ["client_credentials"],
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": "openid",
})
check("management client registered", status == 201 and reg and reg.get("client_id")
      and reg.get("client_secret") and reg.get("registration_access_token")
      and reg.get("registration_client_uri"), (status, raw))
if not (reg and reg.get("registration_access_token")):
    print("\nFAILURES:", fails)
    sys.exit(1)

cid = reg["client_id"]
secret = reg["client_secret"]
rat = reg["registration_access_token"]
mgmt_path = up.urlparse(reg["registration_client_uri"]).path
auth = {"Authorization": "Bearer " + rat, "Content-Type": "application/json"}

s, h, b = req3("GET", mgmt_path)
check("management requires the registration token", s == 401, (s, b))
s, h, b = req3("GET", mgmt_path, headers={"Authorization": "Bearer wrong"})
check("management rejects a wrong token", s == 401, (s, b))
s, h, b = req3("GET", mgmt_path, headers=auth)
meta = json.loads(b)
check("management read returns metadata", s == 200 and meta.get("client_id") == cid
      and meta.get("client_name") == "e2e-management" and "client_secret" not in meta, (s, meta))

s, h, b = req3("PUT", mgmt_path, json.dumps({
    "client_name": "e2e-management-updated",
    "redirect_uris": ["http://localhost:9999/cb2"],
    "backchannel_logout_uri": "https://rp.example/logout",
    "backchannel_logout_session_required": True,
}), auth)
updated = json.loads(b)
check("management update", s == 200 and updated.get("client_name") == "e2e-management-updated"
      and updated.get("redirect_uris") == ["http://localhost:9999/cb2"]
      and updated.get("backchannel_logout_uri") == "https://rp.example/logout"
      and updated.get("backchannel_logout_session_required") is True, (s, updated))

s, h, b = req3("PUT", mgmt_path, json.dumps({"redirect_uris": ["http://evil.example/cb"]}), auth)
check("management update rejects unsafe redirect", s == 400, (s, b))
s, h, b = req3("PUT", mgmt_path, json.dumps({"redirect_uris": ["https://rp.example/cb"],
                                           "scope": "openid admin"}), auth)
check("management update rejects unsupported scope", s == 400, (s, b))

s, h, j, b = form_post("/token", {"grant_type": "client_credentials", "scope": "openid"},
                       {"Authorization": "Basic " + base64.b64encode(f"{cid}:{secret}".encode()).decode()})
check("management client token before rotation", s == 200 and j and j.get("access_token"), b)

s, h, b = req3("PUT", mgmt_path, json.dumps({"rotate_client_secret": True,
                                            "redirect_uris": ["http://localhost:9999/cb2"]}), auth)
rotated = json.loads(b)
new_secret = rotated.get("client_secret")
check("management rotates the client secret", s == 200 and new_secret and new_secret != secret, (s, rotated))

s, h, j, b = form_post("/token", {"grant_type": "client_credentials", "scope": "openid"},
                       {"Authorization": "Basic " + base64.b64encode(f"{cid}:{new_secret}".encode()).decode()})
check("rotated secret works", s == 200 and j and j.get("access_token"), b)
s, h, j, b = form_post("/token", {"grant_type": "client_credentials", "scope": "openid"},
                       {"Authorization": "Basic " + base64.b64encode(f"{cid}:{secret}".encode()).decode()})
check("old secret is rejected after rotation", s == 401, b)

s, h, b = req3("DELETE", mgmt_path, headers=auth)
check("management delete", s == 204, (s, b))
s, h, b = req3("GET", mgmt_path, headers=auth)
check("deleted client cannot be read", s == 401, (s, b))
s, h, j, b = form_post("/token", {"grant_type": "client_credentials", "scope": "openid"},
                       {"Authorization": "Basic " + base64.b64encode(f"{cid}:{new_secret}".encode()).decode()})
check("deleted client cannot authenticate", s == 401, b)

# ---------------------------------------------------------------- back-channel logout
received = {}
delivered = threading.Event()

class LogoutHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        received["body"] = self.rfile.read(length).decode()
        received["content_type"] = self.headers.get("Content-Type", "")
        delivered.set()
        self.send_response(204)
        self.end_headers()
    def log_message(self, *_args):
        pass

server = ThreadingHTTPServer(("127.0.0.1", 0), LogoutHandler)
bp = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()

status, bc, raw = register({
    "client_name": "e2e-backchannel",
    "redirect_uris": [f"http://localhost:{bp}/cb"],
    "grant_types": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_method": "none",
    "scope": "openid profile email offline_access",
    "backchannel_logout_uri": f"http://127.0.0.1:{bp}/logout",
    "backchannel_logout_session_required": True,
})
check("backchannel client registered", status == 201 and bc and bc.get("client_id"), (status, raw))
if bc and bc.get("client_id"):
    code, verifier, detail = authorize_code(
        bc["client_id"], f"http://localhost:{bp}/cb",
        "openid profile email offline_access",
    )
    check("backchannel flow issues a code", bool(code), detail)
    s, h, j, b = form_post("/token", {"grant_type": "authorization_code", "code": code,
                                      "redirect_uri": f"http://localhost:{bp}/cb",
                                      "client_id": bc["client_id"], "code_verifier": verifier})
    check("backchannel flow token exchange", s == 200 and j and j.get("access_token"), b)

    s, h, b = req3("POST", "/account/logout", headers={"Cookie": SESSION_COOKIE})
    check("logout ends the session", s in (302, 303), (s, b))

    got = delivered.wait(8)
    check("back-channel logout delivered", got, received)
    if got:
        check("back-channel uses form encoding",
              received.get("content_type", "").startswith("application/x-www-form-urlencoded"),
              received.get("content_type"))
        form = up.parse_qs(received.get("body", ""))
        token = (form.get("logout_token") or [""])[0]
        check("back-channel carries a logout_token", bool(token), received.get("body", "")[:120])
        if token:
            try:
                payload = verify_jwt(token)
                events = payload.get("events", {}) if payload else {}
                check("logout token claims", payload is not None
                      and payload.get("iss") == BASE
                      and payload.get("aud") == bc["client_id"]
                      and payload.get("sub") == "user-alice"
                      and payload.get("sid") == sid_hash
                      and "http://schemas.openid.net/event/backchannel-logout" in events, payload)
            except Exception as exc:  # noqa: BLE001 - report the failure, do not crash
                check("logout token signature valid", False, repr(exc))

    # A revoked browser session must not keep working.
    r = req("GET", "/", headers={"Cookie": SESSION_COOKIE})
    check("logged-out session is rejected", r.status_code in (302, 303), r.status_code)

server.shutdown()

print()
print("FAILURES:", fails if fails else "none")
sys.exit(1 if fails else 0)
