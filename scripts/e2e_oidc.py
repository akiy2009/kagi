"""End-to-end checks for the OIDC core: PAR, authorize/consent, PKCE, tokens,
refresh rotation, revocation, introspection, prompt=none and DPoP.

Requires a running server with the demo client:
    KAGI_SEED_DEMO=1 KAGI_DB=kagi-e2e.db cargo run
    KAGI_DB=kagi-e2e.db python scripts/e2e_oidc.py

With PostgreSQL / Supabase, seed through psycopg2 instead:
    KAGI_SEED_DEMO=1 KAGI_DATABASE_URL=postgresql://... cargo run
    KAGI_DATABASE_URL=postgresql://... python scripts/e2e_oidc.py
"""

import base64, hashlib, json, os, re, secrets, sqlite3, sys, time
import urllib.parse as up
import requests
from cryptography.hazmat.primitives.asymmetric import ec, utils as acu
from cryptography.hazmat.primitives import hashes

BASE = os.environ.get("KAGI_BASE", "http://localhost:8080")
DB = os.environ.get("KAGI_DB", "kagi-e2e.db")
CLIENT = "demo-web"
REDIRECT = "http://localhost:3000/callback"

fails = []
def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail}"))
    if not cond:
        fails.append(name)

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def unb64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

RS = requests.Session()
RS.max_redirects = 1

def req(method, path, data=None, headers=None, follow=False, base=BASE):
    h = dict(headers or {})
    r = RS.request(method, base + path, data=data, headers=h, allow_redirects=False)
    return r.status_code, r.headers, r.content

def form_post(path, data, headers=None):
    s, h, b = req("POST", path, data, headers)
    try: j = json.loads(b)
    except Exception: j = None
    return s, h, j, b

def jget(s, h, b): return json.loads(b)

# ---------------------------------------------------------------- seed session
sid = secrets.token_urlsafe(32)
sid_hash = hashlib.sha256(sid.encode()).hexdigest()
now = int(time.time())
DATABASE_URL = os.environ.get("KAGI_DATABASE_URL")
if DATABASE_URL:
    # PostgreSQL / Supabase backend: seed through psycopg2.
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
RS.cookies.set("kagi_sid", sid)

# ---------------------------------------------------------------- discovery
s, h, b = req("GET", "/.well-known/openid-configuration")
disc = jget(s, h, b)
check("discovery issuer", s == 200 and disc["issuer"] == BASE, disc)
s, h, b = req("GET", "/jwks.json")
jwks = jget(s, h, b)
check("jwks has keys", s == 200 and len(jwks["keys"]) >= 1, jwks)

# ---------------------------------------------------------------- PAR + PKCE
verifier = b64u(secrets.token_bytes(48))
challenge = b64u(hashlib.sha256(verifier.encode()).digest())
authz = {
    "client_id": CLIENT, "redirect_uri": REDIRECT, "response_type": "code",
    "scope": "openid profile email offline_access", "state": "st-123", "nonce": "n-456",
    "code_challenge": challenge, "code_challenge_method": "S256",
}
s, h, j, b = form_post("/par", authz, {"Cookie": "kagi_sid=" + sid})
check("PAR returns request_uri", s == 201 and j["request_uri"].startswith("urn:ietf:params:oauth:request_uri:"), b)
request_uri = j["request_uri"]

s, h, j, b = form_post("/par", {k: v for k, v in authz.items() if k != "code_challenge"})
check("PAR without PKCE rejected", s == 400, b)

# ---------------------------------------------------------------- authorize (session exists)
s, h, b = req("GET", "/authorize?" + up.urlencode({"client_id": CLIENT, "request_uri": request_uri}), {"Cookie": "kagi_sid=" + sid})
loc = h.get("Location", "")
check("authorize redirects to consent", s in (302, 303) and loc.startswith("/consent?rid="), (s, h))
rid = up.parse_qs(up.urlparse(loc).query)["rid"][0]

s, h, b = req("GET", "/consent?rid=" + rid, headers={"Cookie": "kagi_sid=" + sid})
page = b.decode()
inputs = dict(re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page))
check("consent page has csrf", "csrf" in inputs, inputs)
s, h, b = req("POST", "/consent", {"rid": rid, "csrf": inputs.get("csrf", ""), "decision": "allow"}, {"Cookie": "kagi_sid=" + sid})
loc = h.get("Location", "")
check("consent redirects with code", s in (302, 303) and "code=" in loc, (s, loc))
q = up.parse_qs(up.urlparse(loc).query)
code = q["code"][0]
check("state echoed", q.get("state") == ["st-123"], q)

# ---------------------------------------------------------------- token
s, h, j, b = form_post("/token", {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                  "client_id": CLIENT, "code_verifier": verifier})
check("code exchange", s == 200 and "access_token" in j and "id_token" in j and "refresh_token" in j, b)
at, idt, rt = j["access_token"], j["id_token"], j["refresh_token"]

# ---------------------------------------------------------------- form_post CSP
# The browser must be allowed to run the auto-submit script and POST to the RP
# even though the global CSP restricts both to 'self'.
fp = {**authz, "response_mode": "form_post", "prompt": "none", "state": "fp-state"}
s, h, b = req("GET", "/authorize?" + up.urlencode(fp))
page = b.decode()
csp = h.get("Content-Security-Policy", "")
check("form_post returns an auto-submit page", s == 200 and "<form" in page and "<script" in page, (s, b[:200]))
check("form_post script carries a nonce", "nonce=" in page and "script-src 'nonce-" in csp, (page[:300], csp))
check("form_post CSP allows the RP origin", "form-action http://localhost:3000" in csp, csp)

# verify id_token signature against JWKS
hdr_b, pay_b, sig_b = idt.split(".")
hd = json.loads(unb64(hdr_b)); cl = json.loads(unb64(pay_b)); sig = unb64(sig_b)
k = next((x for x in jwks["keys"] if x.get("kid") == hd.get("kid")), None)
check("id_token kid in jwks", k is not None, hd)
pub = ec.EllipticCurvePublicNumbers(int.from_bytes(unb64(k["x"]), "big"), int.from_bytes(unb64(k["y"]), "big"), ec.SECP256R1()).public_key()
r, ss = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
try:
    pub.verify(acu.encode_dss_signature(r, ss), (hdr_b + "." + pay_b).encode(), ec.ECDSA(hashes.SHA256()))
    ok = True
except Exception as e:
    ok = False
check("id_token ES256 signature valid", ok)
check("id_token claims", cl.get("iss") == BASE and cl.get("aud") == CLIENT and cl.get("sub") == "user-alice"
      and cl.get("nonce") == "n-456" and "at_hash" in cl and cl.get("amr") == ["passkey"], cl)

# userinfo
s, h, b = req("GET", "/userinfo", headers={"Authorization": "Bearer " + at})
ui = jget(s, h, b)
check("userinfo", s == 200 and ui.get("sub") == "user-alice" and ui.get("email") == "alice@example.com", ui)
s, h, b = req("GET", "/userinfo", headers={"Authorization": "Bearer " + at[:-2] + "xx"})
check("userinfo rejects tampered AT", s == 401, (s, b))

# introspect
s, h, j, b = form_post("/introspect", {"token": at, "client_id": CLIENT})
check("introspect active", s == 200 and j.get("active") is True and j.get("sub") == "user-alice", b)

# code replay
s, h, j, b = form_post("/token", {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                                  "client_id": CLIENT, "code_verifier": verifier})
check("code replay rejected", s == 400 and j.get("error") == "invalid_grant", b)

# bad PKCE verifier
# refresh + rotation
s, h, j, b = form_post("/token", {"grant_type": "refresh_token", "refresh_token": rt, "client_id": CLIENT})
check("refresh grant", s == 200 and j.get("refresh_token") and j["refresh_token"] != rt, b)
rt2 = j["refresh_token"]; at2 = j["access_token"]
s, h, j, b = form_post("/token", {"grant_type": "refresh_token", "refresh_token": rt, "client_id": CLIENT})
check("old refresh token reuse rejected", s == 400, b)
s, h, j, b = form_post("/token", {"grant_type": "refresh_token", "refresh_token": rt2, "client_id": CLIENT})
check("family revoked after reuse", s == 400 and j.get("error") == "invalid_grant", b)

# revoke
s, h, j, b = form_post("/revoke", {"token": at, "client_id": CLIENT})
s2, h2, b2 = req("GET", "/userinfo", headers={"Authorization": "Bearer " + at})
check("revoked AT rejected", s == 200 and s2 == 401, (s, s2, b2))
s, h, j, b = form_post("/introspect", {"token": at, "client_id": CLIENT})
check("introspect revoked AT inactive", j.get("active") is False, b)

# ---------------------------------------------------------------- prompt=none
authz2 = dict(authz); authz2["prompt"] = "none"; authz2["state"] = "st-none"
s, h, j, b = form_post("/par", authz2)
ru2 = j["request_uri"]
saved = RS.cookies.get("kagi_sid")
RS.cookies.clear()
s, h, b = req("GET", "/authorize?" + up.urlencode({"client_id": CLIENT, "request_uri": ru2}))
check("prompt=none without session -> login_required", s == 303 and "error=login_required" in h.get("Location", ""), (s, h))
RS.cookies.set("kagi_sid", saved)

# with a session and remembered consent, prompt=none completes silently
authz4 = dict(authz); authz4["prompt"] = "none"; authz4["state"] = "st-silent"
s, h, j, b = form_post("/par", authz4)
ru4 = j["request_uri"]
s, h, b = req("GET", "/authorize?" + up.urlencode({"client_id": CLIENT, "request_uri": ru4}))
loc4 = h.get("Location", "")
check("prompt=none with consent -> code", s == 303 and "code=" in loc4 and "state=st-silent" in loc4, (s, loc4))

# bad redirect_uri
s, h, j, b = form_post("/par", {**authz, "redirect_uri": "http://evil.example/cb"})
check("PAR rejects unregistered redirect_uri", s == 400, b)

# ---------------------------------------------------------------- DPoP
key = ec.generate_private_key(ec.SECP256R1())
pubs = key.public_key().public_numbers()
jwk = {"kty": "EC", "crv": "P-256", "x": b64u(pubs.x.to_bytes(32, "big")), "y": b64u(pubs.y.to_bytes(32, "big"))}
thumb_src = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
jkt = b64u(hashlib.sha256(thumb_src.encode()).digest())

def dpop(htm, htu, extra=None, token=None):
    nowi = int(time.time())
    pl = {"jti": b64u(secrets.token_bytes(16)), "htm": htm, "htu": htu, "iat": nowi}
    if token is not None:
        pl["ath"] = b64u(hashlib.sha256(token.encode()).digest())
    if extra: pl.update(extra)
    h = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    hb = b64u(json.dumps(h, separators=(",", ":")).encode())
    pb = b64u(json.dumps(pl, separators=(",", ":")).encode())
    der = key.sign((hb + "." + pb).encode(), ec.ECDSA(hashes.SHA256()))
    r, ss = acu.decode_dss_signature(der)
    return hb + "." + pb + "." + b64u(r.to_bytes(32, "big") + ss.to_bytes(32, "big"))

authz3 = dict(authz); authz3["dpop_jkt"] = jkt; authz3["state"] = "st-dpop"
s, h, j, b = form_post("/par", authz3, {"DPoP": dpop("POST", BASE + "/par")})
check("PAR with DPoP", s == 201, b)
ru3 = j["request_uri"]
s, h, b = req("GET", "/authorize?" + up.urlencode({"client_id": CLIENT, "request_uri": ru3}),
              {"Cookie": "kagi_sid=" + sid})
loc3 = h.get("Location", "")
if loc3.startswith("/consent?rid="):
    rid3 = up.parse_qs(up.urlparse(loc3).query)["rid"][0]
    s, h, b = req("GET", "/consent?rid=" + rid3, headers={"Cookie": "kagi_sid=" + sid})
    inp3 = dict(re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', b.decode()))
    s, h, b = req("POST", "/consent", {"rid": rid3, "csrf": inp3.get("csrf", ""), "decision": "allow"},
                  {"Cookie": "kagi_sid=" + sid})
    loc3 = h.get("Location", "")
code3 = up.parse_qs(up.urlparse(loc3).query).get("code", [""])[0]
s, h, j, b = form_post("/token", {"grant_type": "authorization_code", "code": code3, "redirect_uri": REDIRECT,
                                  "client_id": CLIENT, "code_verifier": verifier}, {"DPoP": dpop("POST", BASE + "/token")})
check("DPoP token issuance", s == 200 and j.get("token_type") == "DPoP", b)
at3 = j.get("access_token", ""); idt3 = j.get("id_token", "")
cnf_ok = False
if idt3:
    body3 = json.loads(unb64(idt3.split(".")[1]))
    cnf_ok = body3.get("cnf", {}).get("jkt") == jkt
check("id_token cnf.jkt bound", cnf_ok, idt3)
s, h, b = req("GET", "/userinfo", headers={"Authorization": "DPoP " + at3})
check("DPoP AT without proof -> 401", s == 401, (s, b))
s, h, b = req("GET", "/userinfo", headers={"Authorization": "DPoP " + at3, "DPoP": dpop("GET", BASE + "/userinfo", token=at3)})
ui3 = jget(s, h, b)
check("DPoP AT with proof accepted", s == 200 and ui3.get("sub") == "user-alice", (s, ui3))
s, h, b = req("GET", "/userinfo", headers={"Authorization": "DPoP " + at3, "DPoP": dpop("GET", BASE + "/userinfo", token=at3)})
proof = dpop("GET", BASE + "/userinfo", token=at3)
s, h, b = req("GET", "/userinfo", headers={"Authorization": "DPoP " + at3, "DPoP": proof})
s2, h2, b2 = req("GET", "/userinfo", headers={"Authorization": "DPoP " + at3, "DPoP": proof})
check("DPoP replay rejected", s == 200 and s2 == 401, (s, s2, b2))
s, h, b = req("GET", "/userinfo", headers={"Authorization": "Bearer " + at3, "DPoP": dpop("GET", BASE + "/userinfo", token=at3)})
check("Bearer scheme with DPoP-bound AT rejected", s == 401, (s, b))

# ---------------------------------------------------------------- DCR + client_credentials
# When the server is started with KAGI_REGISTRATION_TOKEN, RFC 7591 requires
# the initial access token. Reuse the same environment variable here so the
# suite works with either configuration.
dcr_headers = {"Content-Type": "application/json"}
if os.environ.get("KAGI_REGISTRATION_TOKEN"):
    dcr_headers["Authorization"] = "Bearer " + os.environ["KAGI_REGISTRATION_TOKEN"]
s, h, j, b = form_post("/register", json.dumps({
    "client_name": "e2e-confidential",
    "redirect_uris": ["http://localhost:9999/cb"],
    "grant_types": ["client_credentials"],
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": "openid",
}).encode(), dcr_headers)
check("DCR", s in (200, 201) and j.get("client_id") and j.get("client_secret"), b)
cid, csec = j["client_id"], j["client_secret"]
s, h, j, b = form_post("/token", {"grant_type": "client_credentials", "scope": "openid"},
                       {"Authorization": "Basic " + base64.b64encode(f"{cid}:{csec}".encode()).decode()})
check("client_credentials", s == 200 and j.get("access_token") and "refresh_token" not in j, b)
s, h, j, b = form_post("/token", {"grant_type": "client_credentials"},
                       {"Authorization": "Basic " + base64.b64encode(f"{cid}:wrong".encode()).decode()})
check("bad client secret rejected", s == 401, b)

print()
print("FAILURES:", fails if fails else "none")
sys.exit(1 if fails else 0)
