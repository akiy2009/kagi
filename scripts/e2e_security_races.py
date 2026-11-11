"""Security regression tests for authorization-code races, DPoP replay, key rotation and OIDC metadata.

Run against a local Kagi server with KAGI_SEED_DEMO=1 and KAGI_DB pointing
at the same SQLite database used by the server:

    KAGI_DB=kagi-security-e2e.db python scripts/e2e_security_races.py

Against PostgreSQL / Supabase, set KAGI_DATABASE_URL instead (psycopg2 is
required by requirements-test.txt):

    KAGI_DATABASE_URL=postgresql://... python scripts/e2e_security_races.py

This is an integration test, not an OAuth/OIDC certification suite.
"""
import base64
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlparse

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

BASE = os.environ.get("KAGI_BASE", "http://localhost:8080").rstrip("/")
DB = os.environ.get("KAGI_DB", "kagi-security-e2e.db")
DATABASE_URL = os.environ.get("KAGI_DATABASE_URL", "").strip()
ADMIN = os.environ.get("KAGI_ADMIN_TOKEN", "test-admin")
CLIENT = "demo-web"
REDIRECT = "http://localhost:3000/callback"
failures = []

def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f" -> {str(detail)[:400]}"), flush=True)
    if not ok:
        failures.append(name)

def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def pkce():
    verifier = b64u(secrets.token_bytes(32))
    return verifier, b64u(hashlib.sha256(verifier.encode()).digest())

def insert_code(code, challenge):
    now = int(time.time())
    digest = hashlib.sha256(code.encode()).hexdigest()
    values = (digest, CLIENT, "security-test-user", REDIRECT,
              "openid profile email offline_access", "security-test-nonce",
              challenge, now, '["passkey"]', "urn:kagi:acr:passkey", now + 120, now)
    if DATABASE_URL:
        import psycopg2
        with psycopg2.connect(DATABASE_URL) as con, con.cursor() as cur:
            cur.execute(
                """INSERT INTO auth_codes
                (code_hash, client_id, user_id, redirect_uri, scope, nonce,
                 code_challenge, auth_time, amr, acr, dpop_jkt, session_id,
                 expires_at, created_at, consumed)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NULL, NULL, %s, %s, 0)""",
                values,
            )
        return
    with sqlite3.connect(DB, timeout=10) as con:
        con.execute(
            """INSERT INTO auth_codes
            (code_hash, client_id, user_id, redirect_uri, scope, nonce,
             code_challenge, auth_time, amr, acr, dpop_jkt, session_id,
             expires_at, created_at, consumed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, 0)""",
            values,
        )

def exchange(code, verifier):
    try:
        return requests.post(BASE + "/token", data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT, "client_id": CLIENT,
            "code_verifier": verifier,
        }, timeout=10)
    except Exception as exc:
        return exc

def make_dpop_proof(key, jwk, jti, method, url):
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    payload = {"jti": jti, "htm": method, "htu": url, "iat": int(time.time())}
    head = b64u(json.dumps(header, separators=(",", ":")).encode())
    body = b64u(json.dumps(payload, separators=(",", ":")).encode())
    der = key.sign((head + "." + body).encode(), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return head + "." + body + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))

def seed_test_rows():
    """Seed only isolated test records in the dedicated CI database."""
    now = int(time.time())
    if DATABASE_URL:
        import psycopg2
        with psycopg2.connect(DATABASE_URL) as con, con.cursor() as cur:
            cur.execute(
                """INSERT INTO users
                (id, username, display_name, email, email_verified, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET username = excluded.username,
                  display_name = excluded.display_name, email = excluded.email""",
                ("security-test-user", "security-test-user", "Security Test",
                 "security-test@example.invalid", 0, now),
            )
            cur.execute(
                """INSERT INTO consents (user_id, client_id, scope, created_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (user_id, client_id) DO UPDATE SET
                  scope = excluded.scope, created_at = excluded.created_at""",
                ("security-test-user", CLIENT, "openid profile email offline_access", now),
            )
        return
    with sqlite3.connect(DB, timeout=10) as con:
        con.execute(
            """INSERT OR REPLACE INTO users
            (id, username, display_name, email, email_verified, created_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            ("security-test-user", "security-test-user", "Security Test",
             "security-test@example.invalid", 0, now),
        )
        con.execute(
            """INSERT OR REPLACE INTO consents (user_id, client_id, scope, created_at)
            VALUES (?, ?, ?, ?)""",
            ("security-test-user", CLIENT, "openid profile email offline_access", now),
        )

def seed_authorize_flow(csrf, payload, sid):
    """Seed a browser session and an unconsumed authorization flow."""
    flow_id = secrets.token_urlsafe(18)
    session_hash = hashlib.sha256(sid.encode()).hexdigest()
    now = int(time.time())
    if DATABASE_URL:
        import psycopg2
        with psycopg2.connect(DATABASE_URL) as con, con.cursor() as cur:
            cur.execute(
                """INSERT INTO sessions
                (id, user_id, auth_time, amr, acr, expires_at, created_at, last_seen_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET expires_at = excluded.expires_at,
                  last_seen_at = excluded.last_seen_at""",
                (session_hash, "security-test-user", now, '["passkey"]',
                 "urn:kagi:acr:passkey", now + 3600, now, now),
            )
            cur.execute(
                """INSERT INTO flows
                (id, kind, user_id, client_id, payload, challenge, csrf,
                 expires_at, created_at, consumed)
                VALUES (%s, 'authorize', NULL, %s, %s, NULL, %s, %s, %s, 0)""",
                (flow_id, CLIENT, json.dumps(payload), csrf, now + 600, now),
            )
        return flow_id
    with sqlite3.connect(DB, timeout=10) as con:
        con.execute(
            """INSERT OR REPLACE INTO sessions
            (id, user_id, auth_time, amr, acr, expires_at, created_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_hash, "security-test-user", now, '["passkey"]',
             "urn:kagi:acr:passkey", now + 3600, now, now),
        )
        con.execute(
            """INSERT INTO flows
            (id, kind, user_id, client_id, payload, challenge, csrf,
             expires_at, created_at, consumed)
            VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, 0)""",
            (flow_id, "authorize", None, CLIENT, json.dumps(payload), csrf,
             now + 600, now),
        )
    return flow_id

def main():
    seed_test_rows()

    # OAuth/OIDC metadata sanity checks: assertions are intentionally focused
    # on advertised features and do not claim full normative conformance.
    try:
        discovery = requests.get(BASE + "/.well-known/openid-configuration", timeout=5)
        doc = discovery.json()
        check("OIDC discovery responds", discovery.status_code == 200, discovery.status_code)
        check("OIDC issuer and endpoints are absolute", doc.get("issuer") == BASE
              and doc.get("authorization_endpoint", "").startswith("http")
              and doc.get("token_endpoint", "").startswith("http")
              and doc.get("jwks_uri", "").startswith("http"), doc)
        check("OIDC advertises code + S256", "code" in doc.get("response_types_supported", [])
              and "S256" in doc.get("code_challenge_methods_supported", []), doc)
        check("discovery advertises the supported claims parameter",
              doc.get("claims_parameter_supported") is True,
              doc.get("claims_parameter_supported"))
        check("discovery advertises the device authorization endpoint",
              doc.get("device_authorization_endpoint", "").startswith("http")
              and "urn:ietf:params:oauth:grant-type:device_code"
              in doc.get("grant_types_supported", []), doc)
        check("discovery advertises back-channel logout",
              doc.get("backchannel_logout_supported") is True
              and doc.get("backchannel_logout_session_supported") is True, doc)
        check("discovery advertises the kagi ACR values",
              "urn:kagi:acr:passkey" in doc.get("acr_values_supported", [])
              and "urn:kagi:acr:recovery" in doc.get("acr_values_supported", []),
              doc.get("acr_values_supported"))
        check("OAuth metadata alias responds", requests.get(
            BASE + "/.well-known/oauth-authorization-server", timeout=5).status_code == 200)
    except Exception as exc:
        check("OIDC discovery requests", False, exc)
        return 1

    # Two simultaneous exchanges of the exact same authorization code must
    # never both mint tokens. The database CAS is the security boundary.
    verifier, challenge = pkce()
    code = secrets.token_urlsafe(32)
    insert_code(code, challenge)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: exchange(code, verifier), range(2)))
    statuses = [r.status_code if isinstance(r, requests.Response) else -1 for r in results]
    check("authorization code concurrent exchange: exactly one success",
          statuses.count(200) == 1 and sum(s >= 400 for s in statuses) == 1, statuses)
    success = next((r for r in results if isinstance(r, requests.Response) and r.status_code == 200), None)
    token_kid = None
    if success is not None:
        try:
            access = success.json()["access_token"]
            token_kid = json.loads(unb64(access.split(".")[0])).get("kid")
            check("access token has a signing kid", bool(token_kid), token_kid)
        except Exception as exc:
            check("successful exchange returns parseable token", False, exc)

    # Concurrent consent submissions must issue exactly one authorization code.
    # Both requests pass CSRF and load the same flow; the flow CAS decides.
    verifier_consent, challenge_consent = pkce()
    csrf = secrets.token_urlsafe(18)
    sid = secrets.token_urlsafe(32)
    consent_payload = {
        "client_id": CLIENT, "redirect_uri": REDIRECT, "response_type": "code",
        "scope": "openid profile", "state": "consent-race",
        "code_challenge": challenge_consent, "code_challenge_method": "S256",
    }
    rid = seed_authorize_flow(csrf, consent_payload, sid)
    def submit_consent(_):
        try:
            return requests.post(
                BASE + "/consent",
                data={"rid": rid, "csrf": csrf, "decision": "allow"},
                headers={"Cookie": "kagi_sid=" + sid},
                allow_redirects=False, timeout=10,
            )
        except Exception as exc:
            return exc
    with ThreadPoolExecutor(max_workers=2) as pool:
        consent_results = list(pool.map(submit_consent, range(2)))
    locations = [r.headers.get("Location", "") for r in consent_results
                 if isinstance(r, requests.Response)]
    issued_codes = [loc for loc in locations if "code=" in loc]
    check("concurrent consent: exactly one authorization code issued",
          len(issued_codes) == 1, locations)
    if issued_codes:
        issued_code = parse_qs(urlparse(issued_codes[0]).query).get("code", [""])[0]
        exchanged = exchange(issued_code, verifier_consent)
        check("concurrent consent: the single code is exchangeable",
              getattr(exchanged, "status_code", -1) == 200,
              getattr(exchanged, "text", exchanged))

    # ACR values must be enforced, not merely echoed.
    acr_params = {
        "client_id": CLIENT, "redirect_uri": REDIRECT, "response_type": "code",
        "scope": "openid profile", "state": "acr-test",
        "code_challenge": pkce()[1], "code_challenge_method": "S256",
        "prompt": "none",
    }
    r = requests.get(BASE + "/authorize",
                     params={**acr_params, "acr_values": "urn:kagi:acr:recovery"},
                     headers={"Cookie": "kagi_sid=" + sid},
                     allow_redirects=False, timeout=10)
    loc = r.headers.get("Location", "")
    check("acr_values mismatch returns unmet_authentication_requirements",
          r.status_code in (302, 303)
          and "error=unmet_authentication_requirements" in loc,
          (r.status_code, loc))
    r = requests.get(BASE + "/authorize",
                     params={**acr_params, "state": "acr-ok",
                             "acr_values": "urn:kagi:acr:passkey"},
                     headers={"Cookie": "kagi_sid=" + sid},
                     allow_redirects=False, timeout=10)
    loc = r.headers.get("Location", "")
    check("acr_values satisfied by a passkey session",
          r.status_code in (302, 303) and "code=" in loc,
          (r.status_code, loc))

    # DPoP proof replay: concurrent requests share a single signed proof/jti.
    # Only one can insert the unique replay-cache key.
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256",
           "x": b64u(nums.x.to_bytes(32, "big")),
           "y": b64u(nums.y.to_bytes(32, "big"))}
    verifier2, challenge2 = pkce()
    proof_jti = b64u(secrets.token_bytes(16))
    proof = make_dpop_proof(key, jwk, proof_jti, "POST", BASE + "/par")
    par = {"client_id": CLIENT, "redirect_uri": REDIRECT, "response_type": "code",
           "scope": "openid profile email", "state": secrets.token_urlsafe(12),
           "nonce": secrets.token_urlsafe(12), "code_challenge": challenge2,
           "code_challenge_method": "S256"}
    def submit_par(_):
        try:
            return requests.post(BASE + "/par", data=par, headers={"DPoP": proof}, timeout=10)
        except Exception as exc:
            return exc
    with ThreadPoolExecutor(max_workers=2) as pool:
        par_results = list(pool.map(submit_par, range(2)))
    par_statuses = [r.status_code if isinstance(r, requests.Response) else -1 for r in par_results]
    par_ok = sum(s in (200, 201) for s in par_statuses)
    check("DPoP replay under concurrency: exactly one accepted",
          par_ok == 1 and sum(s >= 400 for s in par_statuses) == 1,
          par_statuses)

    # Rotate the signing key, verify overlap publication, and ensure a token
    # issued after rotation uses the new key while the old key remains served.
    try:
        before = requests.get(BASE + "/jwks.json", timeout=5).json()
        old_kids = {k.get("kid") for k in before.get("keys", [])}
        rotate = requests.post(BASE + "/admin/keys/rotate",
                               headers={"Authorization": "Bearer " + ADMIN}, timeout=10)
        check("key rotation endpoint succeeds", rotate.status_code == 200, rotate.text[:300])
        rotated = rotate.json() if rotate.status_code == 200 else {}
        new_kid = rotated.get("kid")
        after = requests.get(BASE + "/jwks.json", timeout=5).json()
        after_kids = {k.get("kid") for k in after.get("keys", [])}
        check("rotation publishes new key and retains old verification keys",
              bool(new_kid) and new_kid in after_kids and old_kids.issubset(after_kids),
              {"old": sorted(old_kids), "after": sorted(after_kids), "new": new_kid})
        if token_kid:
            check("pre-rotation token key remains in JWKS",
                  token_kid in after_kids, {"token_kid": token_kid, "after": sorted(after_kids)})

        verifier3, challenge3 = pkce()
        code3 = secrets.token_urlsafe(32)
        insert_code(code3, challenge3)
        post_rotate = exchange(code3, verifier3)
        post_kid = None
        if isinstance(post_rotate, requests.Response) and post_rotate.status_code == 200:
            post_kid = json.loads(unb64(post_rotate.json()["access_token"].split(".")[0])).get("kid")
        check("post-rotation token uses the new key",
              isinstance(post_rotate, requests.Response) and post_rotate.status_code == 200
              and post_kid == new_kid, {"status": getattr(post_rotate, "status_code", -1),
                                        "token_kid": post_kid, "new_kid": new_kid})
    except Exception as exc:
        check("key rotation integration checks", False, exc)

    print("\nFailures:", failures if failures else "none", flush=True)
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(main())
