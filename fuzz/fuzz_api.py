#!/usr/bin/env python3
"""Schema-driven mutation fuzzer for the AppSec API (Phase 2).

Authorized testing of this repo's OWN endpoints via FastAPI TestClient — no network,
no new dependencies. Reads the live OpenAPI schema, mutates every operation's path/query/
body with a nasty-value corpus, and runs three oracles:

  1. CRASH   — any 5xx is an unhandled server error (the classic fuzzing signal).
  2. AUTHZ   — a tenant-A token must never read/delete a tenant-B order (IDOR/BOLA).
  3. SQLI    — differential: /vulnerable/search leaks rows /secure/search refuses to.

Run:  python fuzz/fuzz_api.py [iterations] [seed]
Exits non-zero if any finding fires, so it drops straight into CI.
"""
import sys, os, random, string, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import warnings; warnings.filterwarnings("ignore")
from fastapi.testclient import TestClient
from app.main import app

# --- mutation corpus: values that have historically broken parsers/queries/logic ---
NASTY = [
    "", " ", "\x00", "A" * 4096, "%s%s%s%n", "../../../../etc/passwd",
    "' OR '1'='1", "'; DROP TABLE orders;--", "\" OR 1=1--", "1 UNION SELECT 1,2,3,4",
    "<script>alert(1)</script>", "{{7*7}}", "${jndi:ldap://x}", "../",
    -1, 0, 2**63, -(2**63), 1.5, float("inf"), float("nan"),
    True, None, [], {}, {"$ne": None}, "٠١٢٣", "🧨", "\n\r\t",
]

def tok(client, tenant, role="MANAGER", user="u"):
    r = client.post("/token", params={"user_id": user, "tenant_id": tenant, "role": role})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}

def rand_val(rng):
    return rng.choice(NASTY) if rng.random() < 0.8 else "".join(
        rng.choice(string.printable) for _ in range(rng.randint(0, 40)))

def coerce_path(v):
    # path params can't carry None/containers; stringify into something routable
    return str(v).replace("/", "%2F")[:200] or "x"

def run(iterations=400, seed=1337):
    rng = random.Random(seed)
    unsendable = [0]
    client = TestClient(app, raise_server_exceptions=False)
    hdr = tok(client, "tenant-a")
    spec = client.get("/openapi.json").json()
    findings = []

    ops = []
    for path, methods in spec["paths"].items():
        for method, meta in methods.items():
            ops.append((method.upper(), path, meta))

    # ---- oracle 1: crash fuzzing over every operation ----
    for _ in range(iterations):
        method, path, meta = rng.choice(ops)
        url = path
        for p in meta.get("parameters", []):
            if p["in"] == "path":
                url = url.replace("{%s}" % p["name"], coerce_path(rand_val(rng)))
        query = {p["name"]: rand_val(rng) for p in meta.get("parameters", []) if p["in"] == "query"}
        body = None
        if "requestBody" in meta:
            body = {k: rand_val(rng) for k in ("item", "amount", "target_url", "keyword")}
        try:
            r = client.request(method, url, params=_clean(query), json=body, headers=hdr)
        except Exception:
            unsendable[0] += 1   # client refused to encode the input; never reached the app
            continue
        if r.status_code >= 500:
            findings.append(("CRASH", method, path, f"{r.status_code} on input reaching the handler"))

    # ---- oracle 2: cross-tenant authorization (IDOR/BOLA) ----
    hb = tok(client, "tenant-b", user="victim")
    created = client.post("/orders", json={"item": "secret-b", "amount": 10}, headers=hb)
    if created.status_code < 300:
        oid = created.json()["order"]["order_id"]
        for method in ("GET", "DELETE"):
            r = client.request(method, f"/orders/{oid}", headers=hdr)  # tenant-A reaching tenant-B's order
            if r.status_code < 300:
                findings.append(("AUTHZ", method, f"/orders/{oid}",
                                 f"tenant-a read tenant-b order -> {r.status_code}"))

    # ---- oracle 3: SQLi differential (vulnerable vs secure) ----
    payload = {"keyword": "' OR '1'='1"}
    vuln = client.get("/vulnerable/search", params=payload, headers=hdr)
    safe = client.get("/secure/search", params=payload, headers=hdr)
    if vuln.status_code < 300 and safe.status_code < 300:
        nv, ns = len(vuln.json()["results"]), len(safe.json()["results"])
        if nv > ns:
            findings.append(("SQLI", "GET", "/vulnerable/search",
                             f"injection returned {nv} rows vs {ns} from parameterized endpoint"))

    report(findings, iterations, seed, unsendable[0])
    return findings

def _clean(d):  # TestClient rejects non-scalar query values
    return {k: v for k, v in d.items() if isinstance(v, (str, int, float, bool))}

def report(findings, iterations, seed, unsendable=0):
    # dedupe: one row per (kind, method, route)
    seen, uniq = set(), []
    for f in findings:
        k = f[:3]
        if k not in seen:
            seen.add(k); uniq.append(f)
    findings = uniq
    print(f"\nfuzz: {iterations} iterations, seed={seed}, {unsendable} inputs rejected client-side")
    if not findings:
        print("no findings — all oracles passed."); return
    print(f"{len(findings)} finding(s):\n")
    for kind, method, where, detail in findings:
        print(f"  [{kind:5}] {method:6} {where}\n          {detail}")

if __name__ == "__main__":
    it = int(sys.argv[1]) if len(sys.argv) > 1 else 400
    sd = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
    sys.exit(1 if run(it, sd) else 0)
