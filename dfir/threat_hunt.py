#!/usr/bin/env python3
"""Audit-log threat hunter & lateral-movement reconstructor (Phase 3 / DFIR).

Consumes the JSONL security-audit stream emitted by app/audit.py and runs behavioural
hunts that a SIEM correlation rule would, then reconstructs each actor's timeline and
flags tenant-boundary hops (lateral movement).

Audit record schema: timestamp, event_type, user_id, tenant_id, client_ip, details.

Usage:  python dfir/threat_hunt.py <audit.jsonl>        # or pipe via stdin
Exits non-zero when any HIGH-severity chain is found, so it slots into IR automation.
"""
import sys, json, collections, datetime as dt

BURST_WINDOW_S = 60
BURST_THRESHOLD = 10          # events/ip/window => automated enumeration
DENY_EVENTS = {"AUTHZ_DENIED", "IDOR_ATTEMPT", "ACCESS_DENIED", "LOGIN_FAILED"}
HIGH = "HIGH"; MED = "MEDIUM"

def parse(stream):
    for line in stream:
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            r["_t"] = dt.datetime.fromisoformat(r["timestamp"])
            yield r
        except (ValueError, KeyError):
            continue  # skip malformed/truncated lines rather than abort the hunt

def hunt(records):
    records = sorted(records, key=lambda r: r["_t"])
    findings = []
    by_ip = collections.defaultdict(list)
    for r in records:
        by_ip[r.get("client_ip", "unknown")].append(r)

    for ip, evs in by_ip.items():
        tenants = {e.get("tenant_id") for e in evs if e.get("tenant_id") not in (None, "unknown")}
        users = {e.get("user_id") for e in evs if e.get("user_id") not in (None, "anonymous")}

        # --- lateral movement: one source IP touching >1 tenant ---
        if len(tenants) > 1:
            path = [(e["_t"].isoformat(), e.get("tenant_id"), e.get("event_type")) for e in evs]
            findings.append((HIGH, "LATERAL_MOVEMENT", ip,
                             f"source touched {len(tenants)} tenants {sorted(tenants)}; "
                             f"users={sorted(users)}", path))

        # --- SSRF ---
        if any(e.get("event_type") == "SSRF_ATTEMPT_DETECTED" for e in evs):
            urls = [e.get("details", {}).get("blocked_url") for e in evs
                    if e.get("event_type") == "SSRF_ATTEMPT_DETECTED"]
            findings.append((HIGH, "SSRF_ATTEMPT", ip, f"blocked internal targets: {urls}", None))

        # --- enumeration / brute force: burst of denials in a sliding window ---
        denials = sorted(e["_t"] for e in evs if e.get("event_type") in DENY_EVENTS)
        if _max_in_window(denials, BURST_WINDOW_S) >= BURST_THRESHOLD:
            findings.append((HIGH, "ENUMERATION", ip,
                             f"{len(denials)} denied events, >= {BURST_THRESHOLD} within {BURST_WINDOW_S}s", None))

        # --- same user authenticating across tenants: stolen-token / confused-deputy ---
        for u in users:
            ut = {e.get("tenant_id") for e in evs if e.get("user_id") == u}
            ut.discard("unknown")
            if len(ut) > 1:
                findings.append((MED, "IDENTITY_PIVOT", ip,
                                 f"user '{u}' acted under tenants {sorted(ut)}", None))

    order = {HIGH: 0, MED: 1}
    findings.sort(key=lambda f: order.get(f[0], 9))
    return findings

def _max_in_window(sorted_times, window_s):
    """Largest count of timestamps within any `window_s` sliding window."""
    best = i = 0
    for j in range(len(sorted_times)):
        while (sorted_times[j] - sorted_times[i]).total_seconds() > window_s:
            i += 1
        best = max(best, j - i + 1)
    return best

def report(findings):
    if not findings:
        print("threat-hunt: no suspicious patterns found."); return
    print(f"threat-hunt: {len(findings)} finding(s)\n")
    for sev, kind, ip, detail, path in findings:
        print(f"  [{sev:6}] {kind:17} src={ip}\n           {detail}")
        if path:
            print("           lateral path:")
            for t, tenant, ev in path:
                print(f"             {t}  {tenant:10} {ev}")
    print()

def main(argv):
    stream = open(argv[1]) if len(argv) > 1 else sys.stdin
    findings = hunt(list(parse(stream)))
    report(findings)
    return 1 if any(f[0] == HIGH for f in findings) else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
