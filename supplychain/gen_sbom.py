#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 SBOM from requirements.txt (Phase 4 / supply chain).

Dependency-free: stdlib only. The SBOM is the input to cosign attestation and SLSA
provenance in .github/workflows/supply-chain.yml.

Usage:  python supplychain/gen_sbom.py [requirements.txt] > sbom.json
"""
import sys, re, json, uuid, hashlib, datetime

PIN = re.compile(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)")

def parse_requirements(path):
    comps = []
    for line in open(path):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = PIN.match(line)
        if not m:   # unpinned (>=, ~=, extras) — recorded without a concrete version
            name = re.split(r"[<>=!~\[ ]", line, 1)[0]
            comps.append((name, None))
        else:
            comps.append((m.group(1), m.group(2)))
    return comps

def sbom(path):
    comps = parse_requirements(path)
    serial = "urn:uuid:" + str(uuid.uuid4())
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tools": [{"vendor": "appsec", "name": "gen_sbom.py", "version": "1.0"}],
            "component": {"type": "application", "name": "security-api", "bom-ref": "security-api"},
        },
        "components": [
            {
                "type": "library",
                "name": name,
                **({"version": ver} if ver else {}),
                "purl": f"pkg:pypi/{name.lower()}" + (f"@{ver}" if ver else ""),
                "bom-ref": f"pkg:pypi/{name.lower()}@{ver or 'unpinned'}",
            }
            for name, ver in comps
        ],
    }

if __name__ == "__main__":
    req = sys.argv[1] if len(sys.argv) > 1 else "requirements.txt"
    doc = sbom(req)
    out = json.dumps(doc, indent=2)
    sys.stderr.write(f"sbom: {len(doc['components'])} components, serial {doc['serialNumber']}\n")
    print(out)
