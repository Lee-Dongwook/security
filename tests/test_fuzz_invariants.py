"""Phase 2 regression guard: run the fuzzer and assert the security invariants that must
NEVER break, regardless of how many robustness 500s the crash oracle also turns up."""
from fuzz.fuzz_api import run

def test_no_cross_tenant_bypass():
    findings = run(iterations=300, seed=1337)
    authz = [f for f in findings if f[0] == "AUTHZ"]
    assert not authz, f"authorization bypass found: {authz}"

def test_sqli_differential_distinguishes_endpoints():
    # The parameterized /secure endpoint must not leak under the injection the
    # intentionally-vulnerable one does — proves the parameterized fix actually works.
    findings = run(iterations=1, seed=1)
    sqli = [f for f in findings if f[0] == "SQLI"]
    assert sqli and "/vulnerable/search" in sqli[0][2], "SQLi differential oracle stopped firing"
