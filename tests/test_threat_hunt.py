"""Phase 3 guard: the hunter must reconstruct the known attack chain in the sample log."""
import pathlib
from dfir.threat_hunt import hunt, parse

SAMPLE = pathlib.Path(__file__).resolve().parent.parent / "dfir" / "sample_audit.jsonl"

def _kinds():
    with open(SAMPLE) as f:
        return {f2[1]: f2 for f2 in hunt(list(parse(f)))}

def test_detects_lateral_movement_with_path():
    f = _kinds()["LATERAL_MOVEMENT"]
    assert f[0] == "HIGH" and f[4], "lateral movement must include a reconstructed path"

def test_detects_ssrf_and_enumeration():
    k = _kinds()
    assert "SSRF_ATTEMPT" in k and "ENUMERATION" in k

def test_ignores_malformed_lines():
    bad = ["not json", '{"timestamp":"bad"}', ""]
    assert list(parse(bad)) == []   # must not raise
