"""Phase 4 guard: SBOM is valid CycloneDX and every pinned dep is captured with a purl."""
import pathlib
from supplychain.gen_sbom import sbom, parse_requirements

ROOT = pathlib.Path(__file__).resolve().parent.parent
REQ = ROOT / "requirements.txt"

def test_sbom_shape():
    doc = sbom(str(REQ))
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert len(doc["components"]) == len(parse_requirements(str(REQ)))

def test_every_component_has_purl():
    for c in sbom(str(REQ))["components"]:
        assert c["purl"].startswith("pkg:pypi/") and c["bom-ref"]

def test_pinned_versions_present():
    comps = {c["name"]: c for c in sbom(str(REQ))["components"]}
    assert comps["fastapi"]["version"] == "0.159.1"   # pinned dep carries its version
