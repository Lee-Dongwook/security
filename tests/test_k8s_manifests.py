"""Phase 1 guardrail: every k8s manifest must parse and declare kind/apiVersion,
and the zero-trust invariants we rely on must stay in place."""
import glob, pathlib, yaml, pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
FILES = sorted(glob.glob(str(ROOT / "deploy/kubernetes/**/*.yaml"), recursive=True))


def _load(path):
    return [d for d in yaml.safe_load_all(open(path)) if d]


@pytest.mark.parametrize("path", FILES, ids=lambda p: pathlib.Path(p).name)
def test_manifest_valid(path):
    docs = _load(path)
    assert docs, f"{path} is empty"
    for d in docs:
        assert d.get("kind") and d.get("apiVersion"), f"{path}: missing kind/apiVersion"


def _find(kind):
    for f in FILES:
        for d in _load(f):
            if d.get("kind") == kind:
                yield d


def test_default_deny_exists():
    np = [d for d in _find("NetworkPolicy") if d["metadata"]["name"] == "default-deny-all"]
    assert np, "default-deny-all NetworkPolicy missing"
    spec = np[0]["spec"]
    assert spec.get("podSelector") == {} and set(spec["policyTypes"]) == {"Ingress", "Egress"}
    assert "ingress" not in spec and "egress" not in spec, "default-deny must have no allow rules"


def test_mtls_strict():
    pa = list(_find("PeerAuthentication"))
    assert pa and pa[0]["spec"]["mtls"]["mode"] == "STRICT"


def test_workload_hardened():
    dep = next(_find("Deployment"))
    c = dep["spec"]["template"]["spec"]["containers"][0]["securityContext"]
    assert c["allowPrivilegeEscalation"] is False
    assert c["readOnlyRootFilesystem"] is True
    assert c["capabilities"]["drop"] == ["ALL"]
