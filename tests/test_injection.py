from fastapi.testclient import TestClient
from app.main import app
from app.auth import create_access_token

client = TestClient(app)
token = create_access_token({"sub": "alice", "tenant_id": "tenant-a", "role": "MANAGER"})

def test_sql_injection_vulnerable_payload():
    malicious_payload = "' OR '1'='1"
    response = client.get(
        f"/vulnerable/search?keyword={malicious_payload}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert len(response.json()["results"]) >= 2

def test_sql_injection_secure_payload():
    malicious_payload = "' OR '1'='1"
    response = client.get(
        f"/secure/search?keyword={malicious_payload}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    for row in response.json()["results"]:
        assert row[1] == "tenant-a"

def test_xss_payload_rejection():
    response = client.post(
        "/orders",
        json={"item": "<script>alert(1)</script>Server X", "amount": 1500},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 422 
