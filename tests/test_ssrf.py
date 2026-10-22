from fastapi.testclient import TestClient
from app.main import app
from app.auth import create_access_token

client = TestClient(app)
token = create_access_token({"sub": "dave", "tenant_id": "tenant-d", "role": "USER"})

def test_ssrf_blocked_internal_ip():
    response = client.post(
        "/webhook/trigger",
        json={"target_url": "http://127.0.0.1:8000/admin"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Access to internal networks is blocked"

def test_ssrf_blocked_metadata_ip():
    response = client.post(
        "/webhook/trigger",
        json={"target_url": "http://169.254.169.254/latest/meta-data/"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 400
