from fastapi.testclient import TestClient
from app.main import app
from app.auth import create_access_token

client = TestClient(app)

def test_jwt_authentication_success():
    token = create_access_token({"sub": "alice", "tenant_id": "tenant-a", "role": "MANAGER"})
    response = client.get(
        "/orders/101",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200

def test_jwt_invalid_signature():
    response = client.get(
        "/orders/101",
        headers={"Authorization": "Bearer invalid.jwt.signature"}
    )
    assert response.status_code == 401
