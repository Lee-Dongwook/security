from fastapi.testclient import TestClient
from app.main import app
from app.auth import create_access_token

client = TestClient(app)

alice_token = create_access_token({"sub": "alice", "tenant_id": "tenant-a", "role": "MANAGER"})
bob_token = create_access_token({"sub": "bob", "tenant_id": "tenant-b", "role": "MANAGER"})

def test_get_own_order_success():
    response = client.get(
        "/orders/101",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert response.status_code == 200
    assert response.json()["order"]["tenant_id"] == "tenant-a"

def test_cross_tenant_access_denied():
    response = client.get(
        "/orders/102",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert response.status_code == 404

def test_create_order_scoped_to_tenant():
    response = client.post(
        "/orders",
        json={"item": "Server C", "amount": 3000},
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert response.status_code == 201
    assert response.json()["order"]["tenant_id"] == "tenant-a"

def test_cross_tenant_delete_denied():
    response = client.delete(
        "/orders/102",
        headers={"Authorization": f"Bearer {alice_token}"}
    )
    assert response.status_code == 404

def test_unauthorized_access():
    response = client.get("/orders/101")
    assert response.status_code == 401
