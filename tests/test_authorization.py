from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_get_own_order_success():
    response = client.get(
        "/orders/101",
        headers={"Authorization": "Bearer alice-token"}
    )
    assert response.status_code == 200
    assert response.json()["order"]["tenant_id"] == "tenant-a"

def test_cross_tenant_access_denied():
    response = client.get(
        "/orders/102",
        headers={"Authorization": "Bearer alice-token"}
    )
    assert response.status_code == 404

def test_create_order_scoped_to_tenant():
    response = client.post(
        "/orders",
        json={"item": "Server C", "amount": 3000},
        headers={"Authorization": "Bearer alice-token"}
    )
    assert response.status_code == 201
    assert response.json()["order"]["tenant_id"] == "tenant-a"

def test_cross_tenant_delete_denied():
    response = client.delete(
        "/orders/102",
        headers={"Authorization": "Bearer alice-token"}
    )
    assert response.status_code == 404

def test_unauthorized_access():
    response = client.get("/orders/101")
    assert response.status_code == 401
