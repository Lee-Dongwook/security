from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_get_own_order_success():
    response = client.get(
        "/orders/101",
        headers={"Authorization": "Bearer alice-token"}
    )
    assert response.status_code == 200
    assert response.json()["requested_by"] == "alice"

def test_cross_tenant_order_access_denied():
    response = client.get(
        "/orders/102",
        headers={"Authorization": "Bearer alice-token"}
    )
    assert response.status_code == 404

def test_unauthorized_access():
    response = client.get("/orders/101")
    assert response.status_code == 401
