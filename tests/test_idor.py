from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_alice_can_read_her_own_order():
    response = client.get(
        "/orders/101",
        headers={"Authorization": "Bearer alice-token"},
    )

    assert response.status_code == 200
    assert response.json()["order"]["tenant_id"] == "tenant-a"

def test_alice_can_read_bobs_order_idor():
    response = client.get(
        "/orders/202",
        headers={"Authorization": "Bearer alice-token"},
    )

    assert response.status_code == 200
    assert response.json()["order"]["tenant_id"] == "tenant-b"

def test_missing_token_is_rejected():
    response = client.get("/orders/101")

    assert response.status_code == 401
