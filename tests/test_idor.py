
from app.auth import create_access_token
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

alice_token = create_access_token({"sub": "alice", "tenant_id": "tenant-a", "role": "MANAGER"})
bob_token = create_access_token({"sub": "bob", "tenant_id": "tenant-b", "role": "MANAGER"})


def test_alice_can_read_her_own_order():
    response = client.get(
        "/orders/101",
        headers={"Authorization": f"Bearer {alice_token}"},
    )

    assert response.status_code == 200
    assert response.json()["order"]["tenant_id"] == "tenant-a"


def test_alice_cannot_read_bobs_order():
    response = client.get(
        "/orders/202",
        headers={"Authorization": f"Bearer {alice_token}"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Order not found"


def test_bob_can_read_his_own_order():
    response = client.get(
        "/orders/202",
        headers={"Authorization": f"Bearer {bob_token}"},
    )

    assert response.status_code == 200
    assert response.json()["order"]["tenant_id"] == "tenant-b"


def test_missing_token_is_rejected():
    response = client.get("/orders/101")

    assert response.status_code == 401


def test_nonexistent_order_returns_404():
    response = client.get(
        "/orders/999",
        headers={"Authorization": f"Bearer {alice_token}"},
    )

    assert response.status_code == 404
