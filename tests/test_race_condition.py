import concurrent.futures
import uuid
from fastapi.testclient import TestClient
from app.main import app
from app.auth import create_access_token

client = TestClient(app)
token = create_access_token({"sub": "charlie", "tenant_id": "tenant-c", "role": "USER"})

def send_request():
    return client.post(
        "/orders/limited",
        json={"item": "Limited Server", "amount": 500},
        headers={"Authorization": f"Bearer {token}"}
    )

def test_race_condition_limit():
    unique_tenant = f"tenant-{uuid.uuid4().hex[:8]}"
    token = create_access_token({"sub": "charlie", "tenant_id": unique_tenant, "role": "USER"})
    def send_request():
        return client.post(
            "/orders/limited",
            json={"item": "Limited Server", "amount": 500},
            headers={"Authorization": f"Bearer {token}"}
        )
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(send_request) for _ in range(10)]
        results = [f.result() for f in futures]
        
    success_count = sum(1 for r in results if r.status_code == 201)
    assert success_count == 1
