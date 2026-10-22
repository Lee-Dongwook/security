from fastapi import FastAPI, Header, HTTPException
from app.services import get_order_for_tenant

app = FastAPI(title="AppSec IDOR Lab")

USERS = {
    "alice-token": {
        "user_id": "alice",
        "tenant_id": "tenant-a",
        "role": "MANAGER",
    },
    "bob-token": {
        "user_id": "bob",
        "tenant_id": "tenant-b",
        "role": "MANAGER",
    },
}

def get_current_user(authorization: str | None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    token = authorization.removeprefix("Bearer ")
    user = USERS.get(token)

    if user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return user

@app.get("/orders/{order_id}")
def get_order(
    order_id: int,
    authorization: str | None = Header(default=None),
):
    user = get_current_user(authorization)

    order = get_order_for_tenant(
        order_id=order_id,
        tenant_id=user["tenant_id"],
    )

    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")

    return {
        "requested_by": user["user_id"],
        "order": order,
    }
