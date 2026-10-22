from fastapi import FastAPI, Header, HTTPException

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

ORDERS = {
    101: {
        "id": 101,
        "tenant_id": "tenant-a",
        "product": "Laptop",
        "quantity": 2,
    },
    202: {
        "id": 202,
        "tenant_id": "tenant-b",
        "product": "Monitor",
        "quantity": 5,
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

    order = ORDERS.get(order_id)

    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")

    return {
        "requested_by": user["user_id"],
        "order": order,
    }
