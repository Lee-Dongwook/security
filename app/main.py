from fastapi import FastAPI, Header, HTTPException, Depends, status
from app.models import OrderCreate, OrderUpdate
from app.database import (
    get_order_for_tenant,
    create_order_for_tenant,
    delete_order_for_tenant
)

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

def get_current_user(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    token = authorization.removeprefix("Bearer ")
    user = USERS.get(token)

    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    return user

@app.get("/orders/{order_id}")
def get_order(
    order_id: int,
    user: dict = Depends(get_current_user)
):
    order = get_order_for_tenant(
        order_id=order_id,
        tenant_id=user["tenant_id"] 
    )

    if order is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

    return {
        "requested_by": user["user_id"],
        "order": order,
    }

@app.post("/orders", status_code=status.HTTP_201_CREATED)
def create_order(
    payload: OrderCreate,
    user: dict = Depends(get_current_user)
):
    order = create_order_for_tenant(
        tenant_id=user["tenant_id"],
        item=payload.item,
        amount=payload.amount
    )
    return {
        "requested_by": user["user_id"],
        "order": order
    }

@app.delete("/orders/{order_id}")
def delete_order(
    order_id: int,
    user: dict = Depends(get_current_user)
):
    success = delete_order_for_tenant(
        order_id=order_id,
        tenant_id=user["tenant_id"]
    )
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")
    return {"status": "success", "deleted_order_id": order_id}
