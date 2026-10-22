from fastapi import FastAPI, HTTPException, Depends, status
from app.auth import verify_jwt_token, create_access_token
from app.models import OrderCreate
from app.database import (
    get_order_for_tenant,
    create_order_for_tenant,
    delete_order_for_tenant
)

app = FastAPI(title="AppSec IDOR Lab")

@app.post("/token")
def issue_token(user_id: str, tenant_id: str, role: str = "MANAGER"):
    token = create_access_token({"sub": user_id, "tenant_id": tenant_id, "role": role})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/orders/{order_id}")
def get_order(
    order_id: int,
    user: dict = Depends(verify_jwt_token)
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
    user: dict = Depends(verify_jwt_token)
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
    user: dict = Depends(verify_jwt_token)
):
    success = delete_order_for_tenant(
        order_id=order_id,
        tenant_id=user["tenant_id"]
    )
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")
    return {"status": "success", "deleted_order_id": order_id}
