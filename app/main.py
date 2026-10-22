from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import HttpUrl, BaseModel
from app.auth import verify_jwt_token, create_access_token
from app.models import OrderCreate
from app.database import (
    init_db,
    get_db_connection,
    get_order_for_tenant,
    create_order_for_tenant,
    create_order_safe_concurrency,
    delete_order_for_tenant
)
from app.utils import validate_external_url
import httpx
from app.middleware import rate_limiter

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="AppSec IDOR Lab", lifespan=lifespan)

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

@app.post("/orders/limited", status_code=201)
def create_limited_order(payload: OrderCreate, user: dict = Depends(verify_jwt_token)):
    order, error = create_order_safe_concurrency(user["tenant_id"], payload.item, payload.amount, max_limit=1)
    if error:
        raise HTTPException(status_code=400, detail=error)
    return {"requested_by": user["user_id"], "order": order}

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

@app.get("/vulnerable/search")
def search_orders_vulnerable(keyword: str, user: dict = Depends(verify_jwt_token)):
    conn = get_db_connection()
    cursor = conn.cursor()

    # SQL Injection 발생 가능 문장 - 원래는 취약점으로 바로 탐색해야 하나, 본 레포에선 의도적 배선이므로 일단 스캔을 생략한다.
    query = f"SELECT * FROM orders WHERE tenant_id = '{user['tenant_id']}' AND item LIKE '%{keyword}%'" # nosec

    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return {"results": rows}

@app.get("/secure/search")
def search_orders_secure(keyword: str, user: dict = Depends(verify_jwt_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 안전: 파라미터 바인딩 사용
    query = "SELECT order_id, tenant_id, item, amount FROM orders WHERE tenant_id = ? AND item LIKE ?"
    cursor.execute(query, (user['tenant_id'], f"%{keyword}%"))
    rows = cursor.fetchall()
    conn.close()
    return {"results": rows}

class WebhookRequest(PydanticModel := object):
    pass

class WebhookPayload(BaseModel):
    target_url: str

@app.post("/webhook/trigger")
def trigger_webhook(payload: WebhookPayload, user: dict = Depends(verify_jwt_token)):
    validate_external_url(payload.target_url)

    return {"status": "success", "dispatched_to": payload.target_url}

@app.post("/orders/secure", dependencies=[Depends(rate_limiter)])
def create_secure_order(payload: OrderCreate, user: dict = Depends(verify_jwt_token)):
    order = create_order_for_tenant(
        tenant_id=user["tenant_id"],
        item=payload.item,
        amount=payload.amount
    )

    return {
        "status": "created", 
        "tenant": user["tenant_id"], 
        "requested_by": user["user_id"],
        "order": order
    }
