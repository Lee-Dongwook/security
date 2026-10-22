ORDERS_DB = {
    101: {"order_id": 101, "tenant_id": "tenant-a", "item": "Server A", "amount": 1000},
    102: {"order_id": 102, "tenant_id": "tenant-b", "item": "Server B", "amount": 2000},
    202: {"order_id": 202, "tenant_id": "tenant-b", "item": "Server C", "amount": 3000},
}

def get_order_for_tenant(order_id: int, tenant_id: str):
    order = ORDERS_DB.get(order_id)
    if not order or order["tenant_id"] != tenant_id:
        return None
    return order

def create_order_for_tenant(tenant_id: str, item: str, amount: int):
    new_id = max(ORDERS_DB.keys(), default=100) + 1
    new_order = {
        "order_id": new_id,
        "tenant_id": tenant_id,
        "item": item,
        "amount": amount
    }
    ORDERS_DB[new_id] = new_order
    return new_order

def delete_order_for_tenant(order_id: int, tenant_id: str):
    order = get_order_for_tenant(order_id, tenant_id)
    if not order:
        return False
    del ORDERS_DB[order_id]
    return True
