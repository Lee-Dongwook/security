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

def get_order_for_tenant(order_id: int, tenant_id: str):
    order = ORDERS.get(order_id)

    if order is None:
        return None
    
    if order["tenant_id"] != tenant_id:
        return None
    
    return order
