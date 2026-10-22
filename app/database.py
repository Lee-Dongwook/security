import sqlite3
import os

DB_PATH = os.getenv("DB_PATH", "app.db")

def get_db_connection():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders(
            order_id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            item TEXT NOT NULL,
            amount INTEGER NOT NULL
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM orders")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT OR IGNORE INTO orders (order_id, tenant_id, item, amount) VALUES (101, 'tenant-a', 'Server A', 1000)")
        cursor.execute("INSERT OR IGNORE INTO orders (order_id, tenant_id, item, amount) VALUES (102, 'tenant-b', 'Server B', 2000)")
        cursor.execute("INSERT INTO orders (order_id, tenant_id, item, amount) VALUES (202, 'tenant-b', 'Server C', 3000)")
    conn.commit()
    conn.close()

init_db()

def get_order_for_tenant(order_id: int, tenant_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT order_id, tenant_id, item, amount FROM orders WHERE order_id = ? AND tenant_id = ?",
        (order_id, tenant_id)
    )

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None
    return {"order_id": row[0], "tenant_id": row[1], "item": row[2], "amount": row[3]}

def create_order_for_tenant(tenant_id: str, item: str, amount: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO orders (tenant_id, item, amount) VALUES (?, ?, ?)",
        (tenant_id, item, amount)
    )
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    
    return {
        "order_id": new_id,
        "tenant_id": tenant_id,
        "item": item,
        "amount": amount
    }

def create_order_safe_concurrency(tenant_id: str, item: str, amount: int, max_limit: int = 1):
    conn = get_db_connection()
    # BEGIN EXCLUSIVE -> 트랜잭션 시작 시점에서 write Lock
    conn.execute("BEGIN EXCLUSIVE;")
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM orders WHERE tenant_id = ?", (tenant_id,))
        current_count = cursor.fetchone()[0]

        if current_count >= max_limit:
            conn.rollback()
            return None, "Limit exceeded"
        
        cursor.execute(
            "INSERT INTO orders (tenant_id, item, amount) VALUES (?, ?, ?)",
            (tenant_id, item, amount)
        )
        conn.commit()
        new_id = cursor.lastrowid
        return {"order_id": new_id, "tenant_id": tenant_id, "item": item, "amount": amount}, None
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def delete_order_for_tenant(order_id: int, tenant_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM orders WHERE order_id = ? AND tenant_id = ?",
        (order_id, tenant_id)
    )
    conn.commit()
    affected_rows = cursor.rowcount
    conn.close()
    
    return affected_rows > 0
