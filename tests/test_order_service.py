
from app.services import get_order_for_tenant


def test_returns_order_for_matching_tenant():
    order = get_order_for_tenant(101, "tenant-a")

    assert order is not None
    assert order["tenant_id"] == "tenant-a"


def test_returns_none_for_different_tenant():
    order = get_order_for_tenant(202, "tenant-a")

    assert order is None


def test_returns_none_for_missing_order():
    order = get_order_for_tenant(999, "tenant-a")

    assert order is None
