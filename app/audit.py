import json
import logging
from datetime import datetime

logger = logging.getLogger("security_audit")
logger.setLevel(logging.INFO)

handler = logging.StreamHandler()
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)

def log_security_event(event_type: str, user_id: str, tenant_id: str, ip: str, details: dict):
    audit_record = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "user_id": user_id or "anonymous",
        "tenant_id": tenant_id or "unknown",
        "client_ip": ip,
        "details": details
    }
    logger.warning(json.dumps(audit_record))
