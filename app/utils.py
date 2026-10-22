import ipaddress
import socket
from urllib.parse import urlparse
from fastapi import HTTPException
from app.audit import log_security_event

def validate_external_url(url: str, request_ip: str = "unknown", user_id: str = "unknown"):
    parsed = urlparse(url)

    if parsed.scheme not in ["http", "https"]:
        raise HTTPException(status_code=400, detail="Invalid URL scheme")
    
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid hostname")
    
    try:
        ip_str = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip_str)

        if (ip_obj.is_private or 
            ip_obj.is_loopback or 
            ip_obj.is_link_local or 
            ip_obj.is_reserved):
            log_security_event(
                event_type="SSRF_ATTEMPT_DETECTED",
                user_id=user_id,
                tenant_id="unknown",
                ip=request_ip,
                details={"blocked_url": url}
            )
            raise HTTPException(status_code=400, detail="Access to internal networks is blocked")
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Could not resolve hostname")

