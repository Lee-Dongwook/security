import ipaddress
import socket
from urllib.parse import urlparse
from fastapi import HTTPException

def validate_external_url(url: str):
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
            raise HTTPException(status_code=400, detail="Access to internal networks is blocked")
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Could not resolve hostname")

