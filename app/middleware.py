import time
from collections import defaultdict
from fastapi import HTTPException, Request

request_records = defaultdict(list)

def rate_limiter(request: Request, max_requests: int = 5, window_seconds: int = 60):
    client_ip = request.client.host
    now = time.time()

    history = request_records[client_ip]
    history = [t for t in history if now - t < window_seconds]

    if len(history) >= max_requests:
        raise HTTPException(status_code=429, detail="Too Many Requests. Rate limit exceeded.")
    
    history.append(now)
    request_records[client_ip] = history
