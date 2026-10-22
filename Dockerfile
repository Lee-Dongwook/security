# Step 1. Build Stage
FROM python:3.10-slim AS builder

WORKDIR /app

COPY requirements.txt . 
RUN pip install --no-cache-dir -r requirements.txt

# Step 2. Runtime Stage
FROM python:3.10-slim

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY . .

RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
