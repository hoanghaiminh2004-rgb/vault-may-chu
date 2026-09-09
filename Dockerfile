# Vault server - lightweight Python image
# Force rebuild: 2026-09-09-v2 (fix github_storage import)
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY vault_server.py .
COPY cookie_vault.py .
COPY github_storage.py .

# Persistent data dir
RUN mkdir -p /data
ENV VAULT_DATA_DIR=/data

# Render sẽ set PORT env tự động
ENV HOST=0.0.0.0
EXPOSE 10000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:10000/health')" || exit 1

# Run
CMD ["python", "-u", "vault_server.py", "--host", "0.0.0.0", "--port", "10000"]
