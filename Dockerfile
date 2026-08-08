# ── Build stage ───────────────────────────────────────────────
FROM python:3.12-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Native dependencies for QR scanning (pyzbar -> zbar)
RUN apt-get update \
    && apt-get install -y --no-install-recommends libzbar0 \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies first (layer caching). The core image stays ML-free;
# optional local inference uses CPU-only PyTorch when requested explicitly.
COPY requirements.txt requirements-ml-runtime.txt ./
ARG INSTALL_LOCAL_AI=false
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && if [ "$INSTALL_LOCAL_AI" = "true" ]; then \
         pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu "torch>=2.11,<2.14" \
         && pip install --no-cache-dir -r requirements-ml-runtime.txt; \
       fi

# Copy application code
COPY . .

# Create upload directory
RUN mkdir -p /app/uploads

# Run as non-root user for security
RUN addgroup --system botuser && adduser --system --ingroup botuser botuser
RUN chown -R botuser:botuser /app/uploads
USER botuser

# Expose API port (used only in --api mode)
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python main.py --healthcheck

CMD ["python", "main.py"]
