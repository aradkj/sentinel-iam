FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install minimal runtime dependencies and clean apt cache
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and group
RUN groupadd --system --gid 10001 appuser \
    && useradd --system --uid 10001 --gid appuser --create-home appuser \
    && mkdir -p /app/keys \
    && chown -R appuser:appuser /app

COPY --chown=appuser:appuser requirements.txt .

RUN pip install --upgrade pip && pip install -r requirements.txt

COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]