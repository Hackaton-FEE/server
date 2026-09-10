FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

RUN python -m pip install --no-cache-dir uv==0.12.12 \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home app

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY alembic.ini ./
COPY migrations ./migrations
RUN uv sync --frozen --no-dev --no-cache

# Herramientas OSINT reales (opcional; requiere red en el build).
# docker build --build-arg OSINT_REAL=1
ARG OSINT_REAL=0
COPY vendor ./vendor
RUN if [ "$OSINT_REAL" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends git \
        && rm -rf /var/lib/apt/lists/* \
        && ./vendor/osint/setup.sh ; \
    fi

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=2)"

CMD ["uvicorn", "fee_server.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
