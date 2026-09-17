FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    AGENTGATE_ENV=production AGENTGATE_PUBLIC_DEMO=true AGENTGATE_DEV_MODE=false \
    AGENTGATE_DATABASE_URL=sqlite:////app/data/agentgate.db \
    AGENTGATE_ALLOWED_HOSTS='["localhost","127.0.0.1","*.hf.space"]'
WORKDIR /app
RUN useradd --uid 1000 --create-home agentgate
COPY . .
RUN if [ -f requirements.lock ]; then pip install --no-cache-dir -r requirements.lock; fi \
    && pip install --no-cache-dir . \
    && mkdir -p /app/data \
    && chown -R 1000:1000 /app
USER 1000:1000
EXPOSE 7860
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7860/healthz', timeout=3)" || exit 1
CMD ["sh", "-c", "python -m agentgate.cli init-db && exec uvicorn agentgate.api.app:app --host 0.0.0.0 --port 7860 --workers 1"]
