FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285

LABEL org.opencontainers.image.title="Traceyard" \
      org.opencontainers.image.description="Standalone trace search UI for Grafana Tempo" \
      org.opencontainers.image.source="https://github.com/fegasaren/traceyard" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --requirement /app/requirements.txt
COPY --chown=10001:10001 server.py demo.py security.py /app/
COPY --chown=10001:10001 LICENSE /app/LICENSE
COPY --chown=10001:10001 static/ /app/static/

USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '8080') + '/healthz', timeout=3).close()"]

CMD ["python", "/app/server.py"]
