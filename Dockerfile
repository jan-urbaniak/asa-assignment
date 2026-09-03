FROM python:3.11.16-slim-bookworm AS builder

ENV VIRTUAL_ENV=/opt/venv
RUN python -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt \
    && rm -rf "$VIRTUAL_ENV"/lib/python3.11/site-packages/pip* \
              "$VIRTUAL_ENV"/lib/python3.11/site-packages/setuptools* \
              "$VIRTUAL_ENV"/lib/python3.11/site-packages/wheel* \
              "$VIRTUAL_ENV"/bin/pip*


FROM python:3.11.16-slim-bookworm

ARG APP_PORT=8000

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=${APP_PORT}

RUN addgroup --system --gid 10001 appgroup \
    && adduser --system --uid 10001 --ingroup appgroup appuser

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN rm -rf /usr/local/lib/python3.11/site-packages/wheel* \
           /usr/local/lib/python3.11/site-packages/jaraco* \
           /usr/local/lib/python3.11/site-packages/setuptools*

COPY app/ /app/
RUN chown -R appuser:appgroup /app

USER 10001:10001

EXPOSE ${APP_PORT}

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ['PORT'] + '/health', timeout=3)"]

CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port \"$PORT\""]
