# Supported slim base, pinned by digest (python:3.13-slim, Debian 13).
# python:3.9-slim is end-of-life and no longer published by docker-library.
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Unprivileged user. It owns files/ (shared files; a bind mount in compose)
# and downloads/ (where client.py saves downloads, relative to /app).
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin app \
 && mkdir -p /app/files /app/downloads \
 && chown app:app /app/files /app/downloads

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

# client.py imports blockchain_logger.blockchain_logger from this build
# context (peer_client/blockchain_logger), not the copy in p2p/blockchain_logger.
COPY client.py server.py safe_paths.py ./
COPY blockchain_logger/blockchain_logger.py ./blockchain_logger/

USER app

# docker-compose.yml overrides this with `tail -f /dev/null`; the client is
# interactive and is run with `docker exec -it <peer> python client.py`.
CMD ["python", "client.py"]
