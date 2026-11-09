# Supported slim base, pinned by digest (python:3.13-slim, Debian 13).
# python:3.9 is end-of-life and no longer published by docker-library.
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin app

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY app.py database.py ./

USER app

CMD ["python", "app.py"]
