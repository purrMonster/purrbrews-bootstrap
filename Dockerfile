# purrbrews-bootstrap: Python standard library only, plus the openssl command
# (used once, to create the TLS key).
FROM python:3.13-alpine

RUN apk add --no-cache openssl

WORKDIR /app
COPY VERSION server.py wrapper.sh ./
COPY web/ ./web/
# client/ (the installer and the key sync) is deliberately not copied in. Those
# scripts change more often than the server, so they are mounted at /client and
# read on every request: edit them and the next machine gets the new version.

# Filled in by the release workflow; harmless defaults for a local build.
ARG VERSION=dev
ARG REVISION=unknown
ARG SOURCE=
LABEL org.opencontainers.image.title="purrbrews-bootstrap" \
      org.opencontainers.image.description="Hands SSH public keys to machines and keeps them in step" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.source="${SOURCE}"

ENV BOOTSTRAP_DATA=/data \
    BOOTSTRAP_CLIENT_DIR=/client \
    BOOTSTRAP_BIND=0.0.0.0 \
    BOOTSTRAP_ADMIN_BIND=0.0.0.0 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Any unprivileged user works; compose sets it to the owner of ./data.
RUN mkdir /data && chown 1000:1000 /data
USER 1000:1000

EXPOSE 8443 8444
VOLUME /data

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -q --no-check-certificate -O /dev/null https://127.0.0.1:8443/healthz || exit 1

CMD ["python3", "/app/server.py"]
