FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    curl \
    ca-certificates \
    sqlite3 \
    dos2unix \
    expect \
    iproute2 \
    iputils-ping \
    procps \
    jq \
    openssl \
    python3 \
    && rm -rf /var/lib/apt/lists/*

COPY patch.sh update.sh docker-entrypoint.sh configure-nessus.sh nessus-proxy.sh nessus-api.sh nessus-config.sh nessus-users.sh start-manage-api.sh manage-api.py healthcheck.sh /usr/local/bin/

RUN dos2unix /usr/local/bin/patch.sh \
    /usr/local/bin/update.sh \
    /usr/local/bin/docker-entrypoint.sh \
    /usr/local/bin/configure-nessus.sh \
    /usr/local/bin/nessus-proxy.sh \
    /usr/local/bin/nessus-api.sh \
    /usr/local/bin/nessus-config.sh \
    /usr/local/bin/nessus-users.sh \
    /usr/local/bin/start-manage-api.sh \
    /usr/local/bin/healthcheck.sh \
    && chmod +x \
    /usr/local/bin/patch.sh \
    /usr/local/bin/update.sh \
    /usr/local/bin/docker-entrypoint.sh \
    /usr/local/bin/configure-nessus.sh \
    /usr/local/bin/nessus-api.sh \
    /usr/local/bin/nessus-config.sh \
    /usr/local/bin/nessus-users.sh \
    /usr/local/bin/start-manage-api.sh \
    /usr/local/bin/healthcheck.sh \
    /usr/local/bin/manage-api.py \
    && chmod 644 /usr/local/bin/nessus-proxy.sh

EXPOSE 8835 8080

STOPSIGNAL SIGTERM

CMD ["/usr/local/bin/docker-entrypoint.sh"]
