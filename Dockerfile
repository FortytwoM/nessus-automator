FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
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

COPY patch.sh update.sh docker-entrypoint.sh configure-nessus.sh configure-dns.sh configure-dns.py nessus-proxy.sh nessus-api.sh nessus-config.sh nessus-users.sh start-manage-api.sh manage-api.py secure-download.py nessus-status.py nessus_status_lib.py nessus_url_policy.py update-snapshot.py healthcheck.sh /usr/local/bin/

RUN dos2unix /usr/local/bin/patch.sh \
    /usr/local/bin/update.sh \
    /usr/local/bin/docker-entrypoint.sh \
    /usr/local/bin/configure-nessus.sh \
    /usr/local/bin/configure-dns.sh \
    /usr/local/bin/configure-dns.py \
    /usr/local/bin/nessus-proxy.sh \
    /usr/local/bin/nessus-api.sh \
    /usr/local/bin/nessus-config.sh \
    /usr/local/bin/nessus-users.sh \
    /usr/local/bin/start-manage-api.sh \
    /usr/local/bin/secure-download.py \
    /usr/local/bin/nessus-status.py \
    /usr/local/bin/update-snapshot.py \
    /usr/local/bin/healthcheck.sh \
    && chmod +x \
    /usr/local/bin/patch.sh \
    /usr/local/bin/update.sh \
    /usr/local/bin/docker-entrypoint.sh \
    /usr/local/bin/configure-nessus.sh \
    /usr/local/bin/configure-dns.sh \
    /usr/local/bin/configure-dns.py \
    /usr/local/bin/nessus-api.sh \
    /usr/local/bin/nessus-config.sh \
    /usr/local/bin/nessus-users.sh \
    /usr/local/bin/start-manage-api.sh \
    /usr/local/bin/secure-download.py \
    /usr/local/bin/nessus-status.py \
    /usr/local/bin/update-snapshot.py \
    /usr/local/bin/healthcheck.sh \
    /usr/local/bin/manage-api.py \
    && chmod 644 /usr/local/bin/nessus-proxy.sh

EXPOSE 8835 8080

STOPSIGNAL SIGTERM

CMD ["/usr/local/bin/docker-entrypoint.sh"]
