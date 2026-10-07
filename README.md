# Nessus Automator

**English** | [Русский](README.ru.md)

A containerized Tenable Nessus deployment with controlled plugin updates,
scan-source IP selection, and a hardened HTTPS gateway.

## Features

- install Nessus from a local `.deb` or an approved HTTPS source;
- online and offline plugin feed updates;
- select `source_ip` on multi-homed hosts;
- configure the Nessus container DNS resolver;
- expose a single nginx endpoint on TCP/8834;
- manage updates, holds, and readiness through the Operator API;
- wait for active scans before applying an update;
- enforce URL allowlists, DNS and redirect checks, size limits, and timeouts;
- use a stable internal CA or ACME certificate;
- validate host IPs, routes, TLS, ports, and firewalld before deployment.

## Architecture

```text
Client
  │
  ▼ HTTPS :8834
gateway (nginx)
  ├── /manage/v1/* ──► Operator API 127.0.0.1:8080
  └── all other paths ► Nessus       127.0.0.1:8835
```

Both containers use `network_mode: host` on Linux. That lets Nessus originate
scan traffic from a physical host-interface IP. The Nessus backend and
Operator API remain bound to loopback; only the gateway is externally
accessible. Docker Desktop instead uses `docker-compose.desktop.yml`: a
bridge network with `127.0.0.1:8834` published to the host.

## Requirements

Production:

- Linux with Docker Engine and Docker Compose;
- firewalld;
- management and scan-source IPs assigned to host interfaces;
- policy routing for the scan-source IP;
- a certificate, private key, and trusted CA chain.

Local testing is supported on Docker Desktop for Windows/macOS. Host
networking cannot expose `https://127.0.0.1:8834` to the Windows localhost,
so the desktop overlay publishes that port on a bridge network.

## Local Windows setup

Copy the configuration template:

```powershell
Copy-Item env.example .env
```

Set at least:

```env
NESSUS_USERNAME=admin
NESSUS_PASSWORD=replace-with-a-strong-password
GATEWAY_BIND_IP=127.0.0.1
GATEWAY_CERT_DIR=./certs
```

Select an installer and plugin feed source in `.env`. The passwords `admin`
and `changeme` are rejected.

Generate a local certificate from Git Bash or WSL:

```bash
bash scripts/bootstrap-trust.sh 127.0.0.1 localhost
```

Trust the CA for the current Windows user:

```powershell
certutil -user -addstore Root .\certs\ca.pem
```

Start the stack. On Docker Desktop, include the desktop overlay so the UI
is published on `127.0.0.1:8834`:

```powershell
python .\nessusctl.py start
docker compose -f docker-compose.yml -f docker-compose.desktop.yml ps
```

Equivalent Compose command:

```powershell
docker compose -f docker-compose.yml -f docker-compose.desktop.yml up -d --build
```

Open the UI only after both containers report `healthy`:

```text
https://localhost:8834
```

Verify it from PowerShell:

```powershell
curl.exe --fail --ssl-revoke-best-effort `
  --cacert certs/ca.pem `
  https://127.0.0.1:8834/manage/v1/health
```

Physical scan-source routing must be tested on the target Linux host, not in
Docker Desktop.

## Production Linux setup

Example host:

- management: `ens224`, `195.239.191.98`;
- scanning: `ens256`, `195.239.191.99`.

Core configuration:

```env
NESSUS_USERNAME=admin
NESSUS_PASSWORD=replace-with-a-strong-password

GATEWAY_BIND_IP=195.239.191.98
GATEWAY_ALLOWED_CIDRS=10.20.30.0/24
GATEWAY_CERT_DIR=./certs

NESSUS_SOURCE_IP=195.239.191.99

NESSUS_DNS_SERVERS=10.10.0.53,10.10.0.54
NESSUS_DNS_SEARCH=corp.example.internal
```

`GATEWAY_ALLOWED_CIDRS` must contain administrator or VPN source networks, not
the scanning network. Use `/32` for one workstation and commas for multiple
networks.

`NESSUS_DNS_SERVERS` accepts one to three comma-separated IPv4 or IPv6
addresses. `NESSUS_DNS_SEARCH` accepts comma- or space-separated search
domains. These values replace the resolver configuration only inside the
Nessus container on every start; they do not modify host DNS. The configured
servers must resolve the Tenable download hosts in online mode.

Place these files in `GATEWAY_CERT_DIR`:

```text
cert.pem  — leaf certificate or full chain
key.pem   — private key
ca.pem    — trusted CA chain
```

The certificate SAN must contain `GATEWAY_BIND_IP` or the DNS name used by
clients. To create a dedicated internal CA:

```bash
bash scripts/bootstrap-trust.sh 195.239.191.98 nessus.example.internal
```

Distribute `certs/ca.pem` to clients before deployment. The gateway enables
HSTS and is not designed for certificate-validation exceptions.

Apply the firewall policy and deploy:

```bash
sudo bash scripts/host-preflight.sh --apply-firewall
bash scripts/deploy.sh
```

For subsequent deployments:

```bash
bash scripts/deploy.sh
```

Preflight validates the bind and source IPs, source route, TLS files, port
owners, and firewalld restrictions. nginx enforces the same administrator
CIDRs with `allow` and `deny`.

## Installation and plugin feeds

### Online mode

Configure the Tenable feed URL:

```env
NESSUS_PROFILE=online
NESSUS_UPDATE_URL=https://plugins.nessus.org/v2/nessus.php?f=all-2.0.tar.gz&u=...&p=...
```

A remote installer can be provided explicitly:

```env
NESSUS_DEB_URL=https://downloads.tenable.com/...
NESSUS_DEB_SHA256=...
```

The preferred installation method is to place one
`Nessus-*-debian10_amd64.deb` file in `packages/`.

### Offline mode

Place these files in `packages/`:

```text
Nessus-*-debian10_amd64.deb
all-2.0.tar.gz
```

Configure:

```env
NESSUS_PROFILE=offline
NESSUS_PLUGIN_SET=202609100156
```

`NESSUS_PLUGIN_SET` is the 12-digit feed ID matching the archive. The
`packages/` directory is mounted read-only at `/mnt/nessus`.

Update-source priority:

1. an archive supplied through the Operator API;
2. `NESSUS_UPDATE_FILE`;
3. `/mnt/nessus/all-2.0.tar.gz`;
4. `NESSUS_UPDATE_URL`.

A modern `all-2.0.tar.gz` may begin with `23 45 89 17` and is not necessarily
a regular gzip archive. Do not validate it with `gzip -t`.

Nessus 10.12 and newer require a detached signature for a plugin archive. For
the `NESSUS_UPDATE_URL` source the signature (`all-2.0.tar.gz.sig`) is
downloaded automatically from the same URL and passed to `nessuscli update`.
For a local archive, place the signature next to it as `<archive>.sig`; it is
used when present and ignored by older Nessus versions that do not need it.

## Secure downloads

Defaults:

```env
NESSUS_DOWNLOAD_ALLOWED_SCHEMES=https
NESSUS_DOWNLOAD_ALLOWED_HOSTS=plugins.nessus.org,*.tenable.com
NESSUS_DOWNLOAD_ALLOWED_PORTS=443
NESSUS_DOWNLOAD_MAX_BYTES=1073741824
NESSUS_MANAGE_MAX_UPLOAD_BYTES=1073741824
NESSUS_DOWNLOAD_FS_SIZE=2300m
NESSUS_DOWNLOAD_TIMEOUT=1800
```

The hostname, resolved addresses, scheme, and port are checked before each
request and redirect. The connection is pinned to one of those checked
addresses while TLS SNI and certificate validation continue to use the
original hostname. Private, loopback, link-local, reserved, multicast, and
unspecified addresses are rejected. TLS validation is mandatory.

Downloads and multipart uploads use the size-limited
`/var/lib/nessus-downloads` tmpfs and are removed after completion or failure.

## Readiness

The Nessus container remains in `health: starting`, and the gateway does not
start until bootstrap confirms both `engine_status=ready` and
`pluginData=true`.

The readiness endpoint does not require authentication:

```bash
curl --fail --cacert "$NESSUS_CA_CERT" \
  "$BASE/manage/v1/health"
```

Example:

```json
{
  "status": "ok",
  "operator_version": "2.5",
  "ready": true,
  "plugin_set": "202609100156",
  "plugin_data": true,
  "engine_status": "ready",
  "engine_progress": 100,
  "update_state": "idle",
  "update_in_progress": false,
  "hold_active": false
}
```

Start scans only when `ready` is `true`.

## Management

Create API keys in `Settings → My Account → API Keys`.

```bash
BASE=https://nessus.example.internal:8834
NESSUS_CA_CERT=/etc/ssl/certs/company-root-ca.pem
KEYS='accessKey=...; secretKey=...'
```

List scans:

```bash
curl --fail --cacert "$NESSUS_CA_CERT" \
  -H "X-ApiKeys: $KEYS" "$BASE/scans"
```

Start an update:

```bash
curl --fail --cacert "$NESSUS_CA_CERT" -X POST \
  -H "X-ApiKeys: $KEYS" \
  -H "Content-Type: application/json" \
  -d '{}' "$BASE/manage/v1/update"
```

Read update status:

```bash
curl --fail --cacert "$NESSUS_CA_CERT" \
  -H "X-ApiKeys: $KEYS" "$BASE/manage/v1/update/status"
```

Upload an offline feed:

```bash
curl --fail --cacert "$NESSUS_CA_CERT" -X POST \
  -H "X-ApiKeys: $KEYS" \
  -F "archive=@./all-2.0.tar.gz" \
  -F "signature=@./all-2.0.tar.gz.sig" \
  -F "plugin_set=202609100156" \
  "$BASE/manage/v1/update"
```

The `signature` field is optional. Nessus 10.12 and newer require the detached
signature; it is stored beside the archive as `<archive>.sig` and passed to
`nessuscli update` automatically. Omit it for older Nessus versions.

Set and release an update hold:

```bash
curl --fail --cacert "$NESSUS_CA_CERT" -X POST \
  -H "X-ApiKeys: $KEYS" \
  -H "Content-Type: application/json" \
  -d '{"reason":"scan batch"}' "$BASE/manage/v1/hold"

curl --fail --cacert "$NESSUS_CA_CERT" -X DELETE \
  -H "X-ApiKeys: $KEYS" "$BASE/manage/v1/hold"
```

Cancel the current update:

```bash
curl --fail --cacert "$NESSUS_CA_CERT" -X POST \
  -H "X-ApiKeys: $KEYS" "$BASE/manage/v1/update/cancel"
```

Update states are `idle`, `running`, `completed`, `deferred`, `rolled_back`,
`failed`, and `cancelled`.

### Scheduled updates and rollback

Scheduled updates are disabled by default. Enable them with a UTC maintenance
window:

```env
NESSUS_UPDATE_WINDOW_UTC=02:00-05:00
NESSUS_UPDATE_MAX_FEED_AGE_HOURS=48
```

The scheduler checks feed age only inside the window. It uses the same
single-update lock, hold file, and active-scan gate as manual updates. Failed
or deferred attempts retry with exponential backoff from 300 to 3600 seconds;
both limits can be changed in `.env`. Scheduler status is included in
`GET /manage/v1/health`.

Before replacing plugins, `update.sh` creates a compressed snapshot of the
plugin tree, feed metadata, and templates. If installation, patching, or
compilation fails, it restores that snapshot and recompiles the previous
plugins. This does not roll back users, scan results, or the Nessus database.

```env
NESSUS_UPDATE_ROLLBACK=1
NESSUS_UPDATE_ROLLBACK_KEEP=2
NESSUS_UPDATE_ROLLBACK_MAX_BYTES=5368709120
```

Snapshots are kept in the persistent volume and pruned by count. They are
excluded from full backups. A successful rollback returns update state
`rolled_back`; it is not reported as a successful update.

## Operations

`nessusctl.py` is a host-side wrapper, not a new daemon. It uses the existing
Compose files and `scripts/*.sh` from the project directory. Plugin updates
still run inside the container through `update.sh`. On Docker Desktop it also
attaches `docker-compose.desktop.yml`; a bare `docker compose down` / `up`
without that overlay stops publishing `127.0.0.1:8834`.

```bash
python nessusctl.py status
python nessusctl.py start
python nessusctl.py logs
python nessusctl.py restart
python nessusctl.py down
python nessusctl.py update
python nessusctl.py update-status
python nessusctl.py hold "maintenance"
python nessusctl.py release
python nessusctl.py backup
python nessusctl.py restore backups/nessus-backup-<UTC timestamp>.tar.gz --yes
python nessusctl.py doctor
```

Run an update directly on the Docker host:

```bash
docker exec -it nessus /usr/local/bin/update.sh
docker exec -it nessus /usr/local/bin/update.sh --force
```

`--force` skips waiting for active scans.

### Backup and restore

Create a consistent backup in `backups/`. On Windows use Git Bash, not WSL:

```bash
bash scripts/backup.sh
```

Or:

```powershell
python .\nessusctl.py backup
```

An alternative output directory can be supplied as the first argument. The
script records which services are running, stops gateway and Nessus, archives
the persistent volume, and then restores the previous running state. Each
backup consists of three files that must be kept together:

```text
nessus-backup-<UTC timestamp>.tar.gz
nessus-backup-<UTC timestamp>.manifest.json
nessus-backup-<UTC timestamp>.sha256
```

The manifest records the backup schema, Nessus and plugin versions,
architecture, source image, archive size, and SHA-256. Backup archives contain
credentials and scan data; store them with restricted access.

Restore a backup:

```bash
bash scripts/restore.sh backups/nessus-backup-<UTC timestamp>.tar.gz --yes
```

Before stopping services or changing the volume, restore copies the three
backup files into a private staging directory and revalidates them. The archive
is extracted next to the live data, then swapped into place only after the
layout check succeeds. If the swap fails, the previous volume contents are
moved back. After a successful swap, `patch.sh` reapplies immutable flags
before Nessus and the gateway start. Restore is irreversible once the swap
commits.

### Remove all persistent data

The volume contains the database, users, configuration, and plugins. A normal
container shutdown removes plugin immutable flags after stopping Nessus, so
this usually works:

```bash
docker compose down -v
```

If the container was killed or the host lost power while the flags were set,
use the recovery command:

```bash
bash scripts/destroy.sh --yes
```

The script explicitly starts `patch.sh` as the temporary container entrypoint,
unlocks the plugin tree, and removes the volume. Both operations are
irreversible.

## Project layout

- `docker-compose.yml` — Nessus and gateway services;
- `docker-entrypoint.sh` — installation and startup;
- `nessusctl.py` — local administrative CLI;
- `update-snapshot.py` — plugin rollback snapshot prune and path checks;
- `manage-api.py` — Operator API;
- `update.sh` — feed updates and scan gate;
- `secure-download.py` — hardened artifact downloads;
- `patch.sh` — feed patch and immutable flags;
- `gateway/` — nginx and TLS termination;
- `scripts/host-preflight.sh` — production preflight;
- `scripts/deploy.sh` — validation, build, and deployment;
- `scripts/backup.sh` and `scripts/restore.sh` — consistent volume backup and restore;
- `scripts/compose-lib.sh` — host path conversion for Docker bind mounts;
- `scripts/backup-tools.py` — backup manifest and archive validation;
- `scripts/destroy.sh` — immutable-aware persistent data removal;
- `scripts/bootstrap-trust.sh` — local CA bootstrap;
- `env.example` — configuration template.

## Updating base images

Base images are pinned by digest. For a planned refresh:

```bash
docker compose build --pull --no-cache
docker scout quickview nessus-automator-nessus:latest
docker scout quickview nessus-automator-gateway:latest
```

After CVE review and smoke tests, update the corresponding digest in each
`Dockerfile`.

## License

MIT. Nessus is a Tenable product.
