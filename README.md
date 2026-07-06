# Nessus Docker

Docker wrapper for Tenable Nessus: installation, feed patching, plugin updates, and **remote management** through a single HTTPS port.

## What's inside

| Component | Purpose |
|-----------|---------|
| **Nessus** | Scanner, standard REST API (`/scans`, `/session`, …) |
| **Operator API** | What Nessus does not provide out of the box: plugin updates, hold, update status |
| **Gateway (nginx)** | Single entry point `https://host:8834` — only this is exposed externally |

Nessus and the operator API are **not published directly** — traffic goes through the gateway only.

## Quick start

```bash
cp env.example .env
# Set NESSUS_USERNAME, NESSUS_PASSWORD, and a plugin source (see env.example)

docker compose up -d
```

The container will refuse to start with `NESSUS_PASSWORD=admin` or `changeme`.
For a disposable lab environment, explicitly allow this: `NESSUS_ALLOW_DEFAULT_PASSWORD=1`.

Open `https://<host>:8834` and accept the self-signed certificate.

**Firefox and HSTS:** if the browser says you cannot add an exception — HSTS for `localhost:8834` may have been saved from a previous visit. After updating the gateway: close Firefox → delete `SiteSecurityServiceState.txt` in your profile (or **Settings → Privacy → Clear Data → Saved site settings**) → recreate the gateway:

```bash
docker compose up -d --force-recreate gateway
```

Then open `https://localhost:8834` again and add a certificate exception.

First startup: UI and Operator API are available within a few minutes; plugin compilation continues in the background (15–20 min for a full feed). Check `GET /manage/v1/health` — `"ready": true` when scans can run.

## Management: three ways

### 1. Web UI

`https://<host>:8834` — standard Nessus UI. Login/password from `.env` (`NESSUS_USERNAME` / `NESSUS_PASSWORD`).

### 2. Nessus REST API (scans, reports, policies)

Create API keys: **Settings → My Account → API Keys**.

All requests use the same URL and the same keys:

```bash
BASE=https://192.168.1.100:8834
KEYS='accessKey=YOUR_ACCESS_KEY; secretKey=YOUR_SECRET_KEY'

# List scans
curl -sk "$BASE/scans" -H "X-ApiKeys: $KEYS"

# Launch a scan
curl -sk -X POST "$BASE/scans/1/launch" -H "X-ApiKeys: $KEYS"
```

For orchestration, use the **[Nessus API](../Nessus%20API)** project — CLI and `auto` mode with the same `config.yaml`:

```yaml
nessus:
  url: https://192.168.1.100:8834
  access_key: YOUR_ACCESS_KEY
  secret_key: YOUR_SECRET_KEY
  verify_ssl: false
```

### 3. Operator API (plugin updates)

**Same host, same port, same API keys.** No separate credentials.

| Method | Path | Who can call | Action |
|--------|------|--------------|--------|
| `GET` | `/manage/v1/health` | no auth | Operator + Nessus readiness (`ready`, `plugin_set`, `engine_status`, …) |
| `GET` | `/manage/v1/scans/active` | any key | Scans blocking update |
| `GET` | `/manage/v1/update/status` | any key | Current/last update status |
| `POST` | `/manage/v1/hold` | **admin** key | Block update |
| `DELETE` | `/manage/v1/hold` | **admin** key | Release block |
| `POST` | `/manage/v1/update` | **admin** key | Start update (async) |
| `POST` | `/manage/v1/update/cancel` | **admin** key | Cancel current update |
| `GET` | `/manage/v1/update/status` | Nessus keys | Update status |

Auth header (Nessus API keys only):

```http
X-ApiKeys: accessKey=...; secretKey=...
```

Update states: `idle` → `running` → `completed` | `deferred` | `failed` | `cancelled`.

Update checks hold and active scans first, **then** downloads the archive (if online).

Hold state is stored in `NESSUS_UPDATE_HOLD_FILE` (default: `/opt/nessus/var/nessus/.update_hold` on the writable data volume — not under `/mnt/nessus`, which is read-only).
When `packages/all-2.0.tar.gz` changes, bootstrap on container start runs update again (fingerprint in `.update_feed_stamp`).

## Typical workflows

### Offline: archive + feed id via API (no internet)

Centralized update: the orchestrator sends `all-2.0.tar.gz` and the feed number (`plugin_set`, 12 digits).

**JSON** — archive already on the Nessus host (e.g. in `packages/`):

```bash
curl -sk -X POST "$BASE/manage/v1/update" \
  -H "X-ApiKeys: $KEYS" -H "Content-Type: application/json" \
  -d '{
    "archive": "/mnt/nessus/all-2.0.tar.gz",
    "plugin_set": "202606300042",
    "force": false
  }'
```

**Multipart** — upload archive from the orchestrator machine (Nessus has no internet access):

```bash
curl -sk -X POST "$BASE/manage/v1/update" \
  -H "X-ApiKeys: $KEYS" \
  -F "archive=@/path/to/all-2.0.tar.gz" \
  -F "plugin_set=202606300042" \
  -F "force=false"
```

The file is saved to `/opt/nessus/var/nessus/incoming/` inside the container.

Via orchestrator CLI:

```bash
# path inside the container (shared packages/ volume)
cli operator update --archive /mnt/nessus/all-2.0.tar.gz --plugin-set 202606300042 --wait

# upload from the orchestrator host
cli operator update --upload-file ./all-2.0.tar.gz --plugin-set 202606300042 --wait
```

JSON fields: `archive`, `plugin_set` (or `plugin_set_id`, `feed_id`), `force`.  
For online updates: `"source": "https://plugins.nessus.org/..."` or `{}` with `NESSUS_UPDATE_URL`.  
Empty `{}` — default by priority (see below).

**`plugin_set` rules:**

| Mode | Archive | `plugin_set` |
|------|---------|--------------|
| **Online** (URL download) | from Tenable URL | **auto** from [plugins.php](https://plugins.nessus.org/v2/plugins.php) |
| **Offline** (local path / upload) | required | **required** (12 digits from [offline.php](https://plugins.nessus.org/offline.php)) |

**Feed source priority** (for `{}` and `update.sh`):

1. `archive` in POST body (path or multipart upload)
2. `NESSUS_UPDATE_FILE` or `packages/all-2.0.tar.gz` → `/mnt/nessus/all-2.0.tar.gz`
3. `NESSUS_UPDATE_URL` (online)

### Remote plugin update (online)

The Nessus API cannot update the feed — use the operator API for that.

```bash
BASE=https://nessus.example.com:8834
KEYS='accessKey=...; secretKey=...'

# Health check
curl -sk "$BASE/manage/v1/health"

# Start update (waits for active scans to finish)
curl -sk -X POST "$BASE/manage/v1/update" \
  -H "X-ApiKeys: $KEYS" -H "Content-Type: application/json" -d '{}'

# Poll status
curl -sk "$BASE/manage/v1/update/status" -H "X-ApiKeys: $KEYS"
```

Via orchestrator CLI:

```bash
cli operator update --wait
cli operator update-status
```

### Batch scans without interrupting update

Before a scan batch — hold; after — release + update:

```bash
# 1. Block update
curl -sk -X POST "$BASE/manage/v1/hold" \
  -H "X-ApiKeys: $KEYS" -H "Content-Type: application/json" \
  -d '{"reason":"batch-42"}'

# 2. Launch scans (standard Nessus API)
curl -sk -X POST "$BASE/scans/1/launch" -H "X-ApiKeys: $KEYS"

# 3. Release hold and update plugins
curl -sk -X DELETE "$BASE/manage/v1/hold" -H "X-ApiKeys: $KEYS"
curl -sk -X POST "$BASE/manage/v1/update" \
  -H "X-ApiKeys: $KEYS" -H "Content-Type: application/json" -d '{}'
```

Or via CLI:

```bash
cli operator hold --reason "batch-42"
# ... scans ...
cli operator release-hold
cli operator update --wait
```

### Local maintenance (on the Docker host)

```bash
docker compose logs -f nessus
docker exec -it nessus /usr/local/bin/update.sh
docker exec -it nessus /usr/local/bin/update.sh --force   # skip scan wait
curl -sk https://localhost:8834/manage/v1/health
```

## Architecture

```text
Client (browser / orchestrator / curl)
              │
              ▼  https://host:8834
       ┌──────────────┐
       │   gateway    │
       └──────┬───────┘
              │
     ┌────────┴────────┐
     ▼                 ▼
/manage/v1/*       /scans, /session, UI
     │                 │
     ▼                 ▼
operator-api      Nessus :8834
:8080 (internal)  (internal)
```

Update inside the container **does not run on a schedule** — only via operator API (`POST /manage/v1/update`), manually (`docker exec … update.sh`), or once on first start (bootstrap, if a plugin source is configured).

During update:
1. Checks hold file and active scans via Nessus API
2. Stops Nessus → `nessuscli update` → patch → restart

## Configuration (.env)

```bash
cp env.example .env
```

### Required

| Variable | Description |
|----------|-------------|
| `NESSUS_USERNAME` | UI login |
| `NESSUS_PASSWORD` | UI password; applied on first admin creation and **synced** on every start if the volume has a different password |

After changing `.env`, recreate the container — variables are picked up only at creation time:

```bash
docker compose up -d --force-recreate nessus
```

If the password is “stuck” on an old value (e.g. `admin` from the first run without `.env`), recreate the container with the correct `.env` — the entrypoint will align the password in Nessus.

`admin` and `changeme` are blocked by default. For a fully disposable lab setup,
set `NESSUS_ALLOW_DEFAULT_PASSWORD=1`.

### Plugin source (pick one)

See `env.example`: **ONLINE** or **OFFLINE** block — not both at once.

**Online** — URL with `u=` and `p=` (download on update call, not on a timer):

```env
NESSUS_UPDATE_URL=https://plugins.nessus.org/v2/nessus.php?f=all-2.0.tar.gz&u=...&p=...
```

**Offline** — files in `packages/`:

```env
NESSUS_PROFILE=offline
NESSUS_PLUGIN_SET=202606300622   # required; from offline.php, same release as the archive
# packages/Nessus-10.12.0-debian10_amd64.deb   (first install only)
# packages/all-2.0.tar.gz
```

**First install (local .deb)** — if Tenable API returns 403 or there is no internet:

1. Download `Nessus-*-debian10_amd64.deb` from [Tenable downloads](https://www.tenable.com/downloads/nessus) (login required).
2. Copy to `packages/` (one `.deb` file).
3. Start the container — no `NESSUS_DEB_PATH` needed if there is only one `.deb`.

Or set explicitly:

```env
NESSUS_DEB_PATH=/mnt/nessus/Nessus-10.12.0-debian10_amd64.deb
# NESSUS_DEB_INSTALL=local   # skip Tenable API even without NESSUS_PROFILE=offline
```

**Online** — `plugin_set` is fetched from [plugins.php](https://plugins.nessus.org/v2/plugins.php) during patch; do not pass it manually.

**Source priority** (API `{}` and `update.sh`): `archive` in POST → `/mnt/nessus/all-2.0.tar.gz` → `NESSUS_UPDATE_URL`.

### `all-2.0.tar.gz` format (important)

The extension is historical — **this is not a regular gzip/tar archive**. Modern Tenable feeds start with magic bytes:

```text
23 45 89 17   (Tenable plugin bundle)
```

Older feeds may start with `1f 8b` (gzip). `nessuscli update` accepts both formats.  
**Do not validate the feed with `gzip -t`** — a valid bundle will be rejected.

### `/manage/v1/health` (extended)

```json
{
  "status": "ok",
  "operator_version": "2.2",
  "ready": true,
  "plugin_set": "202606300042",
  "plugin_data": true,
  "engine_status": "ready",
  "engine_progress": 100,
  "update_state": "idle",
  "update_in_progress": false,
  "hold_active": false
}
```

`ready: true` means Nessus is ready for scans (`engine_status=ready` and `pluginData=true`). The orchestrator does not need to parse `/server/status`.

**Scheduled plugin push (orchestrator):**

- Poll `GET /manage/v1/health` **without auth** while Nessus is restarting or compiling (`ready: false`, `update_in_progress: true`).
- Do not call authenticated Operator endpoints until `ready: true` and Nessus accepts `GET /session` with your API keys — otherwise **401** is expected.
- `POST /manage/v1/update` returns **409** while bootstrap or another update runs — poll `/health` or `/manage/v1/update/status` instead of retrying every minute.
- Operator API accepts **`X-ApiKeys` only** (same keys as Nessus REST: UI → My Account → API Keys). Admin keys required for `POST`/`DELETE` on hold and update.

### When update runs

| Event | Who triggers it |
|-------|-----------------|
| First container start | Bootstrap: once, if a source exists and `.update_completed` is missing |
| Plugin update in production | **Operator only**: `POST /manage/v1/update` or `cli operator update` |
| Schedule / timer | **No** — the container does not initiate update on its own |

Scan-gate (wait for active scans) applies to every `update.sh` run except `--force`.

### Startup timeouts and healthcheck

Startup is **non-blocking**: Nessus UI, gateway, and Operator API come up as soon as the engine responds; plugin install/compile runs in a **background bootstrap** (`[bootstrap]` in logs).

| Variable | Default | Purpose |
|----------|---------|---------|
| `NESSUS_READY_TIMEOUT` | `1800` (30 min) | Background bootstrap: wait for plugin compilation |
| `NESSUS_READY_RETRY_TIMEOUT` | `600` (10 min) | Retry wait after patch/restart in bootstrap |
| `NESSUS_HEALTH_START_PERIOD` | `120` | Healthcheck grace period in `docker-compose` |
| `NESSUS_HEALTH_STRICT` | `0` | `1` = Docker health requires `pluginData=true` (old blocking behaviour) |

On first start with a large feed (`all-2.0.tar.gz` ~750MB), compilation can take 15–20 minutes — the container is **healthy** before that finishes.

The `nessus` healthcheck verifies: Nessus `/server/status` responds + `GET /manage/v1/health` (operator). Scan readiness is in the API: `"ready": true` only when `engine_status=ready` and `pluginData=true`.

The gateway starts after `nessus: healthy` (typically within a few minutes, not after compile).

## Local packages (offline)

The `packages/` directory is mounted at `/mnt/nessus` (read-only):

| File | Purpose |
|------|---------|
| `Nessus-*-debian10_amd64.deb` | Nessus installer (**first start**, if API/install URL unavailable) |
| `all-2.0.tar.gz` | Plugin feed |

```bash
docker exec -it nessus /usr/local/bin/update.sh /mnt/nessus/all-2.0.tar.gz
```

## Useful commands

```bash
docker compose up -d          # Start
docker compose logs -f        # Logs
docker compose down           # Stop
docker exec -it nessus /bin/bash

# Nessus status
curl -sk https://localhost:8834/server/status

# Operator health
curl -sk https://localhost:8834/manage/v1/health
```

## Removing volumes

`patch.sh` may set `chattr +i` on the plugin tree. Before `docker compose down -v`:

```bash
docker compose down
docker compose run --rm --no-deps nessus /usr/local/bin/patch.sh --feed-unlock
docker compose down -v
```

## Project files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Stack: `nessus` + `gateway` |
| `gateway/` | nginx, single port 8834 |
| `manage-api.py` | Operator API (`/manage/v1/*`) |
| `update.sh` | Plugin update + scan-gate |
| `patch.sh` | Feed patch, immutable lock |
| `nessus-api.sh` | REST helpers, scan checks |
| `nessus-users.sh` | Admin creation, creds for scan-gate |
| `healthcheck.sh` | Docker health: Nessus alive + operator API |
| `env.example` | `.env` template |

## License

MIT. Nessus is a Tenable product; use at your own risk, including for lab/educational purposes.
