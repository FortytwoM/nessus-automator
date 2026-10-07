# Nessus Automator

[English](README.md) | **Русский**

Контейнерный запуск Tenable Nessus с управляемыми обновлениями плагинов,
выбором исходящего IP сканирования и защищённым HTTPS-шлюзом.

## Возможности

- установка Nessus из локального `.deb` или разрешённого HTTPS-источника;
- online- и offline-обновления plugin feed;
- выбор `source_ip` на хостах с несколькими интерфейсами;
- настройка DNS resolver внутри контейнера Nessus;
- единая точка доступа через nginx на TCP/8834;
- Operator API для обновлений, блокировок и проверки готовности;
- ожидание завершения активных сканирований перед обновлением;
- allowlist URL, проверка DNS и redirects, лимиты размера и времени;
- стабильный сертификат внутреннего CA или ACME;
- host preflight для IP, маршрутов, TLS, портов и firewalld.

## Архитектура

```text
Клиент
  │
  ▼ HTTPS :8834
gateway (nginx)
  ├── /manage/v1/* ──► Operator API 127.0.0.1:8080
  └── остальные пути ► Nessus       127.0.0.1:8835
```

Оба контейнера используют `network_mode: host` на Linux. Это позволяет Nessus
создавать соединения с IP физического интерфейса. Backend Nessus и Operator API
остаются на loopback; извне доступен только gateway. Docker Desktop подключает
`docker-compose.desktop.yml`: bridge-сеть и публикация `127.0.0.1:8834` на хост.

## Требования

Production:

- Linux с Docker Engine и Docker Compose;
- firewalld;
- IP управления и IP сканирования на интерфейсах хоста;
- policy routing для IP сканирования;
- сертификат, ключ и цепочка доверия.

Для локальной проверки поддерживается Docker Desktop на Windows/macOS.
Host networking не пробрасывает `https://127.0.0.1:8834` на localhost Windows,
поэтому desktop-оверлей публикует этот порт через bridge-сеть.

## Локальный запуск на Windows

```powershell
Copy-Item env.example .env
```

Минимальная конфигурация:

```env
NESSUS_USERNAME=admin
NESSUS_PASSWORD=replace-with-a-strong-password
GATEWAY_BIND_IP=127.0.0.1
GATEWAY_CERT_DIR=./certs
```

Выберите источник установки и plugin feed в `.env`. Пароли `admin` и
`changeme` запрещены.

Создайте локальный сертификат через Git Bash или WSL:

```bash
bash scripts/bootstrap-trust.sh 127.0.0.1 localhost
```

Установите CA в хранилище текущего пользователя:

```powershell
certutil -user -addstore Root .\certs\ca.pem
```

Запустите стек. На Docker Desktop нужен desktop-оверлей, иначе UI не будет
доступен на `127.0.0.1:8834`:

```powershell
python .\nessusctl.py start
docker compose -f docker-compose.yml -f docker-compose.desktop.yml ps
```

Эквивалентная команда Compose:

```powershell
docker compose -f docker-compose.yml -f docker-compose.desktop.yml up -d --build
```

Открывайте `https://localhost:8834` только после состояния `healthy`.

```powershell
curl.exe --fail --ssl-revoke-best-effort `
  --cacert certs/ca.pem `
  https://127.0.0.1:8834/manage/v1/health
```

Выбор физического интерфейса сканирования проверяйте на целевом Linux-хосте.

## Production-запуск на Linux

Пример:

- management: `ens224`, `195.239.191.98`;
- scanning: `ens256`, `195.239.191.99`.

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

`GATEWAY_ALLOWED_CIDRS` содержит адреса администраторов или VPN. Для одного
рабочего места используйте `/32`; несколько сетей разделяются запятыми.

`NESSUS_DNS_SERVERS` принимает от одного до трёх IPv4- или IPv6-адресов через
запятую. В `NESSUS_DNS_SEARCH` домены поиска разделяются запятыми или пробелами.
Resolver настраивается при каждом запуске только внутри контейнера Nessus и не
меняет DNS хоста. В online-режиме эти серверы должны разрешать имена Tenable.

Разместите в `GATEWAY_CERT_DIR`:

```text
cert.pem  — сертификат или full chain
key.pem   — закрытый ключ
ca.pem    — доверенная цепочка CA
```

SAN сертификата должен содержать `GATEWAY_BIND_IP` или используемое DNS-имя.
Для отдельного внутреннего CA:

```bash
bash scripts/bootstrap-trust.sh 195.239.191.98 nessus.example.internal
```

Сначала распространите `certs/ca.pem` на клиентские машины. Gateway включает
HSTS и не рассчитан на исключения проверки сертификата.

Первичное применение firewall и запуск:

```bash
sudo bash scripts/host-preflight.sh --apply-firewall
bash scripts/deploy.sh
```

Последующие запуски:

```bash
bash scripts/deploy.sh
```

Preflight проверяет bind/source IP, исходящий маршрут, TLS, владельцев портов и
ограничения firewalld. Те же административные CIDR применяются в nginx.

## Установка и plugin feed

### Online

```env
NESSUS_PROFILE=online
NESSUS_UPDATE_URL=https://plugins.nessus.org/v2/nessus.php?f=all-2.0.tar.gz&u=...&p=...
```

Удалённый `.deb` можно задать явно:

```env
NESSUS_DEB_URL=https://downloads.tenable.com/...
NESSUS_DEB_SHA256=...
```

Предпочтительно вручную положить единственный
`Nessus-*-debian10_amd64.deb` в `packages/`.

### Offline

Разместите в `packages/`:

```text
Nessus-*-debian10_amd64.deb
all-2.0.tar.gz
```

```env
NESSUS_PROFILE=offline
NESSUS_PLUGIN_SET=202609100156
```

`NESSUS_PLUGIN_SET` — 12-значный feed ID, соответствующий архиву. Каталог
`packages/` монтируется read-only как `/mnt/nessus`.

Приоритет источников обновления:

1. архив из Operator API;
2. `NESSUS_UPDATE_FILE`;
3. `/mnt/nessus/all-2.0.tar.gz`;
4. `NESSUS_UPDATE_URL`.

Современный `all-2.0.tar.gz` может начинаться с `23 45 89 17` и не являться
обычным gzip-архивом. Не проверяйте его через `gzip -t`.

## Безопасная загрузка

Настройки по умолчанию:

```env
NESSUS_DOWNLOAD_ALLOWED_SCHEMES=https
NESSUS_DOWNLOAD_ALLOWED_HOSTS=plugins.nessus.org,*.tenable.com
NESSUS_DOWNLOAD_ALLOWED_PORTS=443
NESSUS_DOWNLOAD_MAX_BYTES=1073741824
NESSUS_MANAGE_MAX_UPLOAD_BYTES=1073741824
NESSUS_DOWNLOAD_FS_SIZE=2300m
NESSUS_DOWNLOAD_TIMEOUT=1800
```

Перед запросом и каждым redirect проверяются hostname, DNS-ответ и порт.
Соединение закрепляется за одним из проверенных IP, а исходное имя продолжает
использоваться для TLS SNI и проверки сертификата. Private, loopback,
link-local, reserved, multicast и unspecified IP запрещены. TLS-проверка
обязательна.

Загрузки используют отдельный tmpfs `/var/lib/nessus-downloads` и удаляются
после завершения или ошибки.

## Готовность

Контейнер остаётся в `health: starting`, а gateway не запускается, пока
bootstrap не подтвердит `engine_status=ready` и `pluginData=true`.

```bash
curl --fail --cacert "$NESSUS_CA_CERT" \
  "$BASE/manage/v1/health"
```

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

Для запуска сканирований ориентируйтесь только на `ready: true`.

## Управление

Создайте API keys в `Settings → My Account → API Keys`.

```bash
BASE=https://nessus.example.internal:8834
NESSUS_CA_CERT=/etc/ssl/certs/company-root-ca.pem
KEYS='accessKey=...; secretKey=...'
```

Список сканирований:

```bash
curl --fail --cacert "$NESSUS_CA_CERT" \
  -H "X-ApiKeys: $KEYS" "$BASE/scans"
```

Запуск обновления:

```bash
curl --fail --cacert "$NESSUS_CA_CERT" -X POST \
  -H "X-ApiKeys: $KEYS" \
  -H "Content-Type: application/json" \
  -d '{}' "$BASE/manage/v1/update"
```

Статус обновления:

```bash
curl --fail --cacert "$NESSUS_CA_CERT" \
  -H "X-ApiKeys: $KEYS" "$BASE/manage/v1/update/status"
```

Загрузка offline feed:

```bash
curl --fail --cacert "$NESSUS_CA_CERT" -X POST \
  -H "X-ApiKeys: $KEYS" \
  -F "archive=@./all-2.0.tar.gz" \
  -F "plugin_set=202609100156" \
  "$BASE/manage/v1/update"
```

Установить или снять блокировку обновлений:

```bash
curl --fail --cacert "$NESSUS_CA_CERT" -X POST \
  -H "X-ApiKeys: $KEYS" \
  -H "Content-Type: application/json" \
  -d '{"reason":"scan batch"}' "$BASE/manage/v1/hold"

curl --fail --cacert "$NESSUS_CA_CERT" -X DELETE \
  -H "X-ApiKeys: $KEYS" "$BASE/manage/v1/hold"
```

Отменить обновление:

```bash
curl --fail --cacert "$NESSUS_CA_CERT" -X POST \
  -H "X-ApiKeys: $KEYS" "$BASE/manage/v1/update/cancel"
```

Состояния: `idle`, `running`, `completed`, `deferred`, `rolled_back`, `failed`,
`cancelled`.

### Плановые обновления и rollback

По умолчанию scheduler выключен. Для включения задайте maintenance window в
UTC:

```env
NESSUS_UPDATE_WINDOW_UTC=02:00-05:00
NESSUS_UPDATE_MAX_FEED_AGE_HOURS=48
```

Возраст feed проверяется только внутри окна. Плановое обновление использует тот
же single-update lock, hold-файл и ожидание активных сканирований, что и ручной
запуск. После ошибки или отсрочки применяется exponential backoff от 300 до
3600 секунд; оба предела можно изменить в `.env`. Состояние scheduler входит в
ответ `GET /manage/v1/health`.

Перед заменой plugins `update.sh` создаёт сжатый snapshot дерева плагинов,
feed metadata и templates. При ошибке установки, patch или compilation
автоматически восстанавливаются предыдущие плагины и выполняется их повторная
компиляция. Пользователи, результаты сканирований и база Nessus не
откатываются.

```env
NESSUS_UPDATE_ROLLBACK=1
NESSUS_UPDATE_ROLLBACK_KEEP=2
NESSUS_UPDATE_ROLLBACK_MAX_BYTES=5368709120
```

Snapshots находятся в persistent volume и удаляются по лимиту количества. В
полный backup они не включаются. Успешный rollback возвращает состояние
`rolled_back`, а не успешное обновление.

## Эксплуатация

`nessusctl.py` — локальная обёртка, а не новый сервис. Она вызывает уже
существующие Compose-команды и `scripts/*.sh` из каталога проекта. Обновление
плагинов по-прежнему выполняется внутри контейнера через `update.sh`. На
Docker Desktop она также подключает `docker-compose.desktop.yml`; голый
`docker compose down` / `up` без этого оверлея снова уберёт публикацию
`127.0.0.1:8834`.

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

Ручное обновление:

```bash
docker exec -it nessus /usr/local/bin/update.sh
docker exec -it nessus /usr/local/bin/update.sh --force
```

`--force` пропускает ожидание активных сканирований.

### Резервное копирование и восстановление

Создать согласованный backup в каталоге `backups/`. На Windows нужен Git Bash,
не WSL:

```bash
bash scripts/backup.sh
```

Или:

```powershell
python .\nessusctl.py backup
```

Другой каталог можно передать первым аргументом. Скрипт запоминает работающие
сервисы, останавливает gateway и Nessus, архивирует persistent volume, а затем
возвращает прежнее состояние сервисов. Backup состоит из трёх файлов, которые
нужно хранить вместе:

```text
nessus-backup-<UTC timestamp>.tar.gz
nessus-backup-<UTC timestamp>.manifest.json
nessus-backup-<UTC timestamp>.sha256
```

Manifest содержит версию формата, версии Nessus и плагинов, архитектуру,
исходный image, размер и SHA-256 архива. В архив входят учётные данные и
результаты сканирований, поэтому доступ к нему необходимо ограничить.

Восстановить backup:

```bash
bash scripts/restore.sh backups/nessus-backup-<UTC timestamp>.tar.gz --yes
```

До остановки сервисов restore копирует три файла backup во временный каталог и
повторно проверяет их. Архив распаковывается рядом с текущими данными и
подменяется только после проверки layout. Если подмена не удалась, предыдущее
содержимое volume возвращается на место. После успешной подмены `patch.sh`
снова ставит immutable-флаги, затем запускаются Nessus и gateway. После
завершённой подмены restore необратим.

### Полное удаление данных

Volume содержит базу, пользователей, настройки и плагины. При штатной остановке
контейнер сначала останавливает Nessus, затем снимает immutable-флаги. Поэтому
обычно достаточно:

```bash
docker compose down -v
```

Если контейнер был завершён принудительно или хост выключился при установленных
флагах, используйте recovery-команду:

```bash
bash scripts/destroy.sh --yes
```

Скрипт явно запускает `patch.sh` как entrypoint временного контейнера, снимает
флаги со всего дерева плагинов и удаляет volume. Обе операции необратимы.

## Структура проекта

- `docker-compose.yml` — Nessus и gateway;
- `docker-entrypoint.sh` — установка и запуск;
- `nessusctl.py` — локальная административная CLI;
- `update-snapshot.py` — prune и проверка snapshot для rollback;
- `manage-api.py` — Operator API;
- `update.sh` — обновление feed и scan gate;
- `secure-download.py` — защищённая загрузка;
- `patch.sh` — patch feed и immutable-флаги;
- `gateway/` — nginx и TLS termination;
- `scripts/host-preflight.sh` — production preflight;
- `scripts/deploy.sh` — проверка, сборка и запуск;
- `scripts/backup.sh` и `scripts/restore.sh` — согласованный backup/restore volume;
- `scripts/compose-lib.sh` — преобразование путей для bind-mount Docker;
- `scripts/backup-tools.py` — manifest и проверка backup-архивов;
- `scripts/destroy.sh` — удаление данных с учётом immutable-флагов;
- `scripts/bootstrap-trust.sh` — локальный CA;
- `env.example` — шаблон конфигурации.

## Обновление базовых образов

```bash
docker compose build --pull --no-cache
docker scout quickview nessus-automator-nessus:latest
docker scout quickview nessus-automator-gateway:latest
```

После проверки CVE и smoke-тестов зафиксируйте новый digest в `Dockerfile`.

## Лицензия

MIT. Nessus является продуктом Tenable.
