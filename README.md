<div align="center">
  <img src="ui/public/favicon.png" alt="OPNsense" width="128" />

  # OPNsense SFTP Backup Manager

  Centralised backup receiver for OPNsense firewalls. Each firewall pushes encrypted config backups via SFTP using a per-instance SSH key pair. The app stores files on disk, tracks metadata in SQLite, and provides a web GUI for administration.

</div>

## Features

- **SFTP server**: Built-in SFTP with SSH public key authentication only
- **SSH key generation**: 4096-bit RSA key pairs in OpenSSH format per instance
- **Multi-instance support**: Manage backups from multiple OPNsense firewalls
- **Web UI**: Vue 3 + Tailwind 4 management interface (embedded in the binary)
- **SQLite**: Local metadata storage, no external database required
- **Authentication**: Session cookies, bcrypt passwords, optional TOTP 2FA
- **Read-only status API**: API keys for backup health, for dashboards
- **Backup pruning**: Manual and automated retention by days or count

## Install

Add the JDB-NET apt repository, then install the package (amd64 or arm64):

```bash
curl -fsSL https://apt.jdbnet.co.uk/install/stable.sh | sudo bash
sudo apt update
sudo apt install opnsense-sftp
```

The package installs the binary to `/usr/local/bin/opnsense-sftp`, a default config at `/etc/opnsense-sftp/config.yaml`, and a systemd unit. Edit the config, then enable and start the service if needed:

```bash
sudo systemctl enable opnsense-sftp
sudo systemctl start opnsense-sftp
```

Updates are delivered through the apt repository:

```bash
sudo apt update && sudo apt upgrade opnsense-sftp
```

### Alternative: curl install script

```bash
curl -fsSL https://github.com/jdbnet/opnsense-sftp/raw/main/deploy/install.sh | sudo bash
```

This downloads the release binary from GitHub Releases, installs `opnsense-sftp` to `/usr/local/bin`, creates `/etc/opnsense-sftp/config.yaml`, and enables a systemd service.

### Docker

Images are published to `ghcr.io/jdbnet/opnsense-sftp` for `linux/amd64` and `linux/arm64`. Bind-mount config, SQLite data, keys, and backups:

```yaml
services:
  opnsense-sftp:
    image: ghcr.io/jdbnet/opnsense-sftp:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "2222:2222"
    volumes:
      - ./config.yaml:/etc/opnsense-sftp/config.yaml:ro
      - ./data:/var/lib/opnsense-sftp
      - ./keys:/var/lib/opnsense-sftp/keys
      - ./backups:/var/lib/opnsense-sftp/backups
```

Use `deploy/config.yaml` as a starting point. SQLite is stored under `data_dir` (`./data` above). Keep `keys_dir` and `backups_dir` on their own bind mounts so keys and backup files persist independently of the database.

## Configuration

Example `config.yaml`:

```yaml
listen: 0.0.0.0:8080
log_level: info
data_dir: /var/lib/opnsense-sftp
keys_dir: /var/lib/opnsense-sftp/keys
backups_dir: /var/lib/opnsense-sftp/backups
session_secret: change-me
sftp:
  listen: 0.0.0.0:2222
  public_host: ""
  public_port: 0
prune:
  check_interval: 1h
update:
  enabled: true
  url: ""
  allow_dev: false
# How long after the last successful backup a firewall counts as stale.
stale_after: 48h
# Read-only keys for the status API. Startup stores a hash, not the plaintext.
# api_keys:
#   - name: dashboard
#     key: replace-with-a-long-random-secret
```

### Environment variable overrides

- `OPNSENSE_SFTP_LISTEN`, `OPNSENSE_SFTP_DATA_DIR`, `OPNSENSE_SFTP_KEYS_DIR`, `OPNSENSE_SFTP_BACKUPS_DIR`
- `SESSION_SECRET`
- `SFTP_PUBLIC_HOST`, `SFTP_PUBLIC_PORT`
- `OPNSENSE_SFTP_UPDATE_ENABLED`, `OPNSENSE_SFTP_UPDATE_URL`
- `OPNSENSE_SFTP_NO_UPDATE` (any value skips the startup update check)
- `OPNSENSE_SFTP_STALE_AFTER` (for example `48h`)
- `OPNSENSE_SFTP_API_KEYS` (comma-separated `name:key` pairs; the name is the text before the first colon, and keys must not contain commas)

### Auto-update

On startup, when `update.enabled` is true, the binary checks GitHub Releases for a newer build (`https://github.com/jdbnet/opnsense-sftp/releases/latest/download/opnsense-sftp-{arch}`) using the release asset ETag. If the published binary differs, it downloads, verifies, replaces itself, and restarts. Disabled for local `dev` builds unless `update.allow_dev` is set.

The apt package ships with `update.enabled: false` because upgrades are handled by apt. The curl install script enables auto-update by default.

On first run, if no users exist, an `admin` user is created with password `changeme`. Change the password immediately.

## OPNsense setup

1. Open the web UI at `http://your-server:8080` and sign in
2. Create an instance under **Instances** (identifier becomes the SFTP username)
3. In OPNsense: **System → Configuration → Backups**
   - **Type**: SFTP
   - **Target location (URI)**: copy from the instance detail page (e.g. `sftp://lan@backup.example.com:2222//lan`)
   - **SSH Private Key**: download from the instance detail page
4. Save and test the backup connection

## Ports

| Port | Service |
|------|---------|
| 8080 | Web UI + REST API (configurable via `listen`) |
| 2222 | SFTP (configurable via `sftp.listen`) |

Set `sftp.public_host` and `sftp.public_port` to the address OPNsense should use when the public endpoint differs from the bind address.

## Read-only status API

Each job is one OPNsense firewall instance. `id` and `target` are the instance identifier (the SFTP username and backup directory). `name` is the display name. `last_run_at` and `last_success_at` are the time the latest backup was received. `last_size_bytes` is the size of that file.

This app does not record failed pushes, how long a push took, or when the firewall will push next, so `last_duration_seconds`, `last_error`, and `next_run_at` are null. A received backup has `last_status` `success`. An instance that has not pushed yet is `never_run`.

A firewall is `stale` when its latest successful backup is older than `stale_after` (default 48 hours). OPNsense pushes on its own schedule, which this app does not store, so the threshold is a fixed interval rather than twice a cron expression.

`overall` is `unknown` when there are no instances, `failing` when any instance's last status is `failed`, `warning` when any instance is stale, `partial`, or `never_run`, and `ok` when every instance is healthy. Disabled jobs are ignored; every instance in this app is enabled.

API keys are read-only. They can call only the two endpoints below. They cannot create, change, or delete instances, backups, users, or settings. A missing or invalid key returns `401` and `{"error":"unauthorized"}`.

### Create a key

Sign in as an administrator and open **API keys**. Name the key and create it. The full key is shown once. The app stores only a SHA-256 hash, plus a short prefix so you can recognise the key later.

You can also set keys in configuration. The plaintext stays in the config file you manage, and startup writes the hash into the database. Removing a key from the config revokes it on the next start. Those keys are listed in the UI and cannot be revoked there.

```yaml
api_keys:
  - name: dashboard
    key: replace-with-a-long-random-secret
```

Or:

```bash
OPNSENSE_SFTP_API_KEYS=dashboard:replace-with-a-long-random-secret
```

### Authentication

Send either header:

```http
Authorization: Bearer <key>
```

```http
X-API-Key: <key>
```

### `GET /api/v1/health`

A cheap liveness check. It does not read backup history.

```json
{"app":"opnsense-sftp","version":"1.2.3","status":"ok"}
```

### `GET /api/v1/backups/status`

```json
{
  "app": "opnsense-sftp",
  "version": "1.2.3",
  "generated_at": "2026-10-10T12:00:00Z",
  "overall": "ok",
  "jobs": [
    {
      "id": "lan",
      "name": "Home firewall",
      "target": "lan",
      "enabled": true,
      "last_run_at": "2026-10-10T01:00:00Z",
      "last_status": "success",
      "last_success_at": "2026-10-10T01:00:00Z",
      "last_duration_seconds": null,
      "last_size_bytes": 1048576,
      "last_error": null,
      "next_run_at": null,
      "stale": false
    }
  ]
}
```

## Security notes

- Change the default `session_secret`
- SFTP accepts public key authentication only
- Private keys are stored under `keys_dir` with mode 0600
- Each instance is path-sandboxed under `backups_dir/{identifier}/`

## License

[MIT](LICENSE)