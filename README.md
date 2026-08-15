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
- **Backup pruning**: Manual and automated retention by days or count

## Install

On a Linux server (amd64 or arm64):

```bash
curl -fsSL https://git.jdbnet.co.uk/jamie/opnsense-sftp/raw/branch/main/deploy/install.sh | sudo bash
```

This downloads the release binary from `apps.jdbnet.co.uk`, installs `opnsense-sftp` to `/usr/local/bin`, creates `/etc/opnsense-sftp/config.yaml`, and enables a systemd service.

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
```

### Environment variable overrides

- `OPNSENSE_SFTP_LISTEN`, `OPNSENSE_SFTP_DATA_DIR`, `OPNSENSE_SFTP_KEYS_DIR`, `OPNSENSE_SFTP_BACKUPS_DIR`
- `SESSION_SECRET`
- `SFTP_PUBLIC_HOST`, `SFTP_PUBLIC_PORT`
- `OPNSENSE_SFTP_UPDATE_ENABLED`, `OPNSENSE_SFTP_UPDATE_URL`
- `OPNSENSE_SFTP_NO_UPDATE` (any value skips the startup update check)

### Auto-update

On startup, when `update.enabled` is true, the binary compares its SHA256 hash against `https://apps.jdbnet.co.uk/opnsense-sftp-{arch}.sha256`. If a newer build is published, it downloads, verifies, replaces itself, and restarts. Disabled for local `dev` builds unless `update.allow_dev` is set.

The install script enables auto-update by default.

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

## Security notes

- Change the default `session_secret`
- SFTP accepts public key authentication only
- Private keys are stored under `keys_dir` with mode 0600
- Each instance is path-sandboxed under `backups_dir/{identifier}/`

## License

[MIT](LICENSE)