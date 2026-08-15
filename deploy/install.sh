#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/opnsense-sftp}"
DATA_DIR="${DATA_DIR:-/var/lib/opnsense-sftp}"
BASE_URL="${OPNSENSE_SFTP_DOWNLOAD_URL:-https://apps.jdbnet.co.uk}"
SERVICE_NAME="opnsense-sftp"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root or with sudo"
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) asset="opnsense-sftp-amd64" ;;
  aarch64|arm64) asset="opnsense-sftp-arm64" ;;
  *)
    echo "Unsupported architecture: $(uname -m) (need amd64 or arm64)"
    exit 1
    ;;
esac

url="${BASE_URL}/${asset}"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

echo "Downloading ${url}"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL -o "$tmp" "$url"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$tmp" "$url"
else
  echo "Need curl or wget"
  exit 1
fi

install -m 755 "$tmp" "${INSTALL_DIR}/opnsense-sftp"
mkdir -p "$CONFIG_DIR" "$DATA_DIR/keys" "$DATA_DIR/backups"

if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
  cat > "${CONFIG_DIR}/config.yaml" <<EOF
listen: 0.0.0.0:8080
log_level: info
data_dir: ${DATA_DIR}
keys_dir: ${DATA_DIR}/keys
backups_dir: ${DATA_DIR}/backups
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
EOF
  echo "Wrote ${CONFIG_DIR}/config.yaml"
fi

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=OPNsense SFTP backup receiver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/opnsense-sftp ${CONFIG_DIR}/config.yaml
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo "OPNsense SFTP installed from ${url}"
echo "Web UI: http://<server-ip>:8080 (edit ${CONFIG_DIR}/config.yaml)"
echo "SFTP: port 2222"
echo "Status: systemctl status ${SERVICE_NAME}"
