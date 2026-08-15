#!/bin/bash
set -euo pipefail

cd ui && (npm ci --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund) && npm run build && cd ..

CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=${VERSION:-dev}" -o opnsense-sftp ./cmd/opnsense-sftp
