FROM node:24-alpine AS frontend
WORKDIR /build
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund
COPY ui/ ./
RUN npm run build

FROM golang:1.27-alpine AS server
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /build/dist ./ui/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=${VERSION}" -o opnsense-sftp ./cmd/opnsense-sftp

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata \
    && mkdir -p /etc/opnsense-sftp /var/lib/opnsense-sftp/keys /var/lib/opnsense-sftp/backups
COPY --from=server /build/opnsense-sftp /usr/local/bin/opnsense-sftp
COPY deploy/config.yaml /etc/opnsense-sftp/config.yaml
ENV OPNSENSE_SFTP_NO_UPDATE=1
EXPOSE 8080 2222
ENTRYPOINT ["/usr/local/bin/opnsense-sftp"]
CMD ["/etc/opnsense-sftp/config.yaml"]
