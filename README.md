<div align="center">
  <img src="https://assets.s3.jdbnet.co.uk/opnsense.png" alt="OPNsense" width="200" />
  
  # OPNsense SFTP Backup Manager
</div>

A Flask-based web application for managing OPNsense configuration backups via SFTP. This application provides an SFTP server with SSH key authentication, automatically generates SSH keys for each OPNsense instance, and offers a web-based interface for viewing and downloading backups.

## Features

- **SFTP Server**: Built-in SFTP server supporting SSH key authentication
- **SSH Key Generation**: Automatically generates SSH key pairs for each OPNsense instance
- **Multi-Instance Support**: Manage backups from multiple OPNsense instances
- **Web Interface**: Modern web GUI built with Tailwind CSS
- **MariaDB Integration**: Stores instance information, SSH keys, and backup metadata
- **Secure Authentication**: Web interface with session-based authentication

## Quick Start with Docker

### Docker Run

```bash
docker run -d \
  --name opnsense-sftp \
  -p 5000:5000 \
  -p 2222:2222 \
  -e DB_HOST=10.10.2.27 \
  -e DB_PORT=3306 \
  -e DB_NAME=opnsense-sftp \
  -e DB_USER=jamie \
  -e DB_PASSWORD=your_password \
  -e SECRET_KEY=your_secret_key \
  -e ADMIN_PASSWORD=your_admin_password \
  -e SFTP_PORT=2222 \
  -e SFTP_PUBLIC_HOST=opnsense-sftp.jdb143.uk \
  -e SFTP_PUBLIC_PORT=30222 \
  -v /path/to/keys:/app/keys \
  -v /path/to/backups:/app/backups \
  ghcr.io/jdb-net/opnsense-sftp:latest
```

### Docker Compose

```yaml
version: '3.8'

services:
  opnsense-sftp:
    image: ghcr.io/jdb-net/opnsense-sftp:latest
    container_name: opnsense-sftp
    restart: unless-stopped
    ports:
      - "5000:5000"  # Web interface
      - "2222:2222"  # SFTP server
    environment:
      - DB_HOST=10.10.2.27
      - DB_PORT=3306
      - DB_NAME=opnsense-sftp
      - DB_USER=jamie
      - DB_PASSWORD=your_password
      - SECRET_KEY=your_secret_key
      - ADMIN_PASSWORD=your_admin_password
      - SFTP_PORT=2222
      - SFTP_PUBLIC_HOST=opnsense-sftp.jdb143.uk
      - SFTP_PUBLIC_PORT=30222
    volumes:
      - ./keys:/app/keys      # SSH private keys
      - ./backups:/app/backups # Backup files
```

## Configuration

### Environment Variables

- `DB_HOST`: MariaDB host (default: localhost)
- `DB_PORT`: MariaDB port (default: 3306)
- `DB_NAME`: Database name (default: opnsense_backup)
- `DB_USER`: Database user
- `DB_PASSWORD`: Database password
- `SECRET_KEY`: Flask secret key for sessions (**REQUIRED in production!**)
- `ADMIN_PASSWORD`: Default admin password (default: admin)
- `SFTP_HOST`: SFTP server bind address (default: 0.0.0.0)
- `SFTP_PORT`: SFTP server port (default: 2222)
- `SFTP_PUBLIC_HOST`: Public hostname/IP for OPNsense configuration (e.g., `opnsense-sftp.jdb143.uk` or `10.10.2.7`)
- `SFTP_PUBLIC_PORT`: Public port exposed (e.g., NodePort `30222` for Kubernetes)

### Volumes

- `/app/keys`: Directory containing SSH private keys (recommended to mount as volume)
- `/app/backups`: Directory containing backup files (recommended to mount as volume)

## Usage

### Setting up an OPNsense Instance

1. Access the web interface at `http://your-server:5000`
2. Log in with the default credentials (change immediately after first login!)
   - Default username: `admin`
   - Default password: Set via `ADMIN_PASSWORD` environment variable
3. Navigate to "Instances" and click "Add Instance"
4. Fill in:
   - **Name**: Friendly name for the instance (e.g., "Main Router")
   - **Identifier**: Unique identifier (e.g., "lan") - used as SFTP username
   - **Description**: Optional description
5. Click "Create Instance"

### Configuring OPNsense

1. In OPNsense, navigate to **System → Configuration → Backups**
2. Add a new backup target:
   - **Type**: SFTP
   - **Target location (URI)**: Copy from the instance detail page (e.g., `sftp://lan@opnsense-sftp.jdb143.uk:30222//lan`)
   - **SSH Private Key**: Copy or download the private key from the instance detail page
3. Configure your backup schedule and save
4. Test the backup connection to verify authentication works

### Accessing Backups

- View all backups in the "Backups" section
- Download backups by clicking the "Download" link
- View instance-specific backups from the instance detail page

## Kubernetes Deployment

The project includes a Kubernetes deployment manifest. See `deployment.yml` for details.

**Note**: For Kubernetes deployments:
- Use NFS mounts for `keys` and `backups` volumes
- Configure `SFTP_PUBLIC_PORT` to match your NodePort (e.g., `30222`)
- Use `SFTP_PUBLIC_HOST` for the public hostname or IP address

## Security Notes

- **CHANGE THE DEFAULT ADMIN PASSWORD** immediately after first login
- **CHANGE THE SECRET_KEY** in production - use a strong random string
- The SFTP server uses SSH key authentication only (no passwords)
- SSH private keys are stored in the `keys/` directory with restricted permissions (600)
- Backups are stored per-instance to prevent cross-access
- Keep your private keys secure - anyone with access can authenticate as that instance

## Troubleshooting

### Database Connection Issues

- Ensure MariaDB is running and accessible from the container
- Check database credentials in environment variables
- Verify database and user exist with proper permissions
- Check network connectivity between container and database

### SFTP Connection Issues

- Check that the SFTP server is running (should show in logs)
- Verify firewall allows connections on SFTP port (default: 2222)
- Ensure OPNsense can reach the server on the configured port
- Check SSH key format - OPNsense requires the **private key**, not the public key
- Verify the SFTP URI format matches what's displayed in the web interface

### Backup Not Appearing

- Check SFTP server logs for connection attempts
- Verify instance identifier matches SFTP username
- Ensure private key in OPNsense matches the generated key
- Check file permissions on the backups directory

## License

This project is provided as-is for managing OPNsense backups.
