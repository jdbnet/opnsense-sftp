"""
SFTP server implementation for OPNsense backup system.
"""
import os
import threading
from pathlib import Path
from typing import Optional
import paramiko
from paramiko import ServerInterface, AUTH_FAILED, OPEN_SUCCEEDED
from paramiko.sftp_server import SFTPServer, SFTPServerInterface
from paramiko.sftp_handle import SFTPHandle

from database import Database
from ssh_keys import SSHKeyManager
from logger_config import get_logger

logger = get_logger(__name__)


class OPNsenseServerInterface(ServerInterface):
    """SSH server interface for authentication and SFTP operations."""
    
    def __init__(self, database: Database, ssh_key_manager: SSHKeyManager, backups_dir: str = "backups"):
        """Initialize server interface.
        
        Args:
            database: Database instance
            ssh_key_manager: SSH key manager instance
            backups_dir: Directory to store backups
        """
        self.database = database
        self.ssh_key_manager = ssh_key_manager
        self.backups_dir = Path(backups_dir)
        self.backups_dir.mkdir(exist_ok=True, mode=0o755)
        self.current_instance = None
    
    def _canonicalize(self, path):
        """Canonicalize path - ensure it's within backups directory."""
        if isinstance(path, bytes):
            path = path.decode('utf-8')
        
        # Remove leading slash
        path = path.lstrip('/')
        
        if not self.current_instance:
            logger.error(f"No current instance for path: {path}")
            return None
        
        # If path is just the instance identifier (e.g., "lan" from "/lan"),
        # treat it as the root directory for this instance
        if path == self.current_instance['identifier']:
            path = ""
        
        # If path starts with instance identifier (e.g., "lan/backup.xml" from "/lan/backup.xml"),
        # remove it to avoid duplicate instance directory in path
        if path.startswith(self.current_instance['identifier'] + '/'):
            path = path[len(self.current_instance['identifier']) + 1:]
        
        instance_dir = self.backups_dir / self.current_instance['identifier']
        instance_dir.mkdir(exist_ok=True, mode=0o755)
        full_path = instance_dir / path if path else instance_dir
        
        try:
            full_path = full_path.resolve()
            instance_dir_resolved = instance_dir.resolve()
            if not str(full_path).startswith(str(instance_dir_resolved)):
                logger.warning(f"Path traversal attempt detected: {full_path} not in {instance_dir_resolved}")
                return None  # Path traversal attempt
        except Exception as e:
            logger.error(f"Error resolving path {full_path}: {e}")
            return None
        
        return str(full_path)
    
    
    def check_channel_request(self, kind, chanid):
        """Check channel request."""
        if kind == "session":
            return OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_auth_publickey(self, username, key):
        """Authenticate using public key.
        
        Args:
            username: Username (should be instance identifier)
            key: Public key object from paramiko
            
        Returns:
            AUTH_SUCCESSFUL or AUTH_FAILED
        """
        try:
            # Get instance by identifier (username)
            instance = self.database.get_instance_by_identifier(username)
            if not instance:
                logger.warning(f"Instance not found: {username}")
                return AUTH_FAILED
            
            # Get SSH key for this instance
            ssh_key = self.database.get_ssh_key_by_key_id(instance['ssh_key_id'])
            if not ssh_key:
                logger.warning(f"SSH key not found for instance: {username}")
                return AUTH_FAILED
            
            # Compare public keys - get base64 representation
            stored_public_key = ssh_key['public_key'].strip()
            key_fingerprint = key.get_base64()
            
            # Extract key type and base64 from stored key
            # Format: "ssh-rsa AAAAB3NzaC1yc2E..."
            parts = stored_public_key.split()
            if len(parts) >= 2:
                stored_base64 = parts[1]
                if stored_base64 == key_fingerprint or key_fingerprint in stored_public_key:
                    self.current_instance = instance
                    logger.info(f"Authentication successful for instance: {username}")
                    return paramiko.AUTH_SUCCESSFUL
            
            logger.warning(f"Public key mismatch for instance: {username}")
            return AUTH_FAILED
            
        except Exception as e:
            logger.error(f"Error during authentication: {e}")
            return AUTH_FAILED
    
    def get_allowed_auths(self, username):
        """Return allowed authentication methods."""
        return "publickey"
    
    def check_auth_password(self, username, password):
        """Password authentication not supported."""
        return AUTH_FAILED
    
    def check_auth_none(self, username):
        """None authentication not supported."""
        return AUTH_FAILED
    


class OPNsenseSFTPHandle(SFTPHandle):
    """Custom SFTP handle that records backups when closed."""
    
    def __init__(self, flags, sftp_interface):
        """Initialize SFTP handle.
        
        Args:
            flags: File open flags
            sftp_interface: OPNsenseSFTPServerInterface instance
        """
        super().__init__(flags)
        self.sftp_interface = sftp_interface
        self.filename = None
        self.readfile = None
        self.writefile = None
    
    def close(self):
        """Close file handle and record backup if it was a write operation."""
        try:
            if self.writefile:
                self.writefile.close()
                
                instance = self.sftp_interface.current_instance
                if instance and self.filename:
                    filename = Path(self.filename).name
                    file_size = Path(self.filename).stat().st_size if Path(self.filename).exists() else 0
                    
                    try:
                        self.sftp_interface.database.record_backup(
                            instance_id=instance['id'],
                            filename=filename,
                            file_path=str(self.filename),
                            file_size=file_size
                        )
                        logger.info(f"Backup recorded: {filename} ({file_size} bytes) for instance {instance['identifier']}")
                    except Exception as e:
                        logger.error(f"Error recording backup in database: {e}", exc_info=True)
            
            if self.readfile:
                self.readfile.close()
            
            # Call parent close
            super().close()
        except Exception as e:
            logger.error(f"Error in OPNsenseSFTPHandle.close: {e}", exc_info=True)
            super().close()


class OPNsenseSFTPServerInterface(SFTPServerInterface):
    """SFTP server interface for handling file operations."""
    
    def __init__(self, server, *args, **kwargs):
        """Initialize SFTP server interface.
        
        Args:
            server: The OPNsenseServerInterface instance (from ServerInterface)
        """
        super().__init__(server, *args, **kwargs)
        self.server_interface = server
    
    @property
    def current_instance(self):
        """Get current instance from server interface."""
        return getattr(self.server_interface, 'current_instance', None)
    
    @property
    def backups_dir(self):
        """Get backups directory from server interface."""
        return getattr(self.server_interface, 'backups_dir', Path('backups'))
    
    @property
    def database(self):
        """Get database from server interface."""
        return getattr(self.server_interface, 'database', None)
    
    def _canonicalize(self, path):
        """Canonicalize path - ensure it's within backups directory."""
        if isinstance(path, bytes):
            path = path.decode('utf-8')
        
        original_path = path
        
        # Check if path is already an absolute path within our backups directory
        try:
            path_obj = Path(path)
            if path_obj.is_absolute():
                path_resolved = path_obj.resolve()
                instance_dir = self.backups_dir / (self.current_instance['identifier'] if self.current_instance else '')
                instance_dir_resolved = instance_dir.resolve()
                
                # If the resolved path is within the instance directory, use it directly
                if str(path_resolved).startswith(str(instance_dir_resolved)):
                    return str(path_resolved)
        except Exception:
            pass
        
        # Remove leading slash
        path = path.lstrip('/')
        
        instance = self.current_instance
        if not instance:
            logger.error(f"No current instance for path: {path}")
            return None
        
        # If path is just the instance identifier (e.g., "lan" from "/lan"),
        # treat it as the root directory for this instance
        if path == instance['identifier']:
            path = ""
        
        # If path starts with instance identifier (e.g., "lan/backup.xml" from "/lan/backup.xml"),
        # remove it to avoid duplicate instance directory in path
        if path.startswith(instance['identifier'] + '/'):
            path = path[len(instance['identifier']) + 1:]
        
        instance_dir = self.backups_dir / instance['identifier']
        instance_dir.mkdir(exist_ok=True, mode=0o755)
        full_path = instance_dir / path if path else instance_dir
        
        try:
            full_path = full_path.resolve()
            instance_dir_resolved = instance_dir.resolve()
            if not str(full_path).startswith(str(instance_dir_resolved)):
                logger.warning(f"Path traversal attempt detected: {full_path} not in {instance_dir_resolved}")
                return None
        except Exception as e:
            logger.error(f"Error resolving path {full_path}: {e}", exc_info=True)
            return None
        
        return str(full_path)
    
    def canonicalize(self, path):
        """Convert path to real path (canonicalized). This is called by paramiko for REALPATH requests."""
        canonical_path = self._canonicalize(path)
        if not canonical_path:
            logger.warning(f"canonicalize: canonicalization failed for {path}, returning original")
            return path
        return canonical_path
    
    def stat(self, path):
        """Get file/directory stats."""
        canonical_path = self._canonicalize(path)
        if not canonical_path:
            logger.error(f"stat: canonicalization failed for path: {path}")
            return paramiko.SFTP_NO_SUCH_FILE
        
        # Ensure the directory exists
        if not os.path.exists(canonical_path):
            instance = self.current_instance
            if instance:
                instance_dir = self.backups_dir / instance['identifier']
                canonical_path_obj = Path(canonical_path)
                try:
                    if canonical_path_obj.resolve() == instance_dir.resolve():
                        os.makedirs(canonical_path, mode=0o755, exist_ok=True)
                    else:
                        return paramiko.SFTP_NO_SUCH_FILE
                except Exception as e:
                    logger.error(f"Error creating instance directory: {e}")
                    return paramiko.SFTP_NO_SUCH_FILE
            else:
                logger.error(f"stat: no current instance")
                return paramiko.SFTP_NO_SUCH_FILE
        
        try:
            stat_result = os.stat(canonical_path)
            attr = paramiko.SFTPAttributes.from_stat(stat_result)
            if os.path.isdir(canonical_path):
                attr.st_mode = stat_result.st_mode
            return attr
        except OSError as e:
            logger.error(f"Error getting stats for {canonical_path}: {e}")
            if e.errno == 2:  # No such file or directory
                return paramiko.SFTP_NO_SUCH_FILE
            return paramiko.SFTP_FAILURE
        except Exception as e:
            logger.error(f"Unexpected error getting stats: {e}", exc_info=True)
            return paramiko.SFTP_FAILURE
    
    def lstat(self, path):
        """Get file/directory stats (without following symlinks)."""
        canonical_path = self._canonicalize(path)
        if not canonical_path:
            logger.error(f"lstat: canonicalization failed for path: {path}")
            return paramiko.SFTP_NO_SUCH_FILE
        
        # Ensure the directory exists
        if not os.path.exists(canonical_path):
            instance = self.current_instance
            if instance:
                instance_dir = self.backups_dir / instance['identifier']
                canonical_path_obj = Path(canonical_path)
                try:
                    if canonical_path_obj.resolve() == instance_dir.resolve():
                        os.makedirs(canonical_path, mode=0o755, exist_ok=True)
                    else:
                        return paramiko.SFTP_NO_SUCH_FILE
                except Exception as e:
                    logger.error(f"Error creating instance directory: {e}")
                    return paramiko.SFTP_NO_SUCH_FILE
            else:
                logger.error(f"lstat: no current instance")
                return paramiko.SFTP_NO_SUCH_FILE
        
        try:
            stat_result = os.lstat(canonical_path)
            attr = paramiko.SFTPAttributes.from_stat(stat_result)
            if os.path.isdir(canonical_path):
                attr.st_mode = stat_result.st_mode
            return attr
        except OSError as e:
            logger.error(f"Error getting lstat for {canonical_path}: {e}")
            if e.errno == 2:  # No such file or directory
                return paramiko.SFTP_NO_SUCH_FILE
            return paramiko.SFTP_FAILURE
        except Exception as e:
            logger.error(f"Unexpected error getting lstat: {e}", exc_info=True)
            return paramiko.SFTP_FAILURE
    
    def open(self, path, flags, attr):
        """Open a file for reading/writing."""
        canonical_path = self._canonicalize(path)
        if not canonical_path:
            logger.error(f"open: canonicalization failed for {path}")
            return paramiko.SFTP_NO_SUCH_FILE
        
        if os.path.isdir(canonical_path):
            logger.warning(f"open: attempted to open directory as file: {canonical_path}")
            return paramiko.SFTP_FAILURE
        
        try:
            if flags & os.O_WRONLY or flags & os.O_RDWR or (flags & os.O_CREAT and flags & os.O_WRONLY):
                Path(canonical_path).parent.mkdir(parents=True, exist_ok=True)
                f = open(canonical_path, 'wb')
                file_handle = OPNsenseSFTPHandle(flags, self)
                file_handle.filename = canonical_path
                file_handle.readfile = None
                file_handle.writefile = f
                return file_handle
            else:
                if not os.path.exists(canonical_path):
                    logger.error(f"open: file does not exist: {canonical_path}")
                    return paramiko.SFTP_NO_SUCH_FILE
                if os.path.isdir(canonical_path):
                    logger.error(f"open: path is directory: {canonical_path}")
                    return paramiko.SFTP_FAILURE
                f = open(canonical_path, 'rb')
                file_handle = OPNsenseSFTPHandle(flags, self)
                file_handle.filename = canonical_path
                file_handle.readfile = f
                file_handle.writefile = None
                return file_handle
        except OSError as e:
            logger.error(f"Error opening file {canonical_path}: {e}")
            if e.errno == 2:  # No such file or directory
                return paramiko.SFTP_NO_SUCH_FILE
            return paramiko.SFTP_FAILURE
        except Exception as e:
            logger.error(f"Unexpected error opening file {canonical_path}: {e}", exc_info=True)
            return paramiko.SFTP_FAILURE
    
    def close(self, handle):
        """Close file handle.
        
        Note: Paramiko calls handle.close() directly, so the backup recording
        is handled in OPNsenseSFTPHandle.close(). This method is kept for
        compatibility but shouldn't be called for file handles.
        """
        # The actual close logic is in OPNsenseSFTPHandle.close()
        return paramiko.SFTP_OK
    
    def list_folder(self, path):
        """List folder contents."""
        canonical_path = self._canonicalize(path)
        if not canonical_path:
            logger.warning(f"list_folder: canonicalization failed")
            return []
        
        if not os.path.exists(canonical_path):
            try:
                os.makedirs(canonical_path, mode=0o755, exist_ok=True)
            except Exception as e:
                logger.error(f"Error creating directory: {e}")
                return []
        
        if not os.path.isdir(canonical_path):
            logger.warning(f"list_folder: path is not a directory: {canonical_path}")
            return []
        
        try:
            files = []
            for item in os.listdir(canonical_path):
                item_path = os.path.join(canonical_path, item)
                stat = os.stat(item_path)
                attr = paramiko.SFTPAttributes.from_stat(stat)
                attr.filename = item
                files.append(attr)
            return files
        except Exception as e:
            logger.error(f"Error listing folder: {e}", exc_info=True)
            return []
    
    def remove(self, path):
        """Remove a file."""
        canonical_path = self._canonicalize(path)
        if not canonical_path:
            return paramiko.SFTP_NO_SUCH_FILE
        
        try:
            os.remove(canonical_path)
            logger.info(f"Deleted file: {Path(canonical_path).name}")
            return paramiko.SFTP_OK
        except OSError as e:
            logger.error(f"Error removing file: {e}")
            if e.errno == 2:  # No such file or directory
                return paramiko.SFTP_NO_SUCH_FILE
            return paramiko.SFTP_FAILURE
        except Exception as e:
            logger.error(f"Unexpected error removing file: {e}")
            return paramiko.SFTP_FAILURE


class OPNsenseSFTPServer(SFTPServer):
    """Custom SFTP server that uses OPNsenseSFTPServerInterface."""
    
    def __init__(self, channel, name, server, *args, **kwargs):
        """Initialize SFTP server.
        
        Args:
            channel: SSH channel
            name: Subsystem name
            server: OPNsenseServerInterface instance (ServerInterface)
            *args, **kwargs: Additional arguments passed through
        """
        # Pass OPNsenseSFTPServerInterface as sftp_si parameter
        # This tells SFTPServer to use our SFTP interface for handling operations
        super().__init__(channel, name, server, sftp_si=OPNsenseSFTPServerInterface, *args, **kwargs)


class SFTPThreadedServer:
    """Threaded SFTP server that runs in background."""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 2222, 
                 database: Optional[Database] = None,
                 ssh_key_manager: Optional[SSHKeyManager] = None,
                 backups_dir: str = "backups"):
        """Initialize threaded SFTP server.
        
        Args:
            host: Host to bind to
            port: Port to listen on
            database: Database instance
            ssh_key_manager: SSH key manager instance
            backups_dir: Directory for backups
        """
        self.host = host
        self.port = port
        self.database = database or Database()
        self.ssh_key_manager = ssh_key_manager or SSHKeyManager()
        self.backups_dir = backups_dir
        self.server_socket = None
        self.thread = None
        self.running = False
    
    def _handle_client(self, client, addr):
        """Handle individual client connection."""
        try:
            transport = paramiko.Transport(client)
            
            # Create server instance
            server_interface = OPNsenseServerInterface(
                self.database,
                self.ssh_key_manager,
                self.backups_dir
            )
            
            # Load or generate host key
            keys_dir = Path("keys")
            keys_dir.mkdir(exist_ok=True, mode=0o700)
            host_key_path = keys_dir / "host_key"
            
            if not host_key_path.exists():
                key = paramiko.RSAKey.generate(2048)
                key.write_private_key_file(str(host_key_path))
                os.chmod(host_key_path, 0o600)
                logger.info("Generated new SSH host key")
            
            host_key = paramiko.RSAKey.from_private_key_file(str(host_key_path))
            transport.add_server_key(host_key)
            
            # Set SFTP subsystem - use a factory function to create OPNsenseSFTPServer
            def create_sftp_server(channel, name, server):
                return OPNsenseSFTPServer(channel, name, server)
            
            transport.set_subsystem_handler('sftp', create_sftp_server)
            
            # Start server
            transport.start_server(server=server_interface)
            
            # Accept connection
            channel = transport.accept(20)
            if channel is None:
                logger.warning(f"Client {addr} connection timeout")
                transport.close()
                return
            
            instance_id = server_interface.current_instance['identifier'] if server_interface.current_instance else 'unknown'
            logger.info(f"SFTP client connected from {addr[0]}:{addr[1]} as {instance_id}")
            
            # Keep connection alive
            while transport.is_active():
                import time
                time.sleep(1)
            
            transport.close()
            logger.info(f"SFTP client {addr[0]}:{addr[1]} disconnected")
            
        except Exception as e:
            logger.error(f"Error handling SFTP client {addr}: {e}")
    
    def start(self):
        """Start the SFTP server in a background thread."""
        if self.running:
            logger.warning("SFTP server already running")
            return
        
        try:
            import socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.running = True
            
            def server_loop():
                logger.info(f"SFTP server started on {self.host}:{self.port}")
                while self.running:
                    try:
                        client, addr = self.server_socket.accept()
                        client_thread = threading.Thread(
                            target=self._handle_client,
                            args=(client, addr),
                            daemon=True
                        )
                        client_thread.start()
                    except Exception as e:
                        if self.running:
                            logger.error(f"Error accepting SFTP connection: {e}")
            
            self.thread = threading.Thread(target=server_loop, daemon=True)
            self.thread.start()
            
        except Exception as e:
            logger.error(f"Error starting SFTP server: {e}")
            self.running = False
            raise
    
    def stop(self):
        """Stop the SFTP server."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        logger.info("SFTP server stopped")

