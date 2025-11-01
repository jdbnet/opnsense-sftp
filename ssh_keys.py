"""
SSH key generation and management for OPNsense backup system.
"""
import os
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from pathlib import Path
from typing import Tuple, Optional

from logger_config import get_logger

logger = get_logger(__name__)


class SSHKeyManager:
    """Manage SSH key generation and storage."""
    
    def __init__(self, keys_dir: str = "keys"):
        """Initialize SSH key manager.
        
        Args:
            keys_dir: Directory to store SSH private keys
        """
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(exist_ok=True, mode=0o700)  # Ensure directory exists with proper permissions
    
    def generate_key_pair(self, key_id: str) -> Tuple[str, str]:
        """Generate a new SSH key pair.
        
        Args:
            key_id: Unique identifier for the key
            
        Returns:
            Tuple of (private_key_path, public_key_string)
        """
        # Generate RSA key pair (4096 bits)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        # Serialize private key in OpenSSH format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Get public key in OpenSSH format
        public_key = private_key.public_key()
        public_key_ssh = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )
        
        # Save private key to file
        private_key_path = self.keys_dir / f"{key_id}"
        with open(private_key_path, 'wb') as f:
            f.write(private_key_pem)
        os.chmod(private_key_path, 0o600)  # Restrict permissions
        
        # Return public key as string and private key path
        public_key_str = public_key_ssh.decode('utf-8')
        return str(private_key_path), public_key_str
    
    def get_public_key_for_display(self, public_key: str, comment: str = "") -> str:
        """Format public key for display (add comment if needed).
        
        Args:
            public_key: Public key string
            comment: Optional comment to append
            
        Returns:
            Formatted public key string
        """
        if comment:
            return f"{public_key} {comment}"
        return public_key
    
    def load_private_key(self, key_id: str) -> Optional[bytes]:
        """Load private key from file.
        
        Args:
            key_id: Key identifier
            
        Returns:
            Private key bytes or None if not found
        """
        private_key_path = self.keys_dir / key_id
        if not private_key_path.exists():
            return None
        
        try:
            with open(private_key_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error loading private key {key_id}: {e}")
            return None
    
    def delete_key(self, key_id: str) -> bool:
        """Delete SSH key file.
        
        Args:
            key_id: Key identifier
            
        Returns:
            True if deleted successfully
        """
        private_key_path = self.keys_dir / key_id
        try:
            if private_key_path.exists():
                os.remove(private_key_path)
            return True
        except Exception as e:
            logger.error(f"Error deleting key {key_id}: {e}")
            return False
    
    def generate_key_id(self) -> str:
        """Generate a unique key identifier."""
        return str(uuid.uuid4())

