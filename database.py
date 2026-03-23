"""
Database connection and schema management for OPNsense backup system.
"""
import mysql.connector
from mysql.connector import Error
import os
from contextlib import contextmanager
from datetime import datetime
from typing import Optional, List, Dict, Any

from logger_config import get_logger

logger = get_logger(__name__)


class Database:
    """Handle MariaDB database operations."""
    
    def __init__(self):
        self.host = os.getenv('DB_HOST', 'localhost')
        self.port = int(os.getenv('DB_PORT', '3306'))
        self.database = os.getenv('DB_NAME', 'opnsense_backup')
        self.user = os.getenv('DB_USER', 'opnsense_backup')
        self.password = os.getenv('DB_PASSWORD', 'changeme')
        
    @contextmanager
    def get_connection(self):
        """Get database connection with context manager."""
        conn = None
        try:
            conn = mysql.connector.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password
            )
            yield conn
        except Error as e:
            logger.error(f"Database connection error: {e}")
            raise
        finally:
            if conn and conn.is_connected():
                conn.close()
    
    def init_database(self):
        """Initialize database schema."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Create users table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # Backward-compatible user auth columns.
                cursor.execute("SHOW COLUMNS FROM users LIKE 'is_admin'")
                if not cursor.fetchone():
                    cursor.execute("ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT FALSE")

                cursor.execute("SHOW COLUMNS FROM users LIKE 'totp_secret'")
                if not cursor.fetchone():
                    cursor.execute("ALTER TABLE users ADD COLUMN totp_secret VARCHAR(64) NULL")

                cursor.execute("SHOW COLUMNS FROM users LIKE 'totp_enabled'")
                if not cursor.fetchone():
                    cursor.execute("ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT FALSE")
                
                # Create opnsense_instances table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS opnsense_instances (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        name VARCHAR(100) NOT NULL,
                        identifier VARCHAR(100) UNIQUE NOT NULL,
                        ssh_key_id VARCHAR(50) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_backup TIMESTAMP NULL,
                        description TEXT
                    )
                """)
                
                # Create ssh_keys table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ssh_keys (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        key_id VARCHAR(50) UNIQUE NOT NULL,
                        instance_id INT NOT NULL,
                        public_key TEXT NOT NULL,
                        private_key_path VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (instance_id) REFERENCES opnsense_instances(id) ON DELETE CASCADE
                    )
                """)
                
                # Create backups table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS backups (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        instance_id INT NOT NULL,
                        filename VARCHAR(255) NOT NULL,
                        file_path VARCHAR(500) NOT NULL,
                        file_size BIGINT NOT NULL,
                        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (instance_id) REFERENCES opnsense_instances(id) ON DELETE CASCADE
                    )
                """)

                # Create backup pruning settings table (single policy row).
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS backup_prune_settings (
                        id INT PRIMARY KEY,
                        enabled BOOLEAN NOT NULL DEFAULT FALSE,
                        scope_type VARCHAR(10) NOT NULL DEFAULT 'all', /* 'all' or 'instance' */
                        scope_instance_id INT NULL,
                        keep_days INT NULL,
                        keep_count INT NULL,
                        interval_seconds INT NOT NULL DEFAULT 86400,
                        last_run_at TIMESTAMP NULL,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        FOREIGN KEY (scope_instance_id) REFERENCES opnsense_instances(id) ON DELETE SET NULL
                    )
                """)

                # Ensure we have exactly one settings row.
                cursor.execute("""
                    INSERT INTO backup_prune_settings
                        (id, enabled, scope_type, scope_instance_id, keep_days, keep_count, interval_seconds, last_run_at)
                    VALUES
                        (1, FALSE, 'all', NULL, NULL, NULL, 86400, NULL)
                    ON DUPLICATE KEY UPDATE
                        id = id
                """)
                
                conn.commit()
                cursor.close()
                logger.info("Database schema initialized successfully")
        except Error as e:
            logger.error(f"Error initializing database: {e}")
            raise
    
    def create_user(self, username: str, password_hash: str, is_admin: bool = False) -> Optional[int]:
        """Create a new user."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s)",
                    (username, password_hash, is_admin)
                )
                conn.commit()
                user_id = cursor.lastrowid
                cursor.close()
                return user_id
        except Error as e:
            logger.error(f"Error creating user: {e}")
            return None
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = cursor.fetchone()
                cursor.close()
                return user
        except Error as e:
            logger.error(f"Error getting user: {e}")
            return None

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                user = cursor.fetchone()
                cursor.close()
                return user
        except Error as e:
            logger.error(f"Error getting user by id: {e}")
            return None

    def get_all_users(self) -> List[Dict[str, Any]]:
        """Get all users."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    """
                    SELECT id, username, is_admin, totp_enabled, created_at
                    FROM users
                    ORDER BY created_at ASC
                    """
                )
                users = cursor.fetchall()
                cursor.close()
                return users
        except Error as e:
            logger.error(f"Error getting users: {e}")
            return []

    def update_user_username(self, user_id: int, username: str) -> bool:
        """Update username for a user."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET username = %s WHERE id = %s", (username, user_id))
                conn.commit()
                cursor.close()
                return True
        except Error as e:
            logger.error(f"Error updating username: {e}")
            return False

    def update_user_password(self, user_id: int, password_hash: str) -> bool:
        """Update password hash for a user."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (password_hash, user_id))
                conn.commit()
                cursor.close()
                return True
        except Error as e:
            logger.error(f"Error updating password hash: {e}")
            return False

    def update_user_totp(self, user_id: int, totp_secret: Optional[str], totp_enabled: bool) -> bool:
        """Update TOTP settings for a user."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET totp_secret = %s, totp_enabled = %s WHERE id = %s",
                    (totp_secret, totp_enabled, user_id),
                )
                conn.commit()
                cursor.close()
                return True
        except Error as e:
            logger.error(f"Error updating TOTP settings: {e}")
            return False

    def update_user_admin(self, user_id: int, is_admin: bool) -> bool:
        """Update admin flag for a user."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET is_admin = %s WHERE id = %s", (is_admin, user_id))
                conn.commit()
                cursor.close()
                return True
        except Error as e:
            logger.error(f"Error updating user admin flag: {e}")
            return False

    def delete_user(self, user_id: int) -> bool:
        """Delete user by ID."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
                conn.commit()
                cursor.close()
                return True
        except Error as e:
            logger.error(f"Error deleting user: {e}")
            return False
    
    def create_instance(self, name: str, identifier: str, ssh_key_id: str, description: str = "") -> Optional[int]:
        """Create a new OPNsense instance."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO opnsense_instances (name, identifier, ssh_key_id, description)
                       VALUES (%s, %s, %s, %s)""",
                    (name, identifier, ssh_key_id, description)
                )
                conn.commit()
                instance_id = cursor.lastrowid
                cursor.close()
                return instance_id
        except Error as e:
            logger.error(f"Error creating instance: {e}")
            return None
    
    def get_instance_by_identifier(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Get instance by identifier."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    "SELECT * FROM opnsense_instances WHERE identifier = %s",
                    (identifier,)
                )
                instance = cursor.fetchone()
                cursor.close()
                return instance
        except Error as e:
            logger.error(f"Error getting instance by identifier: {e}")
            return None
    
    def get_all_instances(self) -> List[Dict[str, Any]]:
        """Get all instances."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT * FROM opnsense_instances ORDER BY created_at DESC")
                instances = cursor.fetchall()
                cursor.close()
                return instances
        except Error as e:
            logger.error(f"Error getting instances: {e}")
            return []
    
    def save_ssh_key(self, key_id: str, instance_id: int, public_key: str, private_key_path: str) -> bool:
        """Save SSH key to database."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO ssh_keys (key_id, instance_id, public_key, private_key_path)
                       VALUES (%s, %s, %s, %s)""",
                    (key_id, instance_id, public_key, private_key_path)
                )
                conn.commit()
                cursor.close()
                return True
        except Error as e:
            logger.error(f"Error saving SSH key: {e}")
            return False
    
    def get_ssh_key_by_key_id(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Get SSH key by key_id."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT * FROM ssh_keys WHERE key_id = %s", (key_id,))
                key = cursor.fetchone()
                cursor.close()
                return key
        except Error as e:
            logger.error(f"Error getting SSH key: {e}")
            return None
    
    def record_backup(self, instance_id: int, filename: str, file_path: str, file_size: int) -> bool:
        """Record a backup in the database."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO backups (instance_id, filename, file_path, file_size)
                       VALUES (%s, %s, %s, %s)""",
                    (instance_id, filename, file_path, file_size)
                )
                cursor.execute(
                    "UPDATE opnsense_instances SET last_backup = CURRENT_TIMESTAMP WHERE id = %s",
                    (instance_id,)
                )
                conn.commit()
                cursor.close()
                return True
        except Error as e:
            logger.error(f"Error recording backup: {e}")
            return False
    
    def get_backups_for_instance(self, instance_id: int) -> List[Dict[str, Any]]:
        """Get all backups for an instance."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(
                    """SELECT * FROM backups WHERE instance_id = %s 
                       ORDER BY uploaded_at DESC""",
                    (instance_id,)
                )
                backups = cursor.fetchall()
                cursor.close()
                return backups
        except Error as e:
            logger.error(f"Error getting backups: {e}")
            return []
    
    def get_all_backups(self) -> List[Dict[str, Any]]:
        """Get all backups with instance information."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT b.*, o.name as instance_name, o.identifier as instance_identifier
                    FROM backups b
                    JOIN opnsense_instances o ON b.instance_id = o.id
                    ORDER BY b.uploaded_at DESC
                """)
                backups = cursor.fetchall()
                cursor.close()
                return backups
        except Error as e:
            logger.error(f"Error getting all backups: {e}")
            return []
    
    def get_instance_by_id(self, instance_id: int) -> Optional[Dict[str, Any]]:
        """Get instance by ID."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT * FROM opnsense_instances WHERE id = %s", (instance_id,))
                instance = cursor.fetchone()
                cursor.close()
                return instance
        except Error as e:
            logger.error(f"Error getting instance by ID: {e}")
            return None
    
    def get_latest_backup_per_instance(self) -> List[Dict[str, Any]]:
        """Get the latest backup date and time for each instance."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT 
                        o.id as instance_id,
                        o.name as instance_name,
                        o.identifier as instance_identifier,
                        MAX(b.uploaded_at) as latest_backup
                    FROM opnsense_instances o
                    LEFT JOIN backups b ON o.id = b.instance_id
                    GROUP BY o.id, o.name, o.identifier
                    ORDER BY o.name
                """)
                results = cursor.fetchall()
                cursor.close()
                return results
        except Error as e:
            logger.error(f"Error getting latest backup per instance: {e}")
            return []

    def get_backup_prune_settings(self) -> Dict[str, Any]:
        """Get automated backup prune settings (single row)."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT * FROM backup_prune_settings WHERE id = %s", (1,))
                row = cursor.fetchone()
                cursor.close()
                if row:
                    return row
        except Error as e:
            logger.error(f"Error getting backup prune settings: {e}")
        # Safe defaults if table/row doesn't exist yet.
        return {
            "id": 1,
            "enabled": False,
            "scope_type": "all",
            "scope_instance_id": None,
            "keep_days": None,
            "keep_count": None,
            "interval_seconds": 86400,
            "last_run_at": None,
            "updated_at": None,
        }

    def upsert_backup_prune_settings(
        self,
        enabled: bool,
        scope_type: str,
        scope_instance_id: Optional[int],
        keep_days: Optional[int],
        keep_count: Optional[int],
        interval_seconds: int,
    ) -> None:
        """Upsert automated backup prune settings (single row)."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO backup_prune_settings
                        (id, enabled, scope_type, scope_instance_id, keep_days, keep_count, interval_seconds)
                    VALUES
                        (1, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        enabled = VALUES(enabled),
                        scope_type = VALUES(scope_type),
                        scope_instance_id = VALUES(scope_instance_id),
                        keep_days = VALUES(keep_days),
                        keep_count = VALUES(keep_count),
                        interval_seconds = VALUES(interval_seconds)
                    """,
                    (
                        bool(enabled),
                        scope_type,
                        scope_instance_id,
                        keep_days,
                        keep_count,
                        interval_seconds,
                    ),
                )
                conn.commit()
                cursor.close()
        except Error as e:
            logger.error(f"Error updating backup prune settings: {e}")

    def set_backup_prune_last_run_at(self, last_run_at: datetime) -> None:
        """Update last_run_at after a prune run."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE backup_prune_settings SET last_run_at = %s WHERE id = %s",
                    (last_run_at, 1),
                )
                conn.commit()
                cursor.close()
        except Error as e:
            logger.error(f"Error updating backup prune last_run_at: {e}")

    def delete_backups_by_ids(self, backup_ids: List[int]) -> int:
        """Delete backup records by IDs (returns number of deleted rows)."""
        if not backup_ids:
            return 0
        try:
            placeholders = ", ".join(["%s"] * len(backup_ids))
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f"DELETE FROM backups WHERE id IN ({placeholders})",
                    tuple(backup_ids),
                )
                affected = cursor.rowcount or 0
                conn.commit()
                cursor.close()
                return affected
        except Error as e:
            logger.error(f"Error deleting backups by ids: {e}")
            return 0

