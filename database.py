"""
Database connection and schema management for OPNsense backup system.
"""
import mysql.connector
from mysql.connector import Error
import os
from contextlib import contextmanager
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
                
                conn.commit()
                cursor.close()
                logger.info("Database schema initialized successfully")
        except Error as e:
            logger.error(f"Error initializing database: {e}")
            raise
    
    def create_user(self, username: str, password_hash: str) -> Optional[int]:
        """Create a new user."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                    (username, password_hash)
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

