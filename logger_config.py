"""
Custom logging configuration with emojis and clean formatting.
"""
import logging
import sys
from datetime import datetime


class EmojiFormatter(logging.Formatter):
    """Custom formatter with emojis for different log levels."""
    
    # Emoji mapping for log levels
    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': 'ℹ️',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🚨',
    }
    
    def format(self, record):
        # Get emoji for log level
        emoji = self.EMOJIS.get(record.levelname, '📝')
        
        # Format timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Format message with emoji and timestamp
        message = f"{emoji} [{timestamp}] {record.getMessage()}"
        
        return message


def setup_logging(level=logging.INFO):
    """Setup custom logging configuration.
    
    Args:
        level: Logging level (default: INFO)
    """
    # Get root logger
    logger = logging.getLogger()
    logger.setLevel(level)
    
    # Remove existing handlers
    logger.handlers = []
    
    # Create console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    
    # Set custom formatter
    formatter = EmojiFormatter()
    handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(handler)
    
    return logger


def get_logger(name):
    """Get a logger with the custom configuration.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)

