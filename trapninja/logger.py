#!/usr/bin/env python3
"""
TrapNinja Logging Module - Optimized Version

Sets up logging configuration for the application with improved
performance and optimized file handling.
"""
import os
import logging
import gzip
import shutil
import threading
from logging.handlers import RotatingFileHandler

# Initialize logger - config values will be set during setup_logging
logger = logging.getLogger("trapninja")
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', '%Y-%m-%d %H:%M:%S')

# Thread-local storage for more efficient logging
_thread_local = threading.local()


class CompressedRotatingFileHandler(RotatingFileHandler):
    """
    Extended RotatingFileHandler that compresses rotated files
    with optimized compression handling
    """

    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0,
                 encoding=None, delay=0, compress=False):
        """
        Initialize the handler with compression option

        Args:
            compress (bool): Whether to compress rotated log files
        """
        self.compress = compress
        super(CompressedRotatingFileHandler, self).__init__(
            filename, mode, maxBytes, backupCount, encoding, delay)

        # Track files that have been compressed to avoid redundant work
        self._compressed_files = set()

    def doRollover(self):
        """
        Overridden method to add compression after rotation
        with improved efficiency
        """
        # First, do the standard rollover
        super(CompressedRotatingFileHandler, self).doRollover()

        # If compression is enabled, compress the rotated file
        if self.compress:
            # Start compression in a separate thread to avoid blocking
            threading.Thread(target=self._compress_logs, daemon=True).start()

    def _compress_logs(self):
        """
        Compress rotated log files in a background thread
        to avoid blocking the main thread
        """
        # The rotated file has a suffix of .1, .2, etc.
        # Example: /var/log/trapninja.log.1
        for i in range(1, self.backupCount + 1):
            log_file = f"{self.baseFilename}.{i}"
            gz_file = f"{log_file}.gz"

            # Only compress if the file exists, isn't already compressed,
            # and hasn't been processed in this session
            if (os.path.exists(log_file) and
                    not os.path.exists(gz_file) and
                    log_file not in self._compressed_files):

                try:
                    # Mark file as being processed
                    self._compressed_files.add(log_file)

                    # Compress with higher efficiency
                    with open(log_file, 'rb') as f_in:
                        with gzip.open(gz_file, 'wb', compresslevel=6) as f_out:
                            # Use larger buffer for better performance
                            shutil.copyfileobj(f_in, f_out, length=1024 * 1024)

                    # Remove the original file after successful compression
                    os.remove(log_file)
                except Exception as e:
                    # If compression fails, log an error but don't stop execution
                    print(f"Error compressing log file {log_file}: {e}")


class ThreadLocalAdapter(logging.LoggerAdapter):
    """
    Logger adapter that caches formatted messages
    in thread-local storage for better performance
    """

    def process(self, msg, kwargs):
        """
        Process the logging message and keyword arguments passed in to
        a logging call to insert context information as needed.
        """
        # Check for thread-local cache
        if not hasattr(_thread_local, 'log_cache'):
            _thread_local.log_cache = {}

        # Use message as cache key
        cache_key = str(msg)

        # Check cache for already formatted message
        if cache_key in _thread_local.log_cache:
            return _thread_local.log_cache[cache_key], kwargs

        # Format message and cache it
        _thread_local.log_cache[cache_key] = msg

        # Limit cache size
        if len(_thread_local.log_cache) > 1000:
            # Clear the oldest entries (simple approach)
            cache_keys = list(_thread_local.log_cache.keys())
            for key in cache_keys[:500]:  # Remove half the cache
                del _thread_local.log_cache[key]

        return msg, kwargs


def setup_logging(console=True, log_file=None, log_level=None, max_size=10 * 1024 * 1024,
                  backup_count=5, compress=False):
    """
    Set up logging with optional console output and rotation settings
    Optimized for better performance and resource usage

    Args:
        console (bool): Whether to output logs to console as well
        log_file (str): Path to log file, defaults to config.LOG_FILE
        log_level (str): Log level, defaults to config.LOG_LEVEL
        max_size (int): Maximum size of log file in bytes before rotation
        backup_count (int): Number of backup files to keep
        compress (bool): Whether to compress rotated log files
    """
    global logger

    # Get configuration from the config module
    if log_file is None:
        from .config import LOG_FILE
        log_file = LOG_FILE

    if log_level is None:
        from .config import LOG_LEVEL
        log_level = LOG_LEVEL

    # Convert string log level to numeric value using a mapping
    # for better performance than getattr
    log_level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    numeric_level = log_level_map.get(log_level.upper(), logging.INFO)

    # Set the log level
    logger.setLevel(numeric_level)

    # Clear any existing handlers
    logger.handlers = []

    # File handler with rotation
    try:
        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir)
            except Exception:
                # Handle race condition if directory was created in between
                if not os.path.exists(log_dir):
                    raise

        # Use our custom handler if compression is enabled, otherwise use the standard one
        if compress:
            file_handler = CompressedRotatingFileHandler(
                log_file, maxBytes=max_size, backupCount=backup_count, compress=True)
        else:
            file_handler = RotatingFileHandler(
                log_file, maxBytes=max_size, backupCount=backup_count)

        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Error setting up file logging: {e}")

    # Console handler (optional)
    if console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # Wrap logger in thread-local adapter for better performance
    adapted_logger = ThreadLocalAdapter(logger, {})

    # Replace the global logger with our adapted version
    logging.getLogger("trapninja").logger = adapted_logger

    return adapted_logger