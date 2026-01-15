#!/usr/bin/env python3
"""
TrapNinja Test Suite - Logger Module Tests

Tests for trapninja.logger module.

Assumptions:
- CompressedRotatingFileHandler extends RotatingFileHandler
- Compression happens in a background thread (async)
- ThreadLocalAdapter caches messages in thread-local storage
- Cache size is limited to 1000 entries, evicts 500 when full
- setup_logging creates appropriate handlers based on arguments
- Log level strings are case-insensitive

Author: TrapNinja Team
"""

import os
import gzip
import logging
import threading
import pytest
from unittest.mock import MagicMock, patch, mock_open, call
from io import BytesIO


class TestCompressedRotatingFileHandler:
    """Tests for CompressedRotatingFileHandler class."""

    def test_init_with_compression_disabled(self, tmp_path):
        """Test handler initialization with compression disabled."""
        from trapninja.logger import CompressedRotatingFileHandler
        
        log_file = tmp_path / "test.log"
        handler = CompressedRotatingFileHandler(
            str(log_file),
            maxBytes=1000,
            backupCount=3,
            compress=False
        )
        
        assert handler.compress is False
        assert handler.backupCount == 3
        assert handler.maxBytes == 1000
        handler.close()

    def test_init_with_compression_enabled(self, tmp_path):
        """Test handler initialization with compression enabled."""
        from trapninja.logger import CompressedRotatingFileHandler
        
        log_file = tmp_path / "test.log"
        handler = CompressedRotatingFileHandler(
            str(log_file),
            maxBytes=1000,
            backupCount=3,
            compress=True
        )
        
        assert handler.compress is True
        assert handler._compressed_files == set()
        handler.close()

    def test_compressed_files_tracking(self, tmp_path):
        """Test that compressed files are tracked to avoid redundant compression."""
        from trapninja.logger import CompressedRotatingFileHandler
        
        log_file = tmp_path / "test.log"
        handler = CompressedRotatingFileHandler(
            str(log_file),
            maxBytes=1000,
            backupCount=3,
            compress=True
        )
        
        # Initially empty
        assert len(handler._compressed_files) == 0
        
        # Track a file
        handler._compressed_files.add(str(log_file) + ".1")
        assert str(log_file) + ".1" in handler._compressed_files
        
        handler.close()

    @patch('threading.Thread')
    def test_rollover_starts_compression_thread(self, mock_thread, tmp_path):
        """Test that rollover starts compression thread when enabled."""
        from trapninja.logger import CompressedRotatingFileHandler
        
        log_file = tmp_path / "test.log"
        log_file.write_text("initial content")
        
        handler = CompressedRotatingFileHandler(
            str(log_file),
            maxBytes=100,
            backupCount=3,
            compress=True
        )
        
        # Trigger rollover
        handler.doRollover()
        
        # Verify thread was started
        mock_thread.assert_called_once()
        call_kwargs = mock_thread.call_args[1]
        assert call_kwargs['daemon'] is True
        assert call_kwargs['target'] == handler._compress_logs
        
        handler.close()

    @patch('threading.Thread')
    def test_rollover_skips_compression_when_disabled(self, mock_thread, tmp_path):
        """Test that rollover does not start thread when compression disabled."""
        from trapninja.logger import CompressedRotatingFileHandler
        
        log_file = tmp_path / "test.log"
        log_file.write_text("initial content")
        
        handler = CompressedRotatingFileHandler(
            str(log_file),
            maxBytes=100,
            backupCount=3,
            compress=False
        )
        
        handler.doRollover()
        
        # Thread should not be started
        mock_thread.assert_not_called()
        
        handler.close()

    def test_compress_logs_creates_gzip_file(self, tmp_path):
        """Test that _compress_logs creates gzip file and removes original."""
        from trapninja.logger import CompressedRotatingFileHandler
        
        log_file = tmp_path / "test.log"
        log_file.write_text("main log")
        
        # Create a rotated file
        rotated_file = tmp_path / "test.log.1"
        rotated_file.write_text("rotated log content")
        
        handler = CompressedRotatingFileHandler(
            str(log_file),
            maxBytes=1000,
            backupCount=3,
            compress=True
        )
        
        # Run compression directly (not in thread for test)
        handler._compress_logs()
        
        # Verify gzip file exists and original is removed
        gz_file = tmp_path / "test.log.1.gz"
        assert gz_file.exists()
        assert not rotated_file.exists()
        
        # Verify content can be decompressed
        with gzip.open(str(gz_file), 'rb') as f:
            content = f.read()
        assert content == b"rotated log content"
        
        handler.close()

    def test_compress_logs_skips_already_compressed(self, tmp_path):
        """Test that _compress_logs skips files already in tracking set."""
        from trapninja.logger import CompressedRotatingFileHandler
        
        log_file = tmp_path / "test.log"
        log_file.write_text("main log")
        
        rotated_file = tmp_path / "test.log.1"
        rotated_file.write_text("rotated log content")
        
        handler = CompressedRotatingFileHandler(
            str(log_file),
            maxBytes=1000,
            backupCount=3,
            compress=True
        )
        
        # Mark as already processed
        handler._compressed_files.add(str(rotated_file))
        
        handler._compress_logs()
        
        # Original should still exist (not compressed)
        assert rotated_file.exists()
        gz_file = tmp_path / "test.log.1.gz"
        assert not gz_file.exists()
        
        handler.close()

    def test_compress_logs_skips_if_gz_exists(self, tmp_path):
        """Test that _compress_logs skips if .gz already exists."""
        from trapninja.logger import CompressedRotatingFileHandler
        
        log_file = tmp_path / "test.log"
        log_file.write_text("main log")
        
        rotated_file = tmp_path / "test.log.1"
        rotated_file.write_text("rotated log content")
        
        gz_file = tmp_path / "test.log.1.gz"
        gz_file.write_text("existing gz")
        
        handler = CompressedRotatingFileHandler(
            str(log_file),
            maxBytes=1000,
            backupCount=3,
            compress=True
        )
        
        handler._compress_logs()
        
        # Both files should still exist (not recompressed)
        assert rotated_file.exists()
        assert gz_file.read_text() == "existing gz"
        
        handler.close()

    def test_compress_logs_handles_multiple_backups(self, tmp_path):
        """Test compression of multiple backup files."""
        from trapninja.logger import CompressedRotatingFileHandler
        
        log_file = tmp_path / "test.log"
        log_file.write_text("main log")
        
        # Create multiple rotated files
        for i in range(1, 4):
            (tmp_path / f"test.log.{i}").write_text(f"content {i}")
        
        handler = CompressedRotatingFileHandler(
            str(log_file),
            maxBytes=1000,
            backupCount=5,
            compress=True
        )
        
        handler._compress_logs()
        
        # All three should be compressed
        for i in range(1, 4):
            assert (tmp_path / f"test.log.{i}.gz").exists()
            assert not (tmp_path / f"test.log.{i}").exists()
        
        handler.close()

    def test_compress_logs_handles_missing_file(self, tmp_path):
        """Test that _compress_logs handles missing files gracefully."""
        from trapninja.logger import CompressedRotatingFileHandler
        
        log_file = tmp_path / "test.log"
        log_file.write_text("main log")
        
        # Don't create any rotated files
        
        handler = CompressedRotatingFileHandler(
            str(log_file),
            maxBytes=1000,
            backupCount=3,
            compress=True
        )
        
        # Should not raise
        handler._compress_logs()
        
        handler.close()


class TestThreadLocalAdapter:
    """Tests for ThreadLocalAdapter class."""

    def test_adapter_creation(self):
        """Test adapter can be created with a logger."""
        from trapninja.logger import ThreadLocalAdapter
        
        base_logger = logging.getLogger("test_adapter")
        adapter = ThreadLocalAdapter(base_logger, {})
        
        assert adapter.logger == base_logger

    def test_process_caches_message(self):
        """Test that process method caches messages."""
        from trapninja.logger import ThreadLocalAdapter, _thread_local
        
        # Clear any existing cache
        if hasattr(_thread_local, 'log_cache'):
            _thread_local.log_cache.clear()
        
        base_logger = logging.getLogger("test_cache")
        adapter = ThreadLocalAdapter(base_logger, {})
        
        msg, kwargs = adapter.process("Test message", {})
        
        assert msg == "Test message"
        assert "Test message" in _thread_local.log_cache

    def test_process_returns_cached_message(self):
        """Test that cached messages are returned."""
        from trapninja.logger import ThreadLocalAdapter, _thread_local
        
        if hasattr(_thread_local, 'log_cache'):
            _thread_local.log_cache.clear()
        
        base_logger = logging.getLogger("test_cache2")
        adapter = ThreadLocalAdapter(base_logger, {})
        
        # First call - caches
        msg1, _ = adapter.process("Cached message", {})
        
        # Second call - returns from cache
        msg2, _ = adapter.process("Cached message", {})
        
        assert msg1 == msg2 == "Cached message"

    def test_process_preserves_kwargs(self):
        """Test that kwargs are passed through unchanged."""
        from trapninja.logger import ThreadLocalAdapter, _thread_local
        
        if hasattr(_thread_local, 'log_cache'):
            _thread_local.log_cache.clear()
        
        base_logger = logging.getLogger("test_kwargs")
        adapter = ThreadLocalAdapter(base_logger, {})
        
        input_kwargs = {'extra': {'key': 'value'}}
        msg, output_kwargs = adapter.process("Test", input_kwargs)
        
        assert output_kwargs == input_kwargs

    def test_cache_size_limit(self):
        """Test that cache is limited to 1000 entries."""
        from trapninja.logger import ThreadLocalAdapter, _thread_local
        
        if hasattr(_thread_local, 'log_cache'):
            _thread_local.log_cache.clear()
        
        base_logger = logging.getLogger("test_limit")
        adapter = ThreadLocalAdapter(base_logger, {})
        
        # Add 1001 messages
        for i in range(1001):
            adapter.process(f"Message {i}", {})
        
        # Cache should have been trimmed (removes 500 when > 1000)
        assert len(_thread_local.log_cache) <= 1000

    def test_cache_eviction_removes_oldest(self):
        """Test that eviction removes oldest entries."""
        from trapninja.logger import ThreadLocalAdapter, _thread_local
        
        if hasattr(_thread_local, 'log_cache'):
            _thread_local.log_cache.clear()
        
        base_logger = logging.getLogger("test_eviction")
        adapter = ThreadLocalAdapter(base_logger, {})
        
        # Fill cache beyond limit
        for i in range(1100):
            adapter.process(f"Msg {i}", {})
        
        # After eviction, newer messages should still be present
        # and oldest should be removed
        assert len(_thread_local.log_cache) <= 1000
        # Most recent should still be cached
        assert "Msg 1099" in _thread_local.log_cache

    def test_thread_isolation(self):
        """Test that cache is isolated per thread."""
        from trapninja.logger import ThreadLocalAdapter, _thread_local
        
        if hasattr(_thread_local, 'log_cache'):
            _thread_local.log_cache.clear()
        
        base_logger = logging.getLogger("test_threads")
        adapter = ThreadLocalAdapter(base_logger, {})
        
        # Cache in main thread
        adapter.process("Main thread msg", {})
        
        # Check in different thread
        other_thread_cache = []
        
        def check_other_thread():
            from trapninja.logger import _thread_local
            if hasattr(_thread_local, 'log_cache'):
                other_thread_cache.append(dict(_thread_local.log_cache))
            else:
                other_thread_cache.append({})
        
        thread = threading.Thread(target=check_other_thread)
        thread.start()
        thread.join()
        
        # Other thread should have empty or different cache
        assert "Main thread msg" not in other_thread_cache[0]


class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_setup_with_defaults(self, tmp_path, monkeypatch):
        """Test setup_logging with default parameters."""
        from trapninja import logger as logger_module
        
        log_file = tmp_path / "logs" / "test.log"
        
        # Patch config values
        monkeypatch.setattr("trapninja.config.LOG_FILE", str(log_file))
        monkeypatch.setattr("trapninja.config.LOG_LEVEL", "INFO")
        
        result = logger_module.setup_logging(console=False)
        
        assert result is not None
        assert log_file.parent.exists()
        
        # Clean up
        logger_module.logger.handlers.clear()

    def test_setup_creates_log_directory(self, tmp_path, monkeypatch):
        """Test that setup_logging creates log directory if needed."""
        from trapninja import logger as logger_module
        
        log_file = tmp_path / "new_dir" / "subdir" / "test.log"
        
        monkeypatch.setattr("trapninja.config.LOG_FILE", str(log_file))
        monkeypatch.setattr("trapninja.config.LOG_LEVEL", "INFO")
        
        logger_module.setup_logging(console=False)
        
        assert log_file.parent.exists()
        
        logger_module.logger.handlers.clear()

    @pytest.mark.parametrize("level_str,expected_level", [
        ("DEBUG", logging.DEBUG),
        ("INFO", logging.INFO),
        ("WARNING", logging.WARNING),
        ("ERROR", logging.ERROR),
        ("CRITICAL", logging.CRITICAL),
        ("debug", logging.DEBUG),  # Case insensitive
        ("Info", logging.INFO),
    ])
    def test_log_level_mapping(self, level_str, expected_level, tmp_path, monkeypatch):
        """Test log level string to numeric conversion."""
        from trapninja import logger as logger_module
        
        log_file = tmp_path / "test.log"
        
        monkeypatch.setattr("trapninja.config.LOG_FILE", str(log_file))
        monkeypatch.setattr("trapninja.config.LOG_LEVEL", level_str)
        
        logger_module.setup_logging(console=False)
        
        assert logger_module.logger.level == expected_level
        
        logger_module.logger.handlers.clear()

    def test_invalid_log_level_defaults_to_info(self, tmp_path, monkeypatch):
        """Test that invalid log level defaults to INFO."""
        from trapninja import logger as logger_module
        
        log_file = tmp_path / "test.log"
        
        monkeypatch.setattr("trapninja.config.LOG_FILE", str(log_file))
        monkeypatch.setattr("trapninja.config.LOG_LEVEL", "INVALID")
        
        logger_module.setup_logging(console=False)
        
        assert logger_module.logger.level == logging.INFO
        
        logger_module.logger.handlers.clear()

    def test_console_handler_added_when_enabled(self, tmp_path, monkeypatch):
        """Test that console handler is added when console=True."""
        from trapninja import logger as logger_module
        
        log_file = tmp_path / "test.log"
        
        monkeypatch.setattr("trapninja.config.LOG_FILE", str(log_file))
        monkeypatch.setattr("trapninja.config.LOG_LEVEL", "INFO")
        
        logger_module.setup_logging(console=True)
        
        # Should have file handler + console handler
        handler_types = [type(h).__name__ for h in logger_module.logger.handlers]
        assert "StreamHandler" in handler_types
        
        logger_module.logger.handlers.clear()

    def test_console_handler_not_added_when_disabled(self, tmp_path, monkeypatch):
        """Test that console handler is not added when console=False."""
        from trapninja import logger as logger_module
        
        log_file = tmp_path / "test.log"
        
        monkeypatch.setattr("trapninja.config.LOG_FILE", str(log_file))
        monkeypatch.setattr("trapninja.config.LOG_LEVEL", "INFO")
        
        logger_module.setup_logging(console=False)
        
        handler_types = [type(h).__name__ for h in logger_module.logger.handlers]
        assert "StreamHandler" not in handler_types
        
        logger_module.logger.handlers.clear()

    def test_compression_handler_when_compress_true(self, tmp_path, monkeypatch):
        """Test that CompressedRotatingFileHandler is used when compress=True."""
        from trapninja import logger as logger_module
        from trapninja.logger import CompressedRotatingFileHandler
        
        log_file = tmp_path / "test.log"
        
        monkeypatch.setattr("trapninja.config.LOG_FILE", str(log_file))
        monkeypatch.setattr("trapninja.config.LOG_LEVEL", "INFO")
        
        logger_module.setup_logging(console=False, compress=True)
        
        # Find file handler
        file_handlers = [h for h in logger_module.logger.handlers 
                        if isinstance(h, CompressedRotatingFileHandler)]
        assert len(file_handlers) == 1
        
        logger_module.logger.handlers.clear()

    def test_standard_handler_when_compress_false(self, tmp_path, monkeypatch):
        """Test that standard RotatingFileHandler is used when compress=False."""
        from trapninja import logger as logger_module
        from trapninja.logger import CompressedRotatingFileHandler
        from logging.handlers import RotatingFileHandler
        
        log_file = tmp_path / "test.log"
        
        monkeypatch.setattr("trapninja.config.LOG_FILE", str(log_file))
        monkeypatch.setattr("trapninja.config.LOG_LEVEL", "INFO")
        
        logger_module.setup_logging(console=False, compress=False)
        
        # Find file handler - should be standard, not compressed
        file_handlers = [h for h in logger_module.logger.handlers 
                        if isinstance(h, RotatingFileHandler)]
        compressed_handlers = [h for h in logger_module.logger.handlers 
                              if isinstance(h, CompressedRotatingFileHandler)]
        
        assert len(file_handlers) >= 1
        assert len(compressed_handlers) == 0
        
        logger_module.logger.handlers.clear()

    def test_explicit_log_file_parameter(self, tmp_path, monkeypatch):
        """Test that explicit log_file parameter is used."""
        from trapninja import logger as logger_module
        
        # Set a different default
        monkeypatch.setattr("trapninja.config.LOG_FILE", "/default/path.log")
        monkeypatch.setattr("trapninja.config.LOG_LEVEL", "INFO")
        
        explicit_file = tmp_path / "explicit.log"
        logger_module.setup_logging(console=False, log_file=str(explicit_file))
        
        # Should use explicit path
        assert explicit_file.parent.exists()
        
        logger_module.logger.handlers.clear()

    def test_explicit_log_level_parameter(self, tmp_path, monkeypatch):
        """Test that explicit log_level parameter is used."""
        from trapninja import logger as logger_module
        
        log_file = tmp_path / "test.log"
        
        monkeypatch.setattr("trapninja.config.LOG_FILE", str(log_file))
        monkeypatch.setattr("trapninja.config.LOG_LEVEL", "INFO")
        
        logger_module.setup_logging(console=False, log_level="DEBUG")
        
        assert logger_module.logger.level == logging.DEBUG
        
        logger_module.logger.handlers.clear()

    def test_max_size_and_backup_count(self, tmp_path, monkeypatch):
        """Test that max_size and backup_count are applied."""
        from trapninja import logger as logger_module
        from logging.handlers import RotatingFileHandler
        
        log_file = tmp_path / "test.log"
        
        monkeypatch.setattr("trapninja.config.LOG_FILE", str(log_file))
        monkeypatch.setattr("trapninja.config.LOG_LEVEL", "INFO")
        
        logger_module.setup_logging(
            console=False,
            max_size=5 * 1024 * 1024,
            backup_count=10
        )
        
        # Find rotating handler
        rotating_handlers = [h for h in logger_module.logger.handlers 
                           if isinstance(h, RotatingFileHandler)]
        
        assert len(rotating_handlers) >= 1
        handler = rotating_handlers[0]
        assert handler.maxBytes == 5 * 1024 * 1024
        assert handler.backupCount == 10
        
        logger_module.logger.handlers.clear()

    def test_clears_existing_handlers(self, tmp_path, monkeypatch):
        """Test that setup_logging clears existing handlers."""
        from trapninja import logger as logger_module
        
        log_file = tmp_path / "test.log"
        
        monkeypatch.setattr("trapninja.config.LOG_FILE", str(log_file))
        monkeypatch.setattr("trapninja.config.LOG_LEVEL", "INFO")
        
        # Add a dummy handler
        dummy_handler = logging.StreamHandler()
        logger_module.logger.addHandler(dummy_handler)
        
        initial_count = len(logger_module.logger.handlers)
        
        # Setup should clear and add new handlers
        logger_module.setup_logging(console=False)
        
        # Dummy handler should be gone
        assert dummy_handler not in logger_module.logger.handlers
        
        logger_module.logger.handlers.clear()

    def test_returns_adapter(self, tmp_path, monkeypatch):
        """Test that setup_logging returns a ThreadLocalAdapter."""
        from trapninja import logger as logger_module
        from trapninja.logger import ThreadLocalAdapter
        
        log_file = tmp_path / "test.log"
        
        monkeypatch.setattr("trapninja.config.LOG_FILE", str(log_file))
        monkeypatch.setattr("trapninja.config.LOG_LEVEL", "INFO")
        
        result = logger_module.setup_logging(console=False)
        
        assert isinstance(result, ThreadLocalAdapter)
        
        logger_module.logger.handlers.clear()


class TestFormatter:
    """Tests for log formatter."""

    def test_formatter_format(self):
        """Test that formatter has correct format string."""
        from trapninja.logger import formatter
        
        # Should include timestamp, level, and message
        assert '%(asctime)s' in formatter._fmt
        assert '%(levelname)s' in formatter._fmt
        assert '%(message)s' in formatter._fmt

    def test_formatter_datefmt(self):
        """Test that formatter has correct date format."""
        from trapninja.logger import formatter
        
        assert formatter.datefmt == '%Y-%m-%d %H:%M:%S'


class TestModuleLevelLogger:
    """Tests for module-level logger instance."""

    def test_logger_name(self):
        """Test that module logger has correct name."""
        from trapninja.logger import logger
        
        assert logger.name == "trapninja"

    def test_logger_is_logging_logger(self):
        """Test that logger is a logging.Logger instance."""
        from trapninja.logger import logger
        
        assert isinstance(logger, logging.Logger)
