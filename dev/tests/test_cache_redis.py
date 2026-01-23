#!/usr/bin/env python3
"""
TrapNinja Test Suite - Cache Redis Backend Tests

Tests for trapninja.cache.redis_backend module - Redis-based trap caching.

Author: TrapNinja Team
"""

import time
import threading
import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from datetime import datetime, timedelta


class TestCacheConfig:
    """Tests for CacheConfig class."""

    def test_default_values(self):
        """Test CacheConfig default values."""
        from trapninja.cache.redis_backend import CacheConfig
        
        config = CacheConfig()
        
        assert config.enabled is False
        assert config.host == "localhost"
        assert config.port == 6379
        assert config.db == 0
        assert config.retention_hours == 2.0
        assert config.trim_interval_seconds == 60
        assert config.key_prefix == "trapninja:buffer"

    def test_custom_values(self):
        """Test CacheConfig with custom values."""
        from trapninja.cache.redis_backend import CacheConfig
        
        config = CacheConfig(
            enabled=True,
            host="redis.example.com",
            port=6380,
            password="secret",
            retention_hours=4.0
        )
        
        assert config.enabled is True
        assert config.host == "redis.example.com"
        assert config.port == 6380
        assert config.password == "secret"
        assert config.retention_hours == 4.0

    def test_from_dict(self):
        """Test creating config from dictionary."""
        from trapninja.cache.redis_backend import CacheConfig
        
        data = {
            'enabled': True,
            'host': 'redis.local',
            'port': 6381,
            'retention_hours': 6.0
        }
        
        config = CacheConfig.from_dict(data)
        
        assert config.enabled is True
        assert config.host == 'redis.local'
        assert config.port == 6381
        assert config.retention_hours == 6.0

    def test_from_dict_with_defaults(self):
        """Test from_dict uses defaults for missing keys."""
        from trapninja.cache.redis_backend import CacheConfig
        
        config = CacheConfig.from_dict({})
        
        assert config.enabled is False
        assert config.host == "localhost"

    def test_to_dict(self):
        """Test converting config to dictionary."""
        from trapninja.cache.redis_backend import CacheConfig
        
        config = CacheConfig(enabled=True, host="test.local")
        result = config.to_dict()
        
        assert result['enabled'] is True
        assert result['host'] == "test.local"
        assert 'port' in result
        assert 'retention_hours' in result

    def test_roundtrip(self):
        """Test from_dict(to_dict()) produces equivalent config."""
        from trapninja.cache.redis_backend import CacheConfig
        
        original = CacheConfig(
            enabled=True,
            host="redis.test",
            port=6382,
            password="pass123",
            retention_hours=3.5
        )
        
        data = original.to_dict()
        restored = CacheConfig.from_dict(data)
        
        assert restored.enabled == original.enabled
        assert restored.host == original.host
        assert restored.port == original.port
        assert restored.password == original.password
        assert restored.retention_hours == original.retention_hours


class TestCacheStats:
    """Tests for CacheStats class."""

    def test_default_values(self):
        """Test CacheStats default values."""
        from trapninja.cache.redis_backend import CacheStats
        
        stats = CacheStats()
        
        assert stats.entries_stored == 0
        assert stats.entries_trimmed == 0
        assert stats.store_failures == 0
        assert stats.connection_failures == 0

    def test_to_dict(self):
        """Test converting stats to dictionary."""
        from trapninja.cache.redis_backend import CacheStats
        
        stats = CacheStats(
            entries_stored=100,
            entries_trimmed=50,
            store_failures=5
        )
        
        result = stats.to_dict()
        
        assert result['entries_stored'] == 100
        assert result['entries_trimmed'] == 50
        assert result['store_failures'] == 5


class TestTrapCacheInitialization:
    """Tests for TrapCache initialization."""

    def test_initialization(self):
        """Test TrapCache initialization."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        
        assert cache.config == config
        assert cache._connected is False
        assert cache.available is False

    def test_stream_key_generation(self):
        """Test stream key generation."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        config = CacheConfig(key_prefix="test:prefix")
        cache = TrapCache(config)
        
        key = cache._stream_key("voice_noc")
        
        assert key == "test:prefix:voice_noc"


class TestTrapCacheConnection:
    """Tests for TrapCache connection handling."""

    def test_connect_when_disabled(self):
        """Test connect returns False when cache disabled."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        config = CacheConfig(enabled=False)
        cache = TrapCache(config)
        
        result = cache.connect()
        
        assert result is False

    @patch('trapninja.cache.redis_backend.REDIS_AVAILABLE', False)
    def test_connect_without_redis_package(self):
        """Test connect returns False when Redis not installed."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        
        result = cache.connect()
        
        assert result is False

    @patch('trapninja.cache.redis_backend.REDIS_AVAILABLE', True)
    @patch('trapninja.cache.redis_backend.redis')
    def test_connect_success(self, mock_redis):
        """Test successful connection."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        mock_client = MagicMock()
        mock_redis.Redis.return_value = mock_client
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        
        result = cache.connect()
        
        assert result is True
        assert cache.available is True
        mock_client.ping.assert_called_once()

    @patch('trapninja.cache.redis_backend.REDIS_AVAILABLE', True)
    @patch('trapninja.cache.redis_backend.redis')
    def test_connect_failure(self, mock_redis):
        """Test connection failure."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        mock_client = MagicMock()
        mock_client.ping.side_effect = Exception("Connection refused")
        mock_redis.Redis.return_value = mock_client
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        
        result = cache.connect()
        
        assert result is False
        assert cache.available is False
        assert cache._stats.connection_failures == 1


class TestTrapCacheStore:
    """Tests for TrapCache store operations."""

    def test_store_when_not_connected(self):
        """Test store returns None when not connected."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        
        result = cache.store("dest", {"pdu_base64": "test"})
        
        assert result is None

    @patch('trapninja.cache.redis_backend.REDIS_AVAILABLE', True)
    @patch('trapninja.cache.redis_backend.redis')
    def test_store_success(self, mock_redis):
        """Test successful store operation."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        mock_client = MagicMock()
        mock_client.xadd.return_value = "1234567890-0"
        mock_redis.Redis.return_value = mock_client
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        cache.connect()
        
        trap_data = {
            'timestamp': '2024-01-01T00:00:00',
            'source_ip': '10.0.0.1',
            'trap_oid': '1.3.6.1.4.1.9.1',
            'pdu_base64': 'dGVzdA=='
        }
        
        result = cache.store("voice_noc", trap_data)
        
        assert result == "1234567890-0"
        assert cache._stats.entries_stored == 1
        mock_client.xadd.assert_called_once()

    @patch('trapninja.cache.redis_backend.REDIS_AVAILABLE', True)
    @patch('trapninja.cache.redis_backend.redis')
    def test_store_failure(self, mock_redis):
        """Test store failure handling."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        mock_client = MagicMock()
        mock_client.xadd.side_effect = Exception("Write failed")
        mock_redis.Redis.return_value = mock_client
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        cache.connect()
        
        result = cache.store("dest", {"pdu_base64": "test"})
        
        assert result is None
        assert cache._stats.store_failures == 1


class TestTrapCacheQuery:
    """Tests for TrapCache query operations."""

    @patch('trapninja.cache.redis_backend.REDIS_AVAILABLE', True)
    @patch('trapninja.cache.redis_backend.redis')
    def test_query_range(self, mock_redis):
        """Test query_range returns entries."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        mock_client = MagicMock()
        mock_client.xrange.return_value = [
            ("1234567890-0", {'ts': '2024-01-01T00:00:00', 'src': '10.0.0.1', 'oid': '1.3.6.1', 'pdu': 'dGVzdA=='}),
            ("1234567891-0", {'ts': '2024-01-01T00:00:01', 'src': '10.0.0.2', 'oid': '1.3.6.2', 'pdu': 'dGVzdDI='}),
        ]
        mock_redis.Redis.return_value = mock_client
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        cache.connect()
        
        start = datetime(2024, 1, 1, 0, 0, 0)
        end = datetime(2024, 1, 1, 0, 1, 0)
        
        entries = list(cache.query_range("dest", start, end))
        
        assert len(entries) == 2
        assert entries[0]['source_ip'] == '10.0.0.1'
        assert entries[1]['source_ip'] == '10.0.0.2'

    @patch('trapninja.cache.redis_backend.REDIS_AVAILABLE', True)
    @patch('trapninja.cache.redis_backend.redis')
    def test_count_range(self, mock_redis):
        """Test count_range returns count."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        mock_client = MagicMock()
        # First call returns entries, second call returns empty (to break the loop)
        mock_client.xrange.side_effect = [
            [("1704067200000-0", {}), ("1704067200001-0", {}), ("1704067200002-0", {})],
            []  # Empty list to break the while loop
        ]
        mock_redis.Redis.return_value = mock_client
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        cache.connect()
        
        start = datetime(2024, 1, 1)
        end = datetime(2024, 1, 2)
        
        count = cache.count_range("dest", start, end)
        
        assert count == 3


class TestTrapCacheDestinations:
    """Tests for TrapCache destination management."""

    @patch('trapninja.cache.redis_backend.REDIS_AVAILABLE', True)
    @patch('trapninja.cache.redis_backend.redis')
    def test_get_destinations(self, mock_redis):
        """Test get_destinations returns list."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        mock_client = MagicMock()
        mock_client.keys.return_value = [
            "trapninja:buffer:voice_noc",
            "trapninja:buffer:data_noc"
        ]
        mock_redis.Redis.return_value = mock_client
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        cache.connect()
        
        destinations = cache.get_destinations()
        
        assert "voice_noc" in destinations
        assert "data_noc" in destinations

    @patch('trapninja.cache.redis_backend.REDIS_AVAILABLE', True)
    @patch('trapninja.cache.redis_backend.redis')
    def test_get_stream_info(self, mock_redis):
        """Test get_stream_info returns info dict."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        mock_client = MagicMock()
        mock_client.xlen.return_value = 100
        mock_client.xrange.return_value = [("1-0", {'ts': '2024-01-01T00:00:00'})]
        mock_client.xrevrange.return_value = [("100-0", {'ts': '2024-01-01T01:00:00'})]
        mock_client.memory_usage.return_value = 10240
        mock_redis.Redis.return_value = mock_client
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        cache.connect()
        
        info = cache.get_stream_info("voice_noc")
        
        assert info is not None
        assert info['length'] == 100
        assert info['memory_bytes'] == 10240


class TestTrapCacheTrim:
    """Tests for TrapCache retention trimming."""

    @patch('trapninja.cache.redis_backend.REDIS_AVAILABLE', True)
    @patch('trapninja.cache.redis_backend.redis')
    def test_trim_old_entries(self, mock_redis):
        """Test trim_old_entries removes old data."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        mock_client = MagicMock()
        mock_client.keys.return_value = ["trapninja:buffer:dest1"]
        mock_client.xlen.side_effect = [100, 80]  # Before and after
        mock_redis.Redis.return_value = mock_client
        
        config = CacheConfig(enabled=True, retention_hours=2.0)
        cache = TrapCache(config)
        cache.connect()
        
        results = cache.trim_old_entries()
        
        assert 'dest1' in results
        assert cache._stats.entries_trimmed >= 0

    @patch('trapninja.cache.redis_backend.REDIS_AVAILABLE', True)
    @patch('trapninja.cache.redis_backend.redis')
    def test_clear_destination(self, mock_redis):
        """Test clear_destination removes all entries."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        mock_client = MagicMock()
        mock_redis.Redis.return_value = mock_client
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        cache.connect()
        
        result = cache.clear_destination("voice_noc")
        
        assert result is True
        mock_client.delete.assert_called_once()

    @patch('trapninja.cache.redis_backend.REDIS_AVAILABLE', True)
    @patch('trapninja.cache.redis_backend.redis')
    def test_clear_all(self, mock_redis):
        """Test clear_all removes all destinations."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        mock_client = MagicMock()
        mock_client.keys.return_value = ["trapninja:buffer:d1", "trapninja:buffer:d2"]
        mock_redis.Redis.return_value = mock_client
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        cache.connect()
        
        result = cache.clear_all()
        
        assert result is True
        assert mock_client.delete.call_count == 2


class TestTrapCacheStats:
    """Tests for TrapCache statistics."""

    @patch('trapninja.cache.redis_backend.REDIS_AVAILABLE', True)
    @patch('trapninja.cache.redis_backend.redis')
    def test_get_stats(self, mock_redis):
        """Test get_stats returns comprehensive stats."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        mock_client = MagicMock()
        mock_client.keys.return_value = []
        mock_redis.Redis.return_value = mock_client
        
        config = CacheConfig(enabled=True, host="test.redis")
        cache = TrapCache(config)
        cache.connect()
        
        stats = cache.get_stats()
        
        assert stats['available'] is True
        assert 'config' in stats
        assert stats['config']['host'] == "test.redis"
        assert 'operations' in stats
        assert 'destinations' in stats


class TestTrapCacheShutdown:
    """Tests for TrapCache shutdown."""

    @patch('trapninja.cache.redis_backend.REDIS_AVAILABLE', True)
    @patch('trapninja.cache.redis_backend.redis')
    def test_shutdown(self, mock_redis):
        """Test shutdown closes connection."""
        from trapninja.cache.redis_backend import TrapCache, CacheConfig
        
        mock_client = MagicMock()
        mock_redis.Redis.return_value = mock_client
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        cache.connect()
        
        cache.shutdown()
        
        assert cache._connected is False
        mock_client.close.assert_called_once()


class TestRetentionManager:
    """Tests for RetentionManager class."""

    def test_initialization(self):
        """Test RetentionManager initialization."""
        from trapninja.cache.redis_backend import RetentionManager, TrapCache, CacheConfig
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        
        manager = RetentionManager(cache, interval=120)
        
        assert manager.cache == cache
        assert manager.interval == 120

    def test_set_config_file(self, tmp_path):
        """Test set_config_file sets path."""
        from trapninja.cache.redis_backend import RetentionManager, TrapCache, CacheConfig
        import json
        
        config_file = tmp_path / "cache_config.json"
        config_file.write_text(json.dumps({'retention_hours': 3.0}))
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        manager = RetentionManager(cache)
        
        manager.set_config_file(str(config_file))
        
        assert manager._config_file == str(config_file)

    def test_start_stop(self):
        """Test start and stop methods."""
        from trapninja.cache.redis_backend import RetentionManager, TrapCache, CacheConfig
        
        config = CacheConfig(enabled=True)
        cache = TrapCache(config)
        manager = RetentionManager(cache, interval=3600)  # Long interval
        
        manager.start()
        assert manager._thread is not None
        assert manager._thread.is_alive()
        
        manager.stop()
        assert manager._stop_event.is_set()


class TestGlobalCacheManagement:
    """Tests for global cache instance management."""

    def test_get_cache_returns_none_before_init(self):
        """Test get_cache returns None before initialization."""
        from trapninja.cache import redis_backend
        
        # Save original
        original = redis_backend._cache_instance
        redis_backend._cache_instance = None
        
        try:
            result = redis_backend.get_cache()
            assert result is None
        finally:
            redis_backend._cache_instance = original

    @patch('trapninja.cache.redis_backend.REDIS_AVAILABLE', True)
    @patch('trapninja.cache.redis_backend.redis')
    def test_initialize_cache(self, mock_redis):
        """Test initialize_cache creates and connects cache."""
        from trapninja.cache.redis_backend import (
            initialize_cache, shutdown_cache, CacheConfig
        )
        
        mock_client = MagicMock()
        mock_redis.Redis.return_value = mock_client
        
        config = CacheConfig(enabled=True)
        
        try:
            cache = initialize_cache(config)
            assert cache is not None
        finally:
            shutdown_cache()

    def test_initialize_cache_when_disabled(self):
        """Test initialize_cache returns None when disabled."""
        from trapninja.cache.redis_backend import (
            initialize_cache, shutdown_cache, CacheConfig
        )
        
        config = CacheConfig(enabled=False)
        
        try:
            result = initialize_cache(config)
            assert result is None
        finally:
            shutdown_cache()
