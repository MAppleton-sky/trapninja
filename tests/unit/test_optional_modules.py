#!/usr/bin/env python3
"""
Tests for TrapNinja Optional Modules Registry

Verifies lazy loading, fallback handling, and module availability checking.
"""

import pytest
import threading
from unittest.mock import patch, MagicMock


class TestOptionalModule:
    """Test the OptionalModule base class."""
    
    def test_lazy_loading(self):
        """Module should not load until accessed."""
        from trapninja.core.optional_modules import OptionalModule
        
        # Create module wrapper
        mod = OptionalModule('test', 'trapninja.core.constants')
        
        # Should not have loaded yet
        assert mod._available is None
        assert mod._module is None
        
        # Access availability - should trigger load
        available = mod.available
        
        # Should now be loaded
        assert mod._available is not None
        assert available == True  # constants module should exist
    
    def test_unavailable_module(self):
        """Unavailable module should return False and None."""
        from trapninja.core.optional_modules import OptionalModule
        
        mod = OptionalModule('nonexistent', 'trapninja.nonexistent.module')
        
        assert mod.available == False
        assert mod.module is None
        assert mod.import_error is not None
    
    def test_get_attr_fallback(self):
        """get_attr should return default for unavailable modules."""
        from trapninja.core.optional_modules import OptionalModule
        
        mod = OptionalModule('nonexistent', 'trapninja.nonexistent.module')
        
        result = mod.get_attr('some_attr', default='fallback')
        assert result == 'fallback'
    
    def test_call_fallback(self):
        """call should return default for unavailable modules."""
        from trapninja.core.optional_modules import OptionalModule
        
        mod = OptionalModule('nonexistent', 'trapninja.nonexistent.module')
        
        result = mod.call('some_func', 'arg1', kwarg='value', default='fallback')
        assert result == 'fallback'
    
    def test_thread_safety(self):
        """Loading should be thread-safe."""
        from trapninja.core.optional_modules import OptionalModule
        
        mod = OptionalModule('test', 'trapninja.core.constants')
        
        results = []
        errors = []
        
        def check_available():
            try:
                results.append(mod.available)
            except Exception as e:
                errors.append(e)
        
        # Start multiple threads
        threads = [threading.Thread(target=check_available) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All should succeed
        assert len(errors) == 0
        assert len(results) == 10
        assert all(r == True for r in results)


class TestModuleRegistry:
    """Test the ModuleRegistry singleton."""
    
    def test_singleton_access(self):
        """modules should be accessible and consistent."""
        from trapninja.core.optional_modules import modules
        
        # Should be a ModuleRegistry instance
        assert modules is not None
        
        # Multiple imports should return same instance
        from trapninja.core.optional_modules import modules as modules2
        assert modules is modules2
    
    def test_all_modules_accessible(self):
        """All registered modules should be accessible."""
        from trapninja.core.optional_modules import modules
        
        # Access each module - should not raise
        _ = modules.cache
        _ = modules.stats
        _ = modules.shadow
        _ = modules.control
        _ = modules.ebpf
        _ = modules.fragmentation
        _ = modules.ha
    
    def test_get_status(self):
        """get_status should return dict with all modules."""
        from trapninja.core.optional_modules import modules
        
        status = modules.get_status()
        
        assert isinstance(status, dict)
        assert 'cache' in status
        assert 'stats' in status
        assert 'shadow' in status
        assert 'control' in status
        assert 'ebpf' in status
        assert 'fragmentation' in status
        assert 'ha' in status
        
        # Each entry should have available and error keys
        for name, info in status.items():
            assert 'available' in info
            assert 'error' in info


class TestCacheModule:
    """Test the CacheModule wrapper."""
    
    def test_initialize_when_unavailable(self):
        """initialize should return None when module unavailable."""
        from trapninja.core.optional_modules import CacheModule
        
        with patch.object(CacheModule, 'available', False):
            mod = CacheModule()
            mod._available = False  # Force unavailable
            
            result = mod.initialize({})
            assert result is None
    
    def test_get_cache_when_unavailable(self):
        """get_cache should return None when module unavailable."""
        from trapninja.core.optional_modules import CacheModule
        
        mod = CacheModule()
        mod._available = False
        
        result = mod.get_cache()
        assert result is None


class TestStatsModule:
    """Test the StatsModule wrapper."""
    
    def test_collector_config_fallback(self):
        """CollectorConfig should return dummy class when unavailable."""
        from trapninja.core.optional_modules import StatsModule
        
        mod = StatsModule()
        mod._available = False
        
        config_class = mod.CollectorConfig
        
        # Should be a type (class)
        assert isinstance(config_class, type)


class TestShadowModule:
    """Test the ShadowModule wrapper."""
    
    def test_boolean_methods_fallback(self):
        """Boolean methods should return False when unavailable."""
        from trapninja.core.optional_modules import ShadowModule
        
        mod = ShadowModule()
        mod._available = False
        
        assert mod.is_shadow_mode() == False
        assert mod.is_observe_only() == False
        assert mod.should_use_sniff_mode() == False
    
    def test_get_effective_capture_mode_fallback(self):
        """get_effective_capture_mode should return 'auto' when unavailable."""
        from trapninja.core.optional_modules import ShadowModule
        
        mod = ShadowModule()
        mod._available = False
        
        assert mod.get_effective_capture_mode() == 'auto'
    
    def test_config_classes_fallback(self):
        """Config classes should return dummy types when unavailable."""
        from trapninja.core.optional_modules import ShadowModule
        
        mod = ShadowModule()
        mod._available = False
        
        assert isinstance(mod.ShadowConfig, type)
        assert isinstance(mod.CaptureConfig, type)


class TestFragmentationModule:
    """Test the FragmentationModule wrapper."""
    
    def test_filter_generation_fallback(self):
        """Filter generation should work even when module unavailable."""
        from trapninja.core.optional_modules import FragmentationModule
        
        mod = FragmentationModule()
        mod._available = False
        
        # Should use fallback implementation
        result = mod.generate_simple_filter([162, 1162])
        
        assert 'udp dst port 162' in result
        assert 'udp dst port 1162' in result
    
    def test_filter_with_exclude_sport(self):
        """Filter should exclude source port when specified."""
        from trapninja.core.optional_modules import FragmentationModule
        
        mod = FragmentationModule()
        mod._available = False
        
        result = mod.generate_simple_filter([162], exclude_sport=61620)
        
        assert 'udp dst port 162' in result
        assert 'udp src port 61620' in result
        assert 'not' in result
    
    def test_filter_with_local_ip(self):
        """Filter should include destination IP when specified."""
        from trapninja.core.optional_modules import FragmentationModule
        
        mod = FragmentationModule()
        mod._available = False
        
        result = mod.generate_simple_filter([162], local_ip='192.168.1.1')
        
        assert 'udp dst port 162' in result
        assert 'dst host 192.168.1.1' in result


class TestHAModule:
    """Test the HAModule wrapper."""
    
    def test_is_forwarding_enabled_fallback(self):
        """is_forwarding_enabled should return True when HA unavailable."""
        from trapninja.core.optional_modules import HAModule
        
        mod = HAModule()
        mod._available = False
        
        # Should fail open (return True) for standalone mode
        assert mod.is_forwarding_enabled() == True
    
    def test_notify_trap_processed_noop(self):
        """notify_trap_processed should be no-op when unavailable."""
        from trapninja.core.optional_modules import HAModule
        
        mod = HAModule()
        mod._available = False
        
        # Should not raise
        mod.notify_trap_processed()


class TestConvenienceFunctions:
    """Test module-level convenience functions."""
    
    def test_is_module_available(self):
        """is_module_available should check module availability."""
        from trapninja.core.optional_modules import is_module_available
        
        # Test with known module
        result = is_module_available('fragmentation')
        assert isinstance(result, bool)
    
    def test_get_module_status(self):
        """get_module_status should return availability dict."""
        from trapninja.core.optional_modules import get_module_status
        
        status = get_module_status()
        
        assert isinstance(status, dict)
        for name, available in status.items():
            assert isinstance(available, bool)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
