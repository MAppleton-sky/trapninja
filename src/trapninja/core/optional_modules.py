#!/usr/bin/env python3
"""
TrapNinja Optional Modules Registry

Provides lazy-loading and fallback handling for optional modules.
Eliminates boilerplate try/except import blocks throughout the codebase.

Usage:
    from trapninja.core.optional_modules import modules
    
    # Check availability
    if modules.cache.available:
        cache = modules.cache.get_cache()
    
    # Or just use with automatic fallback
    cache = modules.cache.get_cache()  # Returns None if unavailable
    
    # Initialize a module
    modules.cache.initialize(config)
    
    # Shutdown
    modules.cache.shutdown()

Author: TrapNinja Team
"""

import logging
import threading
from typing import Any, Callable, Dict, Optional, TypeVar, Generic

logger = logging.getLogger("trapninja")

T = TypeVar('T')


class OptionalModule(Generic[T]):
    """
    Wrapper for an optional module with lazy loading and fallback support.
    
    Thread-safe lazy loading ensures the module is only imported once,
    even under concurrent access.
    """
    
    def __init__(self, name: str, import_path: str):
        """
        Initialize optional module wrapper.
        
        Args:
            name: Human-readable module name for logging
            import_path: Full import path (e.g., 'trapninja.cache')
        """
        self.name = name
        self._import_path = import_path
        self._module: Optional[Any] = None
        self._available: Optional[bool] = None
        self._lock = threading.Lock()
        self._import_error: Optional[str] = None
    
    def _ensure_loaded(self) -> None:
        """Ensure the module is loaded (or marked unavailable)."""
        if self._available is not None:
            return
        
        with self._lock:
            # Double-check after acquiring lock
            if self._available is not None:
                return
            
            try:
                import importlib
                self._module = importlib.import_module(self._import_path)
                self._available = True
                logger.debug(f"Optional module '{self.name}' loaded successfully")
            except ImportError as e:
                self._module = None
                self._available = False
                self._import_error = str(e)
                logger.debug(f"Optional module '{self.name}' not available: {e}")
    
    @property
    def available(self) -> bool:
        """Check if the module is available."""
        self._ensure_loaded()
        return self._available
    
    @property
    def module(self) -> Optional[Any]:
        """Get the raw module object, or None if unavailable."""
        self._ensure_loaded()
        return self._module
    
    @property
    def import_error(self) -> Optional[str]:
        """Get the import error message if module failed to load."""
        self._ensure_loaded()
        return self._import_error
    
    def get_attr(self, name: str, default: Any = None) -> Any:
        """
        Get an attribute from the module with fallback.
        
        Args:
            name: Attribute name
            default: Default value if module unavailable or attr missing
            
        Returns:
            The attribute value or default
        """
        if not self.available:
            return default
        return getattr(self._module, name, default)
    
    def call(self, func_name: str, *args, default: Any = None, **kwargs) -> Any:
        """
        Call a function from the module with fallback.
        
        Args:
            func_name: Function name to call
            *args: Positional arguments
            default: Default return value if module unavailable
            **kwargs: Keyword arguments
            
        Returns:
            Function result or default
        """
        if not self.available:
            return default
        
        func = getattr(self._module, func_name, None)
        if func is None:
            return default
        
        return func(*args, **kwargs)


# =============================================================================
# CACHE MODULE
# =============================================================================

class CacheModule(OptionalModule):
    """Optional cache module with typed accessors."""
    
    def __init__(self):
        super().__init__('cache', 'trapninja.cache')
    
    def initialize(self, config: Any, config_file: str = None) -> Any:
        """Initialize the cache system."""
        return self.call('initialize_cache', config, config_file=config_file)
    
    def shutdown(self) -> None:
        """Shutdown the cache system."""
        self.call('shutdown_cache')
    
    def get_cache(self) -> Any:
        """Get the cache instance."""
        return self.call('get_cache')


# =============================================================================
# GRANULAR STATISTICS MODULE
# =============================================================================

class StatsModule(OptionalModule):
    """Optional granular statistics module with typed accessors."""
    
    def __init__(self):
        super().__init__('stats', 'trapninja.stats')
    
    def initialize(self, config: Any = None) -> Any:
        """Initialize the statistics collector."""
        return self.call('initialize_stats', config)
    
    def shutdown(self) -> None:
        """Shutdown the statistics collector."""
        self.call('shutdown_stats')
    
    def get_collector(self) -> Any:
        """Get the statistics collector instance."""
        return self.call('get_stats_collector')
    
    @property
    def CollectorConfig(self) -> type:
        """Get the CollectorConfig class."""
        if not self.available:
            # Return a dummy class
            return type('CollectorConfig', (), {})
        return self.get_attr('CollectorConfig', type('CollectorConfig', (), {}))


# =============================================================================
# SHADOW MODE MODULE
# =============================================================================

class ShadowModule(OptionalModule):
    """Optional shadow mode module with typed accessors."""
    
    def __init__(self):
        super().__init__('shadow', 'trapninja.shadow')
    
    def initialize(self, shadow_config: Any = None, capture_config: Any = None) -> bool:
        """Initialize shadow mode."""
        result = self.call('initialize_shadow_mode', 
                          shadow_config=shadow_config, 
                          capture_config=capture_config,
                          default=False)
        return result if result is not None else False
    
    def shutdown(self) -> None:
        """Shutdown shadow mode."""
        self.call('shutdown_shadow_mode')
    
    def is_shadow_mode(self) -> bool:
        """Check if running in shadow mode."""
        return self.call('is_shadow_mode', default=False) or False
    
    def is_observe_only(self) -> bool:
        """Check if in observe-only mode."""
        return self.call('is_observe_only', default=False) or False
    
    def should_use_sniff_mode(self) -> bool:
        """Check if sniff mode should be used."""
        return self.call('should_use_sniff_mode', default=False) or False
    
    def get_effective_capture_mode(self) -> str:
        """Get the effective capture mode."""
        return self.call('get_effective_capture_mode', default='auto') or 'auto'
    
    def get_summary(self) -> Dict[str, Any]:
        """Get shadow mode summary."""
        return self.call('get_shadow_summary', default={'enabled': False}) or {'enabled': False}
    
    def load_shadow_config(self) -> Any:
        """Load shadow configuration."""
        return self.call('load_shadow_config')
    
    def load_capture_config(self) -> Any:
        """Load capture configuration."""
        return self.call('load_capture_config')
    
    @property
    def ShadowConfig(self) -> type:
        """Get the ShadowConfig class."""
        if not self.available:
            return type('ShadowConfig', (), {})
        return self.get_attr('ShadowConfig', type('ShadowConfig', (), {}))
    
    @property
    def CaptureConfig(self) -> type:
        """Get the CaptureConfig class."""
        if not self.available:
            return type('CaptureConfig', (), {})
        return self.get_attr('CaptureConfig', type('CaptureConfig', (), {}))


# =============================================================================
# CONTROL SOCKET MODULE
# =============================================================================

class ControlModule(OptionalModule):
    """Optional control socket module with typed accessors."""
    
    def __init__(self):
        super().__init__('control', 'trapninja.control')
    
    def initialize(self) -> bool:
        """Initialize the control socket."""
        result = self.call('initialize_control_socket', default=False)
        return result if result is not None else False
    
    def shutdown(self) -> None:
        """Shutdown the control socket."""
        self.call('shutdown_control_socket')


# =============================================================================
# EBPF MODULE
# =============================================================================

class EbpfModule(OptionalModule):
    """Optional eBPF acceleration module with typed accessors."""
    
    def __init__(self):
        super().__init__('ebpf', 'trapninja.ebpf')
    
    def is_supported(self) -> bool:
        """Check if eBPF is supported on this system."""
        if not self.available:
            return False
        return self.call('is_ebpf_supported', default=False) or False
    
    def check_dependencies(self) -> Dict[str, Any]:
        """Check eBPF dependencies."""
        return self.call('check_ebpf_dependencies', default={}) or {}
    
    def create_capture(self, *args, **kwargs) -> Any:
        """Create an eBPF capture instance."""
        return self.call('create_capture', *args, **kwargs)


# =============================================================================
# FRAGMENTATION MODULE
# =============================================================================

class FragmentationModule(OptionalModule):
    """Optional IP fragmentation reassembly module with typed accessors."""
    
    def __init__(self):
        super().__init__('fragmentation', 'trapninja.core.fragmentation')
    
    def initialize(self, **kwargs) -> Any:
        """Initialize the fragment buffer."""
        return self.call('initialize_fragment_buffer', **kwargs)
    
    def shutdown(self) -> None:
        """Shutdown the fragment buffer."""
        self.call('shutdown_fragment_buffer')
    
    def get_buffer(self) -> Any:
        """Get the fragment buffer instance."""
        return self.call('get_fragment_buffer')
    
    def get_stats(self) -> Dict[str, Any]:
        """Get fragmentation statistics."""
        return self.call('get_fragment_stats', default={}) or {}
    
    def generate_fragment_aware_filter(
        self, 
        ports: list, 
        exclude_sport: int = None, 
        local_ip: str = None
    ) -> str:
        """
        Generate a BPF filter that handles fragmented packets.
        
        Falls back to simple filter if module unavailable.
        """
        if self.available:
            result = self.call(
                'generate_fragment_aware_filter',
                ports,
                exclude_sport=exclude_sport,
                local_ip=local_ip
            )
            if result:
                return result
        
        # Fallback implementation
        return self._generate_simple_filter(ports, exclude_sport, local_ip)
    
    def generate_simple_filter(
        self, 
        ports: list, 
        exclude_sport: int = None, 
        local_ip: str = None
    ) -> str:
        """Generate a simple BPF filter (no fragment handling)."""
        if self.available:
            result = self.call(
                'generate_simple_filter',
                ports,
                exclude_sport=exclude_sport,
                local_ip=local_ip
            )
            if result:
                return result
        
        return self._generate_simple_filter(ports, exclude_sport, local_ip)
    
    def _generate_simple_filter(
        self, 
        ports: list, 
        exclude_sport: int = None, 
        local_ip: str = None
    ) -> str:
        """Internal fallback filter generator."""
        port_filter = " or ".join([f"udp dst port {p}" for p in ports])
        if local_ip:
            port_filter = f"({port_filter} and dst host {local_ip})"
        if exclude_sport:
            return f"({port_filter}) and not (udp src port {exclude_sport})"
        return port_filter


# =============================================================================
# HA MODULE (for worker.py)
# =============================================================================

class HAModule(OptionalModule):
    """Optional HA module with typed accessors for worker use."""
    
    def __init__(self):
        super().__init__('ha', 'trapninja.ha')
        self._warning_count = 0
        self._max_warnings = 5
    
    def is_forwarding_enabled(self) -> bool:
        """
        Check if this node should forward traps.
        
        CRITICAL: Returns True if HA unavailable (fail-open for standalone mode).
        In HA mode, only the PRIMARY node returns True.
        """
        if not self.available:
            # Rate-limited warning
            self._warning_count += 1
            if self._warning_count <= self._max_warnings:
                logger.warning(
                    "HA module not available - forwarding enabled by default"
                )
            return True
        
        result = self.call('is_forwarding_enabled', default=True)
        return result if result is not None else True
    
    def notify_trap_processed(self) -> None:
        """Notify HA system that a trap was processed."""
        self.call('notify_trap_processed')


# =============================================================================
# MODULE REGISTRY
# =============================================================================

class ModuleRegistry:
    """
    Central registry for all optional modules.
    
    Provides a single access point for all optional module functionality.
    Modules are lazy-loaded on first access.
    
    Usage:
        from trapninja.core.optional_modules import modules
        
        if modules.cache.available:
            cache = modules.cache.get_cache()
    """
    
    def __init__(self):
        self._cache: Optional[CacheModule] = None
        self._stats: Optional[StatsModule] = None
        self._shadow: Optional[ShadowModule] = None
        self._control: Optional[ControlModule] = None
        self._ebpf: Optional[EbpfModule] = None
        self._fragmentation: Optional[FragmentationModule] = None
        self._ha: Optional[HAModule] = None
    
    @property
    def cache(self) -> CacheModule:
        """Access the cache module."""
        if self._cache is None:
            self._cache = CacheModule()
        return self._cache
    
    @property
    def stats(self) -> StatsModule:
        """Access the granular statistics module."""
        if self._stats is None:
            self._stats = StatsModule()
        return self._stats
    
    @property
    def shadow(self) -> ShadowModule:
        """Access the shadow mode module."""
        if self._shadow is None:
            self._shadow = ShadowModule()
        return self._shadow
    
    @property
    def control(self) -> ControlModule:
        """Access the control socket module."""
        if self._control is None:
            self._control = ControlModule()
        return self._control
    
    @property
    def ebpf(self) -> EbpfModule:
        """Access the eBPF module."""
        if self._ebpf is None:
            self._ebpf = EbpfModule()
        return self._ebpf
    
    @property
    def fragmentation(self) -> FragmentationModule:
        """Access the fragmentation module."""
        if self._fragmentation is None:
            self._fragmentation = FragmentationModule()
        return self._fragmentation
    
    @property
    def ha(self) -> HAModule:
        """Access the HA module."""
        if self._ha is None:
            self._ha = HAModule()
        return self._ha
    
    def get_status(self) -> Dict[str, Dict[str, Any]]:
        """
        Get availability status of all optional modules.
        
        Returns:
            Dict mapping module names to their status info
        """
        return {
            'cache': {
                'available': self.cache.available,
                'error': self.cache.import_error,
            },
            'stats': {
                'available': self.stats.available,
                'error': self.stats.import_error,
            },
            'shadow': {
                'available': self.shadow.available,
                'error': self.shadow.import_error,
            },
            'control': {
                'available': self.control.available,
                'error': self.control.import_error,
            },
            'ebpf': {
                'available': self.ebpf.available,
                'error': self.ebpf.import_error,
            },
            'fragmentation': {
                'available': self.fragmentation.available,
                'error': self.fragmentation.import_error,
            },
            'ha': {
                'available': self.ha.available,
                'error': self.ha.import_error,
            },
        }
    
    def shutdown_all(self) -> None:
        """Shutdown all initialized modules in reverse dependency order."""
        # Shutdown in reverse order of typical initialization
        if self._fragmentation and self._fragmentation.available:
            self._fragmentation.shutdown()
        
        if self._stats and self._stats.available:
            self._stats.shutdown()
        
        if self._cache and self._cache.available:
            self._cache.shutdown()
        
        if self._shadow and self._shadow.available:
            self._shadow.shutdown()
        
        if self._control and self._control.available:
            self._control.shutdown()
        
        # Note: ebpf and ha don't have shutdown methods in the same pattern


# Global module registry instance
modules = ModuleRegistry()


# =============================================================================
# CONVENIENCE FUNCTIONS (for backward compatibility during migration)
# =============================================================================

def is_module_available(name: str) -> bool:
    """
    Check if an optional module is available.
    
    Args:
        name: Module name ('cache', 'stats', 'shadow', 'control', 'ebpf', 'fragmentation', 'ha')
        
    Returns:
        True if module is available
    """
    return getattr(modules, name, None) is not None and getattr(modules, name).available


def get_module_status() -> Dict[str, bool]:
    """
    Get availability status of all optional modules.
    
    Returns:
        Dict mapping module names to availability boolean
    """
    return {name: info['available'] for name, info in modules.get_status().items()}
