# Optional Modules System - Implementation

## Overview

The optional modules system (`core/optional_modules.py`) eliminates boilerplate try/except import blocks throughout the TrapNinja codebase. It provides lazy loading with automatic fallbacks for optional modules.

## Problem Solved

Previously, each file that used optional modules had 20-50 lines of boilerplate like:

```python
# OLD PATTERN - repeated in service.py, worker.py, etc.
try:
    from .cache import initialize_cache, shutdown_cache, get_cache
    CACHE_MODULE_AVAILABLE = True
except ImportError:
    CACHE_MODULE_AVAILABLE = False
    def initialize_cache(config):
        return None
    def shutdown_cache():
        pass
    def get_cache():
        return None
```

This pattern was repeated for cache, stats, shadow, control, ebpf, fragmentation, and HA modules across multiple files, totaling 200+ lines of duplicated code.

## Solution

A centralized registry with typed module wrappers:

```python
# NEW PATTERN - single import, clean usage
from .core.optional_modules import modules

# Check availability
if modules.cache.available:
    cache = modules.cache.initialize(config)

# Or use with automatic fallback (returns None if unavailable)
cache = modules.cache.get_cache()

# Shutdown
modules.cache.shutdown()
```

## Files Changed

| File | Lines Removed | Lines Added | Net Change |
|------|---------------|-------------|------------|
| core/optional_modules.py | 0 | 450 | +450 (new file) |
| core/__init__.py | 0 | 10 | +10 |
| service.py | ~120 | ~20 | -100 |
| processing/worker.py | ~50 | ~10 | -40 |
| **Total** | ~170 | ~490 | +320 |

Note: While net lines increased, the new code is:
- Centralized (single point of change)
- Reusable (eliminates future boilerplate)
- Type-safe (IDE autocomplete works)
- Testable (each module wrapper can be unit tested)

## Module Registry

The `modules` singleton provides access to all optional modules:

| Module | Import Path | Usage |
|--------|-------------|-------|
| `modules.cache` | trapninja.cache | Redis cache for trap buffering |
| `modules.stats` | trapninja.stats | Granular statistics collector |
| `modules.shadow` | trapninja.shadow | Shadow/parallel capture mode |
| `modules.control` | trapninja.control | Control socket for CLI |
| `modules.ebpf` | trapninja.ebpf | eBPF acceleration |
| `modules.fragmentation` | trapninja.core.fragmentation | IP fragment reassembly |
| `modules.ha` | trapninja.ha | High availability functions |

## API Reference

### OptionalModule Base Class

All module wrappers inherit from `OptionalModule` which provides:

```python
class OptionalModule:
    @property
    def available(self) -> bool:
        """Check if module is available."""
    
    @property
    def module(self) -> Optional[Any]:
        """Get raw module object."""
    
    @property
    def import_error(self) -> Optional[str]:
        """Get import error message if failed."""
    
    def get_attr(self, name: str, default: Any = None) -> Any:
        """Get attribute with fallback."""
    
    def call(self, func_name: str, *args, default: Any = None, **kwargs) -> Any:
        """Call function with fallback."""
```

### Typed Module Wrappers

Each module has a typed wrapper with specific methods:

#### CacheModule
```python
modules.cache.initialize(config, config_file=None) -> Any
modules.cache.shutdown() -> None
modules.cache.get_cache() -> Any
```

#### StatsModule
```python
modules.stats.initialize(config=None) -> Any
modules.stats.shutdown() -> None
modules.stats.get_collector() -> Any
modules.stats.CollectorConfig  # Class reference
```

#### ShadowModule
```python
modules.shadow.initialize(shadow_config=None, capture_config=None) -> bool
modules.shadow.shutdown() -> None
modules.shadow.is_shadow_mode() -> bool
modules.shadow.is_observe_only() -> bool
modules.shadow.should_use_sniff_mode() -> bool
modules.shadow.get_effective_capture_mode() -> str
modules.shadow.get_summary() -> Dict
modules.shadow.load_shadow_config() -> Any
modules.shadow.load_capture_config() -> Any
modules.shadow.ShadowConfig  # Class reference
modules.shadow.CaptureConfig  # Class reference
```

#### ControlModule
```python
modules.control.initialize() -> bool
modules.control.shutdown() -> None
```

#### EbpfModule
```python
modules.ebpf.is_supported() -> bool
modules.ebpf.check_dependencies() -> Dict
modules.ebpf.create_capture(*args, **kwargs) -> Any
```

#### FragmentationModule
```python
modules.fragmentation.initialize(**kwargs) -> Any
modules.fragmentation.shutdown() -> None
modules.fragmentation.get_buffer() -> Any
modules.fragmentation.get_stats() -> Dict
modules.fragmentation.generate_fragment_aware_filter(ports, exclude_sport=None, local_ip=None) -> str
modules.fragmentation.generate_simple_filter(ports, exclude_sport=None, local_ip=None) -> str
```

#### HAModule
```python
modules.ha.is_forwarding_enabled() -> bool  # Returns True if unavailable (fail-open)
modules.ha.notify_trap_processed() -> None
```

### Utility Functions

```python
from trapninja.core.optional_modules import is_module_available, get_module_status

# Check single module
if is_module_available('cache'):
    ...

# Get all statuses
status = get_module_status()
# {'cache': True, 'stats': True, 'shadow': False, ...}
```

## Thread Safety

Module loading is thread-safe using double-checked locking:

```python
def _ensure_loaded(self) -> None:
    if self._available is not None:
        return  # Fast path
    
    with self._lock:
        if self._available is not None:
            return  # Double-check
        # Load module...
```

## Adding New Optional Modules

1. Create a new wrapper class:

```python
class NewModule(OptionalModule):
    def __init__(self):
        super().__init__('new_module', 'trapninja.new_module')
    
    def some_method(self) -> Any:
        return self.call('some_method', default=None)
```

2. Add to ModuleRegistry:

```python
class ModuleRegistry:
    def __init__(self):
        self._new_module: Optional[NewModule] = None
    
    @property
    def new_module(self) -> NewModule:
        if self._new_module is None:
            self._new_module = NewModule()
        return self._new_module
```

3. Update `get_status()` and `shutdown_all()` if needed.

## Migration Guide

### Before (old pattern)
```python
try:
    from .cache import initialize_cache, get_cache
    CACHE_MODULE_AVAILABLE = True
except ImportError:
    CACHE_MODULE_AVAILABLE = False
    def initialize_cache(config):
        return None
    def get_cache():
        return None

# Usage
if CACHE_MODULE_AVAILABLE:
    cache = initialize_cache(config)
```

### After (new pattern)
```python
from .core.optional_modules import modules

# Usage
if modules.cache.available:
    cache = modules.cache.initialize(config)
# Or simply:
cache = modules.cache.get_cache()  # Returns None if unavailable
```

## Testing

Run unit tests:
```bash
pytest tests/unit/test_optional_modules.py -v
```

## Benefits

1. **Single Source of Truth**: All optional module handling in one file
2. **Reduced Duplication**: ~150 lines of boilerplate eliminated
3. **Type Safety**: IDE autocomplete and type checking work
4. **Testability**: Each module wrapper can be unit tested
5. **Consistency**: Same pattern for all optional modules
6. **Maintainability**: Adding new modules requires changes in one place
7. **Thread Safety**: Built-in thread-safe lazy loading
