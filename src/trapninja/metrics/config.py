#!/usr/bin/env python3
"""
TrapNinja Metrics Configuration Module

Handles loading, validation, and management of metrics configuration.
Supports:
- Custom output directory for Prometheus metrics files
- Global labels/tags applied to all metrics
- Export interval configuration
- File naming customization

Configuration file: metrics_config.json
Location: Same directory as other TrapNinja config files

Example configuration:
{
    "enabled": true,
    "directory": "/opt/metrics",
    "export_interval_seconds": 60,
    "prometheus_file": "trapninja_metrics.prom",
    "json_file": "trapninja_metrics.json",
    "global_labels": {
        "on_prem": "1",
        "environment": "production",
        "datacenter": "dc1"
    }
}
"""

import os
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Any

logger = logging.getLogger("trapninja")

# Default configuration values
DEFAULT_METRICS_DIR = "/var/log/trapninja/metrics"
DEFAULT_EXPORT_INTERVAL = 60
DEFAULT_PROMETHEUS_FILE = "trapninja_metrics.prom"
DEFAULT_JSON_FILE = "trapninja_metrics.json"


@dataclass
class MetricsConfig:
    """
    Configuration for TrapNinja metrics system.
    
    Attributes:
        enabled: Whether metrics collection is enabled
        directory: Directory to write metrics files
        export_interval_seconds: How often to export metrics (seconds)
        prometheus_file: Filename for Prometheus format metrics
        json_file: Filename for JSON format metrics
        global_labels: Labels/tags to apply to ALL metrics
    """
    enabled: bool = True
    directory: str = DEFAULT_METRICS_DIR
    export_interval_seconds: int = DEFAULT_EXPORT_INTERVAL
    prometheus_file: str = DEFAULT_PROMETHEUS_FILE
    json_file: str = DEFAULT_JSON_FILE
    global_labels: Dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate and normalize configuration values."""
        # Ensure directory is an absolute path
        if self.directory and not os.path.isabs(self.directory):
            self.directory = os.path.abspath(self.directory)
        
        # Validate export interval
        if self.export_interval_seconds < 1:
            logger.warning(
                f"Invalid export_interval_seconds ({self.export_interval_seconds}), "
                f"using default ({DEFAULT_EXPORT_INTERVAL})"
            )
            self.export_interval_seconds = DEFAULT_EXPORT_INTERVAL
        
        # Sanitize label keys and values
        sanitized_labels = {}
        for key, value in self.global_labels.items():
            # Prometheus label names must match [a-zA-Z_][a-zA-Z0-9_]*
            sanitized_key = self._sanitize_label_name(key)
            # Values are strings
            sanitized_value = str(value)
            sanitized_labels[sanitized_key] = sanitized_value
        self.global_labels = sanitized_labels
    
    @staticmethod
    def _sanitize_label_name(name: str) -> str:
        """
        Sanitize a label name to be Prometheus-compliant.
        
        Prometheus label names must:
        - Start with [a-zA-Z_]
        - Contain only [a-zA-Z0-9_]
        """
        if not name:
            return "_unnamed"
        
        # Replace invalid characters with underscore
        sanitized = ""
        for i, char in enumerate(name):
            if i == 0:
                # First character must be letter or underscore
                if char.isalpha() or char == '_':
                    sanitized += char
                else:
                    sanitized += '_' + char if char.isalnum() else '_'
            else:
                # Subsequent characters can be alphanumeric or underscore
                if char.isalnum() or char == '_':
                    sanitized += char
                else:
                    sanitized += '_'
        
        return sanitized or "_unnamed"
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MetricsConfig':
        """
        Create MetricsConfig from a dictionary.
        
        Args:
            data: Configuration dictionary
            
        Returns:
            MetricsConfig instance
        """
        return cls(
            enabled=data.get('enabled', True),
            directory=data.get('directory', DEFAULT_METRICS_DIR),
            export_interval_seconds=data.get('export_interval_seconds', DEFAULT_EXPORT_INTERVAL),
            prometheus_file=data.get('prometheus_file', DEFAULT_PROMETHEUS_FILE),
            json_file=data.get('json_file', DEFAULT_JSON_FILE),
            global_labels=data.get('global_labels', {}),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization.
        
        Returns:
            Configuration as dictionary
        """
        return {
            'enabled': self.enabled,
            'directory': self.directory,
            'export_interval_seconds': self.export_interval_seconds,
            'prometheus_file': self.prometheus_file,
            'json_file': self.json_file,
            'global_labels': self.global_labels,
        }
    
    @property
    def prometheus_path(self) -> str:
        """Full path to Prometheus metrics file."""
        return os.path.join(self.directory, self.prometheus_file)
    
    @property
    def json_path(self) -> str:
        """Full path to JSON metrics file."""
        return os.path.join(self.directory, self.json_file)


# Global configuration instance
_metrics_config: Optional[MetricsConfig] = None


def get_config_file_path() -> str:
    """
    Get the path to the metrics configuration file.
    
    Uses the same config directory as other TrapNinja config files.
    
    Returns:
        Path to metrics_config.json
    """
    try:
        from ..config import CONFIG_DIR
        return os.path.join(CONFIG_DIR, 'metrics_config.json')
    except ImportError:
        # Fallback if config module not available
        return '/etc/trapninja/metrics_config.json'


def load_metrics_config(config_file: str = None) -> MetricsConfig:
    """
    Load metrics configuration from file.
    
    Args:
        config_file: Optional path to config file. If not provided,
                    uses the default location.
    
    Returns:
        MetricsConfig instance
    """
    global _metrics_config
    
    if config_file is None:
        config_file = get_config_file_path()
    
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                data = json.load(f)
            
            _metrics_config = MetricsConfig.from_dict(data)
            logger.info(f"Loaded metrics config from {config_file}")
            
            # Log configuration summary
            if _metrics_config.global_labels:
                labels_str = ", ".join(
                    f"{k}={v}" for k, v in _metrics_config.global_labels.items()
                )
                logger.info(f"  Global labels: {labels_str}")
            logger.info(f"  Output directory: {_metrics_config.directory}")
            logger.info(f"  Export interval: {_metrics_config.export_interval_seconds}s")
            
            return _metrics_config
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in metrics config {config_file}: {e}")
        except Exception as e:
            logger.error(f"Error loading metrics config: {e}")
    else:
        logger.debug(f"Metrics config file not found: {config_file}")
    
    # Return default configuration
    _metrics_config = MetricsConfig()
    return _metrics_config


def save_metrics_config(config: MetricsConfig, config_file: str = None) -> bool:
    """
    Save metrics configuration to file.
    
    Args:
        config: MetricsConfig instance to save
        config_file: Optional path to config file
        
    Returns:
        True if saved successfully
    """
    if config_file is None:
        config_file = get_config_file_path()
    
    try:
        # Ensure directory exists
        config_dir = os.path.dirname(config_file)
        if config_dir and not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)
        
        with open(config_file, 'w') as f:
            json.dump(config.to_dict(), f, indent=2)
        
        logger.info(f"Saved metrics config to {config_file}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to save metrics config: {e}")
        return False


def get_metrics_config() -> MetricsConfig:
    """
    Get the current metrics configuration.
    
    Loads from file if not already loaded.
    
    Returns:
        Current MetricsConfig instance
    """
    global _metrics_config
    
    if _metrics_config is None:
        _metrics_config = load_metrics_config()
    
    return _metrics_config


def create_example_config() -> Dict[str, Any]:
    """
    Create an example metrics configuration dictionary.
    
    Useful for generating example configuration files.
    
    Returns:
        Example configuration dictionary with comments
    """
    return {
        "_comment": "TrapNinja Metrics Configuration",
        "_comment_labels": "global_labels are added to ALL Prometheus metrics",
        "enabled": True,
        "directory": "/opt/metrics",
        "export_interval_seconds": 60,
        "prometheus_file": "trapninja_metrics.prom",
        "json_file": "trapninja_metrics.json",
        "global_labels": {
            "on_prem": "1",
            "environment": "production"
        }
    }
