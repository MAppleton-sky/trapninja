#!/usr/bin/env python3
"""
TrapNinja HA Config Bundle

Handles bundling, serialization, and checksum calculation for
shared configuration files in HA clusters.

Author: TrapNinja Team
Version: 1.0.0
"""

import os
import json
import hashlib
import logging
import tempfile
import shutil
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple
from enum import Enum

logger = logging.getLogger("trapninja")


class SharedConfig(Enum):
    """
    Enumeration of shared configuration files.
    
    These files are synchronized between HA peers.
    Server-specific files are NOT included here.
    """
    DESTINATIONS = "destinations.json"
    BLOCKED_IPS = "blocked_ips.json"
    BLOCKED_TRAPS = "blocked_traps.json"
    REDIRECTED_IPS = "redirected_ips.json"
    REDIRECTED_OIDS = "redirected_oids.json"
    REDIRECTED_DESTINATIONS = "redirected_destinations.json"
    
    @property
    def description(self) -> str:
        """Human-readable description of the config file."""
        descriptions = {
            SharedConfig.DESTINATIONS: "Trap forwarding destinations",
            SharedConfig.BLOCKED_IPS: "Blocked source IP addresses",
            SharedConfig.BLOCKED_TRAPS: "Blocked trap OIDs",
            SharedConfig.REDIRECTED_IPS: "IP-based trap redirection rules",
            SharedConfig.REDIRECTED_OIDS: "OID-based trap redirection rules",
            SharedConfig.REDIRECTED_DESTINATIONS: "Redirection destination groups",
        }
        return descriptions.get(self, self.value)


# List of shared config file names for easy reference
SHARED_CONFIG_FILES = [config.value for config in SharedConfig]


@dataclass
class ConfigEntry:
    """
    Single configuration file entry.
    
    Attributes:
        name: Filename of the configuration
        content: Parsed JSON content
        checksum: MD5 checksum of the content
        mtime: Modification time when loaded
    """
    name: str
    content: Any
    checksum: str
    mtime: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            'name': self.name,
            'content': self.content,
            'checksum': self.checksum,
            'mtime': self.mtime
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConfigEntry':
        """Deserialize from dictionary."""
        return cls(
            name=data['name'],
            content=data['content'],
            checksum=data['checksum'],
            mtime=data.get('mtime', 0.0)
        )
    
    @staticmethod
    def calculate_checksum(content: Any) -> str:
        """Calculate MD5 checksum of content."""
        content_str = json.dumps(content, sort_keys=True, separators=(',', ':'))
        return hashlib.md5(content_str.encode('utf-8')).hexdigest()
    
    def verify(self) -> bool:
        """Verify checksum matches content."""
        return self.checksum == self.calculate_checksum(self.content)


@dataclass
class ConfigBundle:
    """
    Bundle of all shared configuration files.
    
    Used for synchronization between HA peers.
    Includes version tracking and integrity verification.
    
    Attributes:
        version: Bundle version number (increments on changes)
        entries: Dict mapping filename to ConfigEntry
        bundle_checksum: Overall checksum of the entire bundle
        source_instance: Instance ID that created this bundle
        timestamp: Unix timestamp when bundle was created
    """
    version: int
    entries: Dict[str, ConfigEntry] = field(default_factory=dict)
    bundle_checksum: str = ""
    source_instance: str = ""
    timestamp: float = 0.0
    
    def __post_init__(self):
        """Calculate bundle checksum after initialization."""
        if not self.bundle_checksum:
            self.bundle_checksum = self._calculate_bundle_checksum()
        if not self.timestamp:
            import time
            self.timestamp = time.time()
    
    def _calculate_bundle_checksum(self) -> str:
        """Calculate overall bundle checksum."""
        checksums = sorted([
            f"{name}:{entry.checksum}"
            for name, entry in self.entries.items()
        ])
        combined = "|".join(checksums) + f"|v{self.version}"
        return hashlib.md5(combined.encode('utf-8')).hexdigest()
    
    def get_summary_checksum(self) -> str:
        """Get a summary checksum for quick comparison."""
        return self.bundle_checksum
    
    def add_entry(self, name: str, content: Any, mtime: float = 0.0) -> None:
        """
        Add or update a configuration entry.
        
        Args:
            name: Configuration filename
            content: Parsed JSON content
            mtime: File modification time
        """
        checksum = ConfigEntry.calculate_checksum(content)
        self.entries[name] = ConfigEntry(
            name=name,
            content=content,
            checksum=checksum,
            mtime=mtime
        )
        # Recalculate bundle checksum
        self.bundle_checksum = self._calculate_bundle_checksum()
    
    def get_entry(self, name: str) -> Optional[ConfigEntry]:
        """Get configuration entry by name."""
        return self.entries.get(name)
    
    def verify_integrity(self) -> Tuple[bool, List[str]]:
        """
        Verify integrity of all entries.
        
        Returns:
            Tuple of (all_valid, list of failed entry names)
        """
        failed = []
        for name, entry in self.entries.items():
            if not entry.verify():
                failed.append(name)
        
        # Also verify bundle checksum
        if self.bundle_checksum != self._calculate_bundle_checksum():
            failed.append("__bundle__")
        
        return len(failed) == 0, failed
    
    def compare(self, other: 'ConfigBundle') -> Dict[str, str]:
        """
        Compare this bundle with another.
        
        Returns:
            Dict mapping filename to status:
            - 'same': Content identical
            - 'modified': Content differs
            - 'added': Only in self
            - 'removed': Only in other
        """
        result = {}
        
        all_names = set(self.entries.keys()) | set(other.entries.keys())
        
        for name in all_names:
            if name in self.entries and name in other.entries:
                if self.entries[name].checksum == other.entries[name].checksum:
                    result[name] = 'same'
                else:
                    result[name] = 'modified'
            elif name in self.entries:
                result[name] = 'added'
            else:
                result[name] = 'removed'
        
        return result
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize bundle to dictionary."""
        return {
            'version': self.version,
            'entries': {
                name: entry.to_dict()
                for name, entry in self.entries.items()
            },
            'bundle_checksum': self.bundle_checksum,
            'source_instance': self.source_instance,
            'timestamp': self.timestamp
        }
    
    def to_json(self) -> str:
        """Serialize bundle to JSON string."""
        return json.dumps(self.to_dict())
    
    def to_bytes(self) -> bytes:
        """Serialize bundle to bytes."""
        return self.to_json().encode('utf-8')
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConfigBundle':
        """Deserialize bundle from dictionary."""
        entries = {
            name: ConfigEntry.from_dict(entry_data)
            for name, entry_data in data.get('entries', {}).items()
        }
        return cls(
            version=data.get('version', 0),
            entries=entries,
            bundle_checksum=data.get('bundle_checksum', ''),
            source_instance=data.get('source_instance', ''),
            timestamp=data.get('timestamp', 0.0)
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'ConfigBundle':
        """Deserialize bundle from JSON string."""
        return cls.from_dict(json.loads(json_str))
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ConfigBundle':
        """Deserialize bundle from bytes."""
        return cls.from_json(data.decode('utf-8'))
    
    @classmethod
    def load_from_disk(cls, config_dir: str, instance_id: str = "") -> 'ConfigBundle':
        """
        Load all shared configuration files from disk.
        
        Args:
            config_dir: Path to configuration directory
            instance_id: ID of this instance (for tracking source)
            
        Returns:
            ConfigBundle with all loaded configurations
        """
        import time
        
        bundle = cls(version=0, source_instance=instance_id)
        
        for config in SharedConfig:
            file_path = os.path.join(config_dir, config.value)
            
            if os.path.exists(file_path):
                try:
                    mtime = os.path.getmtime(file_path)
                    with open(file_path, 'r') as f:
                        content = json.load(f)
                    bundle.add_entry(config.value, content, mtime)
                    logger.debug(f"Loaded config: {config.value}")
                except Exception as e:
                    logger.error(f"Failed to load {config.value}: {e}")
                    # Add empty default
                    default = {} if 'destination' in config.value.lower() else []
                    bundle.add_entry(config.value, default, 0.0)
            else:
                # File doesn't exist - use empty default
                logger.debug(f"Config file not found: {config.value}")
                if config == SharedConfig.REDIRECTED_DESTINATIONS:
                    default = {}
                else:
                    default = []
                bundle.add_entry(config.value, default, 0.0)
        
        bundle.timestamp = time.time()
        return bundle
    
    def save_to_disk(self, config_dir: str, backup: bool = True) -> Tuple[bool, List[str]]:
        """
        Save all configuration entries to disk.
        
        Uses atomic writes (write to temp file, then rename) for safety.
        Optionally creates backups of existing files.
        
        Args:
            config_dir: Path to configuration directory
            backup: If True, backup existing files before overwriting
            
        Returns:
            Tuple of (success, list of files saved)
        """
        saved_files = []
        
        # Verify integrity before saving
        valid, failed = self.verify_integrity()
        if not valid:
            logger.error(f"Bundle integrity check failed: {failed}")
            return False, []
        
        for name, entry in self.entries.items():
            file_path = os.path.join(config_dir, name)
            
            try:
                # Create backup if file exists
                if backup and os.path.exists(file_path):
                    backup_path = f"{file_path}.bak"
                    try:
                        shutil.copy2(file_path, backup_path)
                        logger.debug(f"Backed up {name} to {backup_path}")
                    except Exception as e:
                        logger.warning(f"Failed to backup {name}: {e}")
                
                # Atomic write: write to temp file, then rename
                temp_fd, temp_path = tempfile.mkstemp(
                    suffix='.tmp',
                    dir=config_dir,
                    prefix=f".{name}."
                )
                
                try:
                    with os.fdopen(temp_fd, 'w') as f:
                        json.dump(entry.content, f, indent=2)
                    
                    # Set proper permissions before rename
                    os.chmod(temp_path, 0o644)
                    
                    # Atomic rename
                    os.rename(temp_path, file_path)
                    
                    saved_files.append(name)
                    logger.debug(f"Saved config: {name}")
                    
                except Exception as e:
                    # Clean up temp file on error
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass
                    raise e
                    
            except Exception as e:
                logger.error(f"Failed to save {name}: {e}")
                # Continue with other files
        
        if len(saved_files) == len(self.entries):
            logger.info(f"Saved {len(saved_files)} configuration files")
            return True, saved_files
        else:
            logger.warning(
                f"Saved {len(saved_files)}/{len(self.entries)} configuration files"
            )
            return False, saved_files
    
    def __str__(self) -> str:
        return (
            f"ConfigBundle(v{self.version}, "
            f"{len(self.entries)} entries, "
            f"checksum={self.bundle_checksum[:8]}...)"
        )
    
    def __repr__(self) -> str:
        return self.__str__()


def get_local_bundle_checksum(config_dir: str) -> str:
    """
    Quick checksum calculation without full bundle load.
    
    Useful for comparing if sync is needed without loading all files.
    
    Args:
        config_dir: Path to configuration directory
        
    Returns:
        Checksum string representing current config state
    """
    checksums = []
    
    for config in SharedConfig:
        file_path = os.path.join(config_dir, config.value)
        
        if os.path.exists(file_path):
            try:
                # Use file mtime and size for quick comparison
                stat = os.stat(file_path)
                file_sig = f"{config.value}:{stat.st_mtime}:{stat.st_size}"
                checksums.append(file_sig)
            except OSError:
                checksums.append(f"{config.value}:0:0")
        else:
            checksums.append(f"{config.value}:missing")
    
    combined = "|".join(sorted(checksums))
    return hashlib.md5(combined.encode('utf-8')).hexdigest()
