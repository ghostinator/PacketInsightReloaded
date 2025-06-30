#!/usr/bin/env python3
"""
Enhanced Configuration Management for Packet Insight
Includes proper type hints, validation, and improved error handling
"""

import os
import sys
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional, Union, List
import logging

from .exceptions import ConfigurationError

logger = logging.getLogger(__name__)


class PacketInsightConfig:
    """Enhanced configuration manager with proper type safety and validation"""

    # Default configuration values with type annotations
    DEFAULT_CONFIG: Dict[str, Any] = {
        # Analysis thresholds
        'retransmission_threshold': 0.05,  # 5% retransmission rate threshold
        'high_jitter_threshold': 0.1,      # 100ms jitter threshold
        'syn_delay_threshold': 0.5,        # 500ms SYN delay threshold
        'dns_timeout_threshold': 1.0,      # 1s DNS response time threshold

        # Live capture settings
        'rolling_capture_size_mb': 100,    # Start new capture file after 100MB
        'rolling_capture_interval_min': 15, # Start new capture file every 15 minutes
        'enable_realtime_alerts': True,    # Show alerts in real-time during live capture
        'default_capture_duration': 60,    # Default capture duration in seconds

        # Output settings
        'default_output_format': 'text',   # Default output format (text, json, csv, html)
        'default_output_dir': 'reports',   # Default directory for saving reports

        # Advanced settings
        'packet_sample_rate': 1,           # Process every Nth packet (1 = all packets)
        'max_packets_in_memory': 10000,    # Maximum packets to keep in memory
        'enable_experimental_features': False, # Enable experimental features

        # Telemetry settings (new)
        'telemetry_enabled': False,        # Enable anonymous telemetry
        'telemetry_endpoint': 'https://api.packetinsight.local/v1/telemetry',
        'telemetry_interval_hours': 24,    # How often to send telemetry data

        # Logging settings
        'log_level': 'INFO',               # Logging level (DEBUG, INFO, WARNING, ERROR)
        'log_file': None,                  # Log file path (None for console only)
        'enable_debug_mode': False,        # Enable debug mode

        # Performance settings
        'worker_threads': 4,               # Number of worker threads for analysis
        'chunk_size': 1000,                # Packet processing chunk size
        'memory_limit_mb': 512,            # Memory limit for analysis operations
    }

    # Validation schema for configuration values
    VALIDATION_SCHEMA: Dict[str, Dict[str, Any]] = {
        'retransmission_threshold': {'type': float, 'min': 0.0, 'max': 1.0},
        'high_jitter_threshold': {'type': float, 'min': 0.0, 'max': 10.0},
        'syn_delay_threshold': {'type': float, 'min': 0.0, 'max': 60.0},
        'dns_timeout_threshold': {'type': float, 'min': 0.0, 'max': 30.0},
        'rolling_capture_size_mb': {'type': int, 'min': 1, 'max': 10000},
        'rolling_capture_interval_min': {'type': int, 'min': 1, 'max': 1440},
        'enable_realtime_alerts': {'type': bool},
        'default_capture_duration': {'type': int, 'min': 1, 'max': 86400},
        'default_output_format': {'type': str, 'choices': ['text', 'json', 'csv', 'html']},
        'packet_sample_rate': {'type': int, 'min': 1, 'max': 1000},
        'max_packets_in_memory': {'type': int, 'min': 100, 'max': 1000000},
        'enable_experimental_features': {'type': bool},
        'telemetry_enabled': {'type': bool},
        'telemetry_interval_hours': {'type': int, 'min': 1, 'max': 168},  # 1 hour to 1 week
        'log_level': {'type': str, 'choices': ['DEBUG', 'INFO', 'WARNING', 'ERROR']},
        'enable_debug_mode': {'type': bool},
        'worker_threads': {'type': int, 'min': 1, 'max': 32},
        'chunk_size': {'type': int, 'min': 10, 'max': 10000},
        'memory_limit_mb': {'type': int, 'min': 64, 'max': 16384},
    }

    def __init__(self, config_dict: Optional[Dict[str, Any]] = None):
        """Initialize configuration with optional custom values"""
        self.config = self.DEFAULT_CONFIG.copy()
        self._config_sources: List[str] = ["defaults"]

        if config_dict:
            self.update(config_dict)
            self._config_sources.append("init_dict")

    @classmethod
    def from_file(cls, config_path: Optional[str] = None) -> 'PacketInsightConfig':
        """Load configuration from file with fallbacks and proper error handling"""
        instance = cls()

        # Try user-specified path first
        if config_path:
            if os.path.exists(config_path):
                try:
                    instance._load_from_path(Path(config_path))
                    return instance
                except Exception as e:
                    raise ConfigurationError(f"Failed to load config from {config_path}: {e}")
            else:
                raise ConfigurationError(f"Config file not found: {config_path}")

        # Try standard locations
        standard_paths = [
            Path.cwd() / 'packet_insight.yaml',     # Current directory
            Path.cwd() / 'packet_insight.yml',
            Path.cwd() / 'packet_insight.json',
            Path.home() / '.config' / 'packet_insight.yaml',  # User config directory
            Path.home() / '.packet_insight.yaml',   # User home
            Path('/etc/packet_insight.yaml'),       # System-wide (Linux/macOS)
        ]

        for path in standard_paths:
            if path.exists():
                try:
                    instance._load_from_path(path)
                    logger.info(f"Loaded configuration from {path}")
                    return instance
                except Exception as e:
                    logger.warning(f"Failed to load config from {path}: {e}")

        # No config found, use defaults
        logger.info("No configuration file found. Using defaults.")
        return instance

    def _load_from_path(self, path: Path) -> None:
        """Load configuration from a specific path with validation"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                if path.suffix.lower() in ['.yaml', '.yml']:
                    config_dict = yaml.safe_load(f)
                elif path.suffix.lower() == '.json':
                    config_dict = json.load(f)
                else:
                    raise ConfigurationError(f"Unsupported config format: {path.suffix}")

            if config_dict:
                self.update(config_dict)
                self._config_sources.append(str(path))

        except yaml.YAMLError as e:
            raise ConfigurationError(f"YAML parsing error in {path}: {e}")
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"JSON parsing error in {path}: {e}")
        except IOError as e:
            raise ConfigurationError(f"IO error reading {path}: {e}")

    def save_to_file(self, path: Union[str, Path], format: Optional[str] = None) -> None:
        """Save current configuration to file with format auto-detection"""
        path = Path(path)

        # Auto-detect format from extension if not specified
        if format is None:
            if path.suffix.lower() in ['.yaml', '.yml']:
                format = 'yaml'
            elif path.suffix.lower() == '.json':
                format = 'json'
            else:
                format = 'yaml'  # Default to YAML
                path = path.with_suffix('.yaml')

        try:
            # Create directory if it doesn't exist
            path.parent.mkdir(parents=True, exist_ok=True)

            # Create a clean config dict for export (remove internal metadata)
            export_config = {k: v for k, v in self.config.items() 
                           if not k.startswith('_')}

            if format == 'yaml':
                with open(path, 'w', encoding='utf-8') as f:
                    yaml.dump(export_config, f, default_flow_style=False, sort_keys=False)
            elif format == 'json':
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(export_config, f, indent=2)
            else:
                raise ConfigurationError(f"Unsupported format: {format}")

            logger.info(f"Configuration saved to {path}")

        except Exception as e:
            raise ConfigurationError(f"Failed to save configuration to {path}: {e}")

    def validate(self) -> List[str]:
        """Validate current configuration against schema"""
        errors = []

        for key, value in self.config.items():
            if key in self.VALIDATION_SCHEMA:
                schema = self.VALIDATION_SCHEMA[key]
                error = self._validate_value(key, value, schema)
                if error:
                    errors.append(error)

        return errors

    def _validate_value(self, key: str, value: Any, schema: Dict[str, Any]) -> Optional[str]:
        """Validate a single configuration value"""
        # Type validation
        expected_type = schema.get('type')
        if expected_type and not isinstance(value, expected_type):
            return f"{key}: expected {expected_type.__name__}, got {type(value).__name__}"

        # Range validation
        if 'min' in schema and value < schema['min']:
            return f"{key}: value {value} is below minimum {schema['min']}"
        if 'max' in schema and value > schema['max']:
            return f"{key}: value {value} is above maximum {schema['max']}"

        # Choice validation
        if 'choices' in schema and value not in schema['choices']:
            return f"{key}: value '{value}' not in allowed choices {schema['choices']}"

        return None

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with optional default"""
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set configuration value with validation"""
        if key in self.VALIDATION_SCHEMA:
            error = self._validate_value(key, value, self.VALIDATION_SCHEMA[key])
            if error:
                raise ConfigurationError(f"Validation error: {error}")

        self.config[key] = value

    def update(self, config_dict: Dict[str, Any]) -> None:
        """Update multiple configuration values with validation"""
        errors = []

        for key, value in config_dict.items():
            if key in self.VALIDATION_SCHEMA:
                error = self._validate_value(key, value, self.VALIDATION_SCHEMA[key])
                if error:
                    errors.append(error)

        if errors:
            raise ConfigurationError(f"Validation errors: {'; '.join(errors)}")

        self.config.update(config_dict)

    def reset_to_defaults(self) -> None:
        """Reset configuration to default values"""
        self.config = self.DEFAULT_CONFIG.copy()
        self._config_sources = ["defaults"]

    def get_config_sources(self) -> List[str]:
        """Get list of configuration sources"""
        return self._config_sources.copy()

    def export_schema(self) -> Dict[str, Any]:
        """Export the validation schema for documentation purposes"""
        return self.VALIDATION_SCHEMA.copy()

    def __getitem__(self, key: str) -> Any:
        """Allow dictionary-like access to configuration"""
        return self.config[key]

    def __setitem__(self, key: str, value: Any) -> None:
        """Allow dictionary-like setting of configuration"""
        self.set(key, value)

    def __contains__(self, key: str) -> bool:
        """Allow 'in' operator for checking key existence"""
        return key in self.config

    def __repr__(self) -> str:
        """String representation of configuration"""
        return f"PacketInsightConfig(sources={self._config_sources})"

    def __str__(self) -> str:
        """Human-readable string representation"""
        return f"PacketInsight Configuration with {len(self.config)} settings"


# Utility function for backward compatibility
def load_config(config_path: Optional[str] = None) -> PacketInsightConfig:
    """Load configuration from file or defaults"""
    return PacketInsightConfig.from_file(config_path)


# Example usage and validation
if __name__ == "__main__":
    # Create default configuration
    config = PacketInsightConfig()

    # Validate configuration
    errors = config.validate()
    if errors:
        print("Configuration errors:")
        for error in errors:
            print(f"  - {error}")
    else:
        print("Configuration is valid")

    # Export default configuration
    if len(sys.argv) > 1:
        config.save_to_file(sys.argv[1])
        print(f"Default configuration exported to {sys.argv[1]}")
    else:
        print("Usage: python config.py <output_file>")
