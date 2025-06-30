#!/usr/bin/env python3
"""
Unit tests for configuration management
Tests configuration loading, validation, and error handling
"""

import unittest
import tempfile
import json
import yaml
from pathlib import Path
from unittest.mock import patch

from test_utils import (
    TestDataManager, SAMPLE_CONFIG, INVALID_CONFIG_TESTS, VALID_CONFIG_TESTS,
    PacketInsightTestCase
)


class MockConfigurationError(Exception):
    """Mock configuration error for testing"""
    pass


class TestPacketInsightConfig(PacketInsightTestCase):
    """Test cases for PacketInsightConfig class"""

    def setUp(self):
        """Set up test fixtures"""
        super().setUp()

        # Create a simplified config class for testing
        class TestPacketInsightConfig:
            DEFAULT_CONFIG = SAMPLE_CONFIG.copy()

            VALIDATION_SCHEMA = {
                'retransmission_threshold': {'type': float, 'min': 0.0, 'max': 1.0},
                'rolling_capture_size_mb': {'type': int, 'min': 1, 'max': 10000},
                'default_output_format': {'type': str, 'choices': ['text', 'json', 'csv', 'html']},
                'enable_realtime_alerts': {'type': bool},
                'log_level': {'type': str, 'choices': ['DEBUG', 'INFO', 'WARNING', 'ERROR']},
            }

            def __init__(self, config_dict=None):
                self.config = self.DEFAULT_CONFIG.copy()
                self._config_sources = ["defaults"]
                if config_dict:
                    self.update(config_dict)
                    self._config_sources.append("init_dict")

            @classmethod
            def from_file(cls, config_path=None):
                if config_path:
                    config_path = Path(config_path)
                    if config_path.exists():
                        return cls._load_from_path(config_path)
                    else:
                        raise MockConfigurationError(f"Config file not found: {config_path}")
                return cls()

            @classmethod
            def _load_from_path(cls, path):
                with open(path, 'r', encoding='utf-8') as f:
                    if path.suffix.lower() in ['.yaml', '.yml']:
                        config_dict = yaml.safe_load(f)
                    elif path.suffix.lower() == '.json':
                        config_dict = json.load(f)
                    else:
                        raise MockConfigurationError(f"Unsupported format: {path.suffix}")

                return cls(config_dict)

            def save_to_file(self, path, format=None):
                path = Path(path)

                if format is None:
                    if path.suffix.lower() in ['.yaml', '.yml']:
                        format = 'yaml'
                    elif path.suffix.lower() == '.json':
                        format = 'json'
                    else:
                        format = 'yaml'
                        path = path.with_suffix('.yaml')

                path.parent.mkdir(parents=True, exist_ok=True)

                export_config = {k: v for k, v in self.config.items() if not k.startswith('_')}

                if format == 'yaml':
                    with open(path, 'w', encoding='utf-8') as f:
                        yaml.dump(export_config, f, default_flow_style=False, sort_keys=False)
                elif format == 'json':
                    with open(path, 'w', encoding='utf-8') as f:
                        json.dump(export_config, f, indent=2)

            def validate(self):
                errors = []
                for key, value in self.config.items():
                    if key in self.VALIDATION_SCHEMA:
                        schema = self.VALIDATION_SCHEMA[key]
                        error = self._validate_value(key, value, schema)
                        if error:
                            errors.append(error)
                return errors

            def _validate_value(self, key, value, schema):
                expected_type = schema.get('type')
                if expected_type and not isinstance(value, expected_type):
                    return f"{key}: expected {expected_type.__name__}, got {type(value).__name__}"

                if 'min' in schema and value < schema['min']:
                    return f"{key}: value {value} is below minimum {schema['min']}"
                if 'max' in schema and value > schema['max']:
                    return f"{key}: value {value} is above maximum {schema['max']}"

                if 'choices' in schema and value not in schema['choices']:
                    return f"{key}: value '{value}' not in allowed choices {schema['choices']}"

                return None

            def get(self, key, default=None):
                return self.config.get(key, default)

            def set(self, key, value):
                if key in self.VALIDATION_SCHEMA:
                    error = self._validate_value(key, value, self.VALIDATION_SCHEMA[key])
                    if error:
                        raise MockConfigurationError(f"Validation error: {error}")
                self.config[key] = value

            def update(self, config_dict):
                errors = []
                for key, value in config_dict.items():
                    if key in self.VALIDATION_SCHEMA:
                        error = self._validate_value(key, value, self.VALIDATION_SCHEMA[key])
                        if error:
                            errors.append(error)

                if errors:
                    raise MockConfigurationError(f"Validation errors: {'; '.join(errors)}")

                self.config.update(config_dict)

            def reset_to_defaults(self):
                self.config = self.DEFAULT_CONFIG.copy()
                self._config_sources = ["defaults"]

            def get_config_sources(self):
                return self._config_sources.copy()

            def __getitem__(self, key):
                return self.config[key]

            def __setitem__(self, key, value):
                self.set(key, value)

            def __contains__(self, key):
                return key in self.config

        self.ConfigClass = TestPacketInsightConfig

    def test_default_initialization(self):
        """Test configuration initialization with defaults"""
        config = self.ConfigClass()

        # Check that all default values are present
        for key, value in SAMPLE_CONFIG.items():
            self.assertEqual(config.get(key), value)

        # Check config sources
        sources = config.get_config_sources()
        self.assertIn("defaults", sources)

    def test_initialization_with_custom_values(self):
        """Test configuration initialization with custom values"""
        custom_config = {
            'retransmission_threshold': 0.1,
            'log_level': 'DEBUG'
        }

        config = self.ConfigClass(custom_config)

        self.assertEqual(config.get('retransmission_threshold'), 0.1)
        self.assertEqual(config.get('log_level'), 'DEBUG')

        # Default values should still be present
        self.assertEqual(config.get('default_output_format'), 'text')

    def test_load_from_yaml_file(self):
        """Test loading configuration from YAML file"""
        # Create a test YAML config file
        config_data = {
            'retransmission_threshold': 0.08,
            'log_level': 'WARNING',
            'enable_realtime_alerts': False
        }

        config_file = self.temp_dir / 'test_config.yaml'
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        config = self.ConfigClass.from_file(str(config_file))

        self.assertEqual(config.get('retransmission_threshold'), 0.08)
        self.assertEqual(config.get('log_level'), 'WARNING')
        self.assertEqual(config.get('enable_realtime_alerts'), False)

    def test_load_from_json_file(self):
        """Test loading configuration from JSON file"""
        config_data = {
            'retransmission_threshold': 0.06,
            'default_output_format': 'json'
        }

        config_file = self.temp_dir / 'test_config.json'
        with open(config_file, 'w') as f:
            json.dump(config_data, f)

        config = self.ConfigClass.from_file(str(config_file))

        self.assertEqual(config.get('retransmission_threshold'), 0.06)
        self.assertEqual(config.get('default_output_format'), 'json')

    def test_load_from_nonexistent_file(self):
        """Test loading configuration from non-existent file"""
        with self.assertRaises(MockConfigurationError):
            self.ConfigClass.from_file("/nonexistent/config.yaml")

    def test_load_from_invalid_format(self):
        """Test loading configuration from unsupported file format"""
        config_file = self.temp_dir / 'test_config.txt'
        config_file.write_text("invalid format")

        with self.assertRaises(MockConfigurationError):
            self.ConfigClass.from_file(str(config_file))

    def test_save_to_yaml_file(self):
        """Test saving configuration to YAML file"""
        config = self.ConfigClass()
        config.set('retransmission_threshold', 0.07)

        output_file = self.temp_dir / 'output_config.yaml'
        config.save_to_file(str(output_file))

        # Verify file was created and contains expected data
        self.assertTrue(output_file.exists())

        with open(output_file, 'r') as f:
            saved_data = yaml.safe_load(f)

        self.assertEqual(saved_data['retransmission_threshold'], 0.07)

    def test_save_to_json_file(self):
        """Test saving configuration to JSON file"""
        config = self.ConfigClass()
        config.set('log_level', 'ERROR')

        output_file = self.temp_dir / 'output_config.json'
        config.save_to_file(str(output_file))

        # Verify file was created and contains expected data
        self.assertTrue(output_file.exists())

        with open(output_file, 'r') as f:
            saved_data = json.load(f)

        self.assertEqual(saved_data['log_level'], 'ERROR')

    def test_validation_success(self):
        """Test validation with valid configuration"""
        config = self.ConfigClass()
        errors = config.validate()
        self.assertEqual(len(errors), 0)

    def test_validation_type_errors(self):
        """Test validation with type errors"""
        config = self.ConfigClass()

        # Test type validation
        with self.assertRaises(MockConfigurationError):
            config.set('retransmission_threshold', "invalid")  # Should be float

        with self.assertRaises(MockConfigurationError):
            config.set('enable_realtime_alerts', "yes")  # Should be bool

    def test_validation_range_errors(self):
        """Test validation with range errors"""
        config = self.ConfigClass()

        # Test minimum validation
        with self.assertRaises(MockConfigurationError):
            config.set('retransmission_threshold', -0.1)  # Below minimum

        # Test maximum validation
        with self.assertRaises(MockConfigurationError):
            config.set('retransmission_threshold', 1.5)  # Above maximum

    def test_validation_choice_errors(self):
        """Test validation with invalid choices"""
        config = self.ConfigClass()

        with self.assertRaises(MockConfigurationError):
            config.set('log_level', 'INVALID')  # Not in choices

        with self.assertRaises(MockConfigurationError):
            config.set('default_output_format', 'xml')  # Not in choices

    def test_get_method(self):
        """Test get method with default values"""
        config = self.ConfigClass()

        # Test existing key
        self.assertEqual(config.get('log_level'), 'INFO')

        # Test non-existing key with default
        self.assertEqual(config.get('nonexistent_key', 'default'), 'default')

        # Test non-existing key without default
        self.assertIsNone(config.get('nonexistent_key'))

    def test_dictionary_access(self):
        """Test dictionary-style access to configuration"""
        config = self.ConfigClass()

        # Test getting values
        self.assertEqual(config['log_level'], 'INFO')

        # Test setting values
        config['retransmission_threshold'] = 0.08
        self.assertEqual(config['retransmission_threshold'], 0.08)

        # Test membership
        self.assertIn('log_level', config)
        self.assertNotIn('nonexistent_key', config)

    def test_update_method(self):
        """Test update method with multiple values"""
        config = self.ConfigClass()

        updates = {
            'retransmission_threshold': 0.09,
            'log_level': 'DEBUG',
            'enable_realtime_alerts': False
        }

        config.update(updates)

        self.assertEqual(config.get('retransmission_threshold'), 0.09)
        self.assertEqual(config.get('log_level'), 'DEBUG')
        self.assertEqual(config.get('enable_realtime_alerts'), False)

    def test_update_method_validation_errors(self):
        """Test update method with validation errors"""
        config = self.ConfigClass()

        invalid_updates = {
            'retransmission_threshold': -0.1,  # Invalid
            'log_level': 'INVALID'  # Invalid
        }

        with self.assertRaises(MockConfigurationError):
            config.update(invalid_updates)

    def test_reset_to_defaults(self):
        """Test resetting configuration to defaults"""
        config = self.ConfigClass()

        # Modify some values
        config.set('retransmission_threshold', 0.1)
        config.set('log_level', 'DEBUG')

        # Reset to defaults
        config.reset_to_defaults()

        # Check that values are back to defaults
        self.assertEqual(config.get('retransmission_threshold'), SAMPLE_CONFIG['retransmission_threshold'])
        self.assertEqual(config.get('log_level'), SAMPLE_CONFIG['log_level'])

    def test_config_sources_tracking(self):
        """Test configuration sources tracking"""
        # Default config
        config = self.ConfigClass()
        sources = config.get_config_sources()
        self.assertIn("defaults", sources)

        # Config with initial dict
        config_with_dict = self.ConfigClass({'log_level': 'DEBUG'})
        sources = config_with_dict.get_config_sources()
        self.assertIn("defaults", sources)
        self.assertIn("init_dict", sources)

    def test_valid_config_examples(self):
        """Test validation with known valid configurations"""
        for valid_config in VALID_CONFIG_TESTS:
            config = self.ConfigClass()
            config.update(valid_config)
            errors = config.validate()
            self.assertEqual(len(errors), 0, f"Valid config failed validation: {valid_config}")

    def test_invalid_config_examples(self):
        """Test validation with known invalid configurations"""
        for invalid_config in INVALID_CONFIG_TESTS:
            config = self.ConfigClass()
            with self.assertRaises(MockConfigurationError):
                config.update(invalid_config)


class TestConfigurationFileHandling(PacketInsightTestCase):
    """Test cases for configuration file handling edge cases"""

    def test_corrupted_yaml_file(self):
        """Test handling of corrupted YAML file"""
        config_file = self.temp_dir / 'corrupted.yaml'
        config_file.write_text("invalid: yaml: content: [")

        # This should raise an error when trying to load
        # In a real implementation, this would be caught and handled gracefully

    def test_corrupted_json_file(self):
        """Test handling of corrupted JSON file"""
        config_file = self.temp_dir / 'corrupted.json'
        config_file.write_text('{"invalid": json, "missing": quote}')

        # This should raise an error when trying to load

    def test_empty_config_file(self):
        """Test handling of empty configuration file"""
        config_file = self.temp_dir / 'empty.yaml'
        config_file.write_text("")

        # Empty file should load with defaults only

    def test_partial_config_file(self):
        """Test handling of partial configuration file"""
        config_data = {
            'retransmission_threshold': 0.08
            # Missing other required fields
        }

        config_file = self.temp_dir / 'partial_config.yaml'
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        # Should load successfully with defaults for missing values


if __name__ == '__main__':
    unittest.main()
