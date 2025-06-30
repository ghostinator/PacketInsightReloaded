#!/usr/bin/env python3
"""
Test utilities for Packet Insight
Provides sample data, mock objects, and test helpers
"""

import tempfile
import json
from pathlib import Path
from typing import Dict, Any, List
import unittest.mock

# Sample PCAP statistics for testing
SAMPLE_STATS: Dict[str, Any] = {
    'packet_count': 1000,
    'total_bytes': 1024 * 1024,  # 1MB
    'start_time': 1640995200.0,  # 2022-01-01 00:00:00
    'start_timestamp': 1640995200.0,
    'end_timestamp': 1640995260.0,  # 60 seconds later
    'retransmissions': 25,
    'resets': 5,
    'dns_issues': 3,
    'http_errors': {'404': 10, '500': 2},
    'tcp_syn_delays': [0.1, 0.15, 0.08, 0.12],
    'udp_jitter': [0.01, 0.02, 0.015],
    'top_talkers': {
        '192.168.1.100': 300,
        '192.168.1.101': 250,
        '10.0.0.1': 200
    },
    'protocols': {
        'TCP': 700,
        'UDP': 250,
        'ICMP': 50
    },
    'conversations': {
        '192.168.1.100_192.168.1.101': 150,
        '192.168.1.100_10.0.0.1': 100
    },
    'throughput_samples': [(1640995200.0, 1500), (1640995201.0, 1400)],
    'malformed_packets': 5,
    'tls_handshakes': 20,
    'tls_versions': {'0x0303': 15, '0x0304': 5},
    'tls_cipher_suites': {'0x1301': 10, '0x1302': 10},
    'tls_alerts': 2,
    'expired_certs': ['example.com'],
    'self_signed_certs': ['test.local'],
    'dns_queries': {'google.com': 50, 'github.com': 30},
    'dns_response_times': [0.02, 0.025, 0.018, 0.030],
    'dns_record_types': {'1': 60, '28': 20},
    'pending_dns_queries': {},
    'dhcp_servers': {'192.168.1.1': 5},
    'dhcp_discover': 5,
    'dhcp_offer': 5,
    'dhcp_request': 5,
    'dhcp_ack': 5,
    'dhcp_nak': 0
}

SAMPLE_CONFIG: Dict[str, Any] = {
    'retransmission_threshold': 0.05,
    'high_jitter_threshold': 0.1,
    'syn_delay_threshold': 0.5,
    'dns_timeout_threshold': 1.0,
    'rolling_capture_size_mb': 100,
    'rolling_capture_interval_min': 15,
    'enable_realtime_alerts': True,
    'default_capture_duration': 60,
    'default_output_format': 'text',
    'default_output_dir': 'reports',
    'packet_sample_rate': 1,
    'max_packets_in_memory': 10000,
    'enable_experimental_features': False,
    'telemetry_enabled': False,
    'log_level': 'INFO',
    'enable_debug_mode': False,
    'worker_threads': 4,
    'chunk_size': 1000,
    'memory_limit_mb': 512
}

SAMPLE_BASELINE: Dict[str, Dict[str, float]] = {
    'workday': {
        'tcp_retransmission_rate': 0.025,
        'tcp_resets': 3,
        'avg_tcp_handshake_delay': 0.1,
        'avg_udp_jitter': 0.005,
        'http_error_rate': 0.02
    },
    'weekend': {
        'tcp_retransmission_rate': 0.015,
        'tcp_resets': 1,
        'avg_tcp_handshake_delay': 0.08,
        'avg_udp_jitter': 0.003,
        'http_error_rate': 0.01
    }
}


class MockPacket:
    """Mock packet object for testing"""

    def __init__(self, **kwargs):
        # Set default values
        self.sniff_timestamp = kwargs.get('sniff_timestamp', '1640995200.0')
        self.length = kwargs.get('length', '1500')
        self.transport_layer = kwargs.get('transport_layer', 'TCP')
        self.highest_layer = kwargs.get('highest_layer', 'HTTP')

        # Add layers based on what's being tested
        if kwargs.get('has_ip', True):
            self.ip = MockIPLayer(**kwargs.get('ip_kwargs', {}))

        if kwargs.get('has_tcp', False):
            self.tcp = MockTCPLayer(**kwargs.get('tcp_kwargs', {}))

        if kwargs.get('has_udp', False):
            self.udp = MockUDPLayer(**kwargs.get('udp_kwargs', {}))

        if kwargs.get('has_http', False):
            self.http = MockHTTPLayer(**kwargs.get('http_kwargs', {}))

        if kwargs.get('has_dns', False):
            self.dns = MockDNSLayer(**kwargs.get('dns_kwargs', {}))

        if kwargs.get('has_tls', False):
            self.tls = MockTLSLayer(**kwargs.get('tls_kwargs', {}))

        if kwargs.get('has_dhcp', False):
            self.dhcp = MockDHCPLayer(**kwargs.get('dhcp_kwargs', {}))

    def __contains__(self, layer_name):
        """Support 'layer in packet' syntax"""
        layer_attr = layer_name.lower()
        return hasattr(self, layer_attr)


class MockIPLayer:
    """Mock IP layer"""

    def __init__(self, src='192.168.1.100', dst='192.168.1.101', **kwargs):
        self.src = src
        self.dst = dst


class MockTCPLayer:
    """Mock TCP layer"""

    def __init__(self, flags='', has_retransmission=False, **kwargs):
        self.flags = flags
        if has_retransmission:
            self.analysis_retransmission = True


class MockUDPLayer:
    """Mock UDP layer"""

    def __init__(self, srcport='12345', dstport='53', **kwargs):
        self.srcport = srcport
        self.dstport = dstport


class MockHTTPLayer:
    """Mock HTTP layer"""

    def __init__(self, response_code=None, **kwargs):
        if response_code:
            self.response_code = str(response_code)


class MockDNSLayer:
    """Mock DNS layer"""

    def __init__(self, flags_response='0', query_name='google.com', 
                 query_type='1', query_id='12345', **kwargs):
        self.flags_response = flags_response
        if query_name:
            self.qry_name = query_name
        if query_type:
            self.qry_type = query_type
        self.id = query_id


class MockTLSLayer:
    """Mock TLS layer"""

    def __init__(self, record_content_type=None, handshake_type=None,
                 handshake_version=None, **kwargs):
        if record_content_type:
            self.record_content_type = record_content_type
        if handshake_type:
            self.handshake_type = handshake_type
        if handshake_version:
            self.handshake_version = handshake_version


class MockDHCPLayer:
    """Mock DHCP layer"""

    def __init__(self, message_type=None, **kwargs):
        if message_type:
            self.option_dhcp_message_type = str(message_type)


class TestDataManager:
    """Manages test data and provides helper methods"""

    def __init__(self):
        self.temp_dir = None
        self.temp_files = []

    def setup_temp_directory(self) -> Path:
        """Create a temporary directory for tests"""
        self.temp_dir = Path(tempfile.mkdtemp(prefix='packet_insight_test_'))
        return self.temp_dir

    def create_temp_config(self, config_data: Dict[str, Any] = None) -> Path:
        """Create a temporary configuration file"""
        if not self.temp_dir:
            self.setup_temp_directory()

        config_data = config_data or SAMPLE_CONFIG
        config_file = self.temp_dir / 'test_config.yaml'

        import yaml
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)

        self.temp_files.append(config_file)
        return config_file

    def create_temp_baseline(self, baseline_data: Dict[str, Any] = None) -> Path:
        """Create a temporary baseline file"""
        if not self.temp_dir:
            self.setup_temp_directory()

        baseline_data = baseline_data or SAMPLE_BASELINE
        baseline_file = self.temp_dir / 'test_baseline.json'

        with open(baseline_file, 'w') as f:
            json.dump(baseline_data, f)

        self.temp_files.append(baseline_file)
        return baseline_file

    def create_mock_pcap_file(self) -> Path:
        """Create a mock PCAP file for testing"""
        if not self.temp_dir:
            self.setup_temp_directory()

        pcap_file = self.temp_dir / 'test.pcap'
        # Create an empty file that exists
        pcap_file.touch()

        self.temp_files.append(pcap_file)
        return pcap_file

    def cleanup(self):
        """Clean up temporary files and directories"""
        import shutil

        for file in self.temp_files:
            try:
                if file.exists():
                    file.unlink()
            except Exception:
                pass

        if self.temp_dir and self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir)
            except Exception:
                pass


def create_mock_pyshark_capture(packets: List[MockPacket]):
    """Create a mock pyshark capture object"""
    mock_capture = unittest.mock.MagicMock()
    mock_capture.__iter__ = unittest.mock.MagicMock(return_value=iter(packets))
    mock_capture.__list__ = unittest.mock.MagicMock(return_value=packets)
    return mock_capture


def assert_stats_valid(stats: Dict[str, Any]) -> bool:
    """Assert that statistics dictionary has valid structure"""
    required_keys = [
        'packet_count', 'total_bytes', 'start_timestamp', 'end_timestamp',
        'retransmissions', 'resets', 'dns_issues', 'protocols', 'top_talkers'
    ]

    for key in required_keys:
        assert key in stats, f"Missing required key: {key}"

    # Check data types
    assert isinstance(stats['packet_count'], int)
    assert isinstance(stats['total_bytes'], int)
    assert isinstance(stats['protocols'], dict)
    assert isinstance(stats['top_talkers'], dict)

    return True


def generate_test_packets(count: int = 10) -> List[MockPacket]:
    """Generate a list of test packets"""
    packets = []

    for i in range(count):
        # Vary the packet types
        if i % 4 == 0:
            # TCP packet
            packet = MockPacket(
                has_tcp=True,
                tcp_kwargs={'flags': 'ACK'},
                sniff_timestamp=str(1640995200.0 + i)
            )
        elif i % 4 == 1:
            # UDP packet
            packet = MockPacket(
                transport_layer='UDP',
                has_udp=True,
                sniff_timestamp=str(1640995200.0 + i)
            )
        elif i % 4 == 2:
            # HTTP packet
            packet = MockPacket(
                has_tcp=True,
                has_http=True,
                http_kwargs={'response_code': 200 if i % 2 == 0 else 404},
                sniff_timestamp=str(1640995200.0 + i)
            )
        else:
            # DNS packet
            packet = MockPacket(
                transport_layer='UDP',
                has_udp=True,
                has_dns=True,
                dns_kwargs={
                    'query_name': f'test{i}.com',
                    'query_id': str(1000 + i)
                },
                sniff_timestamp=str(1640995200.0 + i)
            )

        packets.append(packet)

    return packets


# Test configuration validation data
INVALID_CONFIG_TESTS = [
    {'retransmission_threshold': -0.1},  # Below minimum
    {'retransmission_threshold': 1.5},   # Above maximum
    {'log_level': 'INVALID'},            # Invalid choice
    {'worker_threads': 0},               # Below minimum
    {'default_output_format': 'xml'},    # Invalid format
]

VALID_CONFIG_TESTS = [
    {'retransmission_threshold': 0.1},
    {'log_level': 'DEBUG'},
    {'worker_threads': 8},
    {'default_output_format': 'json'},
    {'enable_realtime_alerts': False},
]


class PacketInsightTestCase(unittest.TestCase):
    """Base test case with common setup and teardown"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_data = TestDataManager()
        self.temp_dir = self.test_data.setup_temp_directory()

    def tearDown(self):
        """Clean up test fixtures"""
        self.test_data.cleanup()

    def create_test_config(self, **overrides):
        """Create a test configuration with optional overrides"""
        config_data = SAMPLE_CONFIG.copy()
        config_data.update(overrides)
        return self.test_data.create_temp_config(config_data)

    def assertStatsValid(self, stats):
        """Assert that statistics are valid"""
        assert_stats_valid(stats)

    def assertConfigValid(self, config):
        """Assert that configuration is valid"""
        errors = config.validate()
        self.assertEqual(len(errors), 0, f"Configuration errors: {errors}")
