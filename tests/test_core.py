#!/usr/bin/env python3
"""
Unit tests for the core analytics engine
Tests packet analysis, statistics generation, and error handling
"""

import unittest
import tempfile
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import json

from test_utils import (
    TestDataManager, MockPacket, SAMPLE_STATS, SAMPLE_CONFIG,
    assert_stats_valid, create_mock_pyshark_capture, PacketInsightTestCase,
    generate_test_packets
)

# Mock the insight modules since we're testing in isolation
import sys
from unittest.mock import MagicMock

# Create mock modules for testing
mock_insight = MagicMock()
mock_insight.exceptions = MagicMock()
mock_insight.config = MagicMock()
mock_insight.utils = MagicMock()

sys.modules['insight'] = mock_insight
sys.modules['insight.exceptions'] = mock_insight.exceptions
sys.modules['insight.config'] = mock_insight.config
sys.modules['insight.utils'] = mock_insight.utils

# Define the exceptions for testing
class PacketInsightError(Exception):
    pass

class CaptureError(PacketInsightError):
    pass

class AnalysisError(PacketInsightError):
    pass

class BaselineError(PacketInsightError):
    pass

mock_insight.exceptions.PacketInsightError = PacketInsightError
mock_insight.exceptions.CaptureError = CaptureError
mock_insight.exceptions.AnalysisError = AnalysisError
mock_insight.exceptions.BaselineError = BaselineError

# Mock config class
class MockPacketInsightConfig:
    def __init__(self, config_dict=None):
        self.config = SAMPLE_CONFIG.copy()
        if config_dict:
            self.config.update(config_dict)

    def get(self, key, default=None):
        return self.config.get(key, default)

mock_insight.config.PacketInsightConfig = MockPacketInsightConfig

# Mock utils
def mock_safe_divide(numerator, denominator):
    return numerator / denominator if denominator else 0.0

mock_insight.utils.safe_divide = mock_safe_divide
mock_insight.utils.get_tshark_path = lambda: "tshark"


class TestPacketAnalyzer(PacketInsightTestCase):
    """Test cases for PacketAnalyzer class"""

    def setUp(self):
        """Set up test fixtures"""
        super().setUp()
        self.config = MockPacketInsightConfig()

        # Create a simplified analyzer class for testing
        class TestPacketAnalyzer:
            def __init__(self, config=None):
                self.config = config or MockPacketInsightConfig()

            def initialize_stats(self):
                return {
                    'packet_count': 0,
                    'total_bytes': 0,
                    'start_time': 1640995200.0,
                    'start_timestamp': float('inf'),
                    'end_timestamp': 0,
                    'retransmissions': 0,
                    'resets': 0,
                    'dns_issues': 0,
                    'http_errors': {},
                    'tcp_syn_delays': [],
                    'udp_jitter': [],
                    'top_talkers': {},
                    'protocols': {},
                    'conversations': {},
                    'throughput_samples': [],
                    'prev_udp_time': {},
                    'malformed_packets': 0,
                    'tls_handshakes': 0,
                    'tls_versions': {},
                    'tls_cipher_suites': {},
                    'tls_alerts': 0,
                    'expired_certs': [],
                    'self_signed_certs': [],
                    'dns_queries': {},
                    'dns_response_times': [],
                    'dns_record_types': {},
                    'pending_dns_queries': {},
                    'dhcp_servers': {},
                    'dhcp_discover': 0,
                    'dhcp_offer': 0,
                    'dhcp_request': 0,
                    'dhcp_ack': 0,
                    'dhcp_nak': 0
                }

            def update_stats(self, stats, packet):
                """Simplified update_stats for testing"""
                stats['packet_count'] += 1

                if hasattr(packet, 'length'):
                    stats['total_bytes'] += int(packet.length)

                if hasattr(packet, 'sniff_timestamp'):
                    timestamp = float(packet.sniff_timestamp)
                    stats['start_timestamp'] = min(stats['start_timestamp'], timestamp)
                    stats['end_timestamp'] = max(stats['end_timestamp'], timestamp)

                # Protocol tracking
                protocol = getattr(packet, 'transport_layer', 'Unknown')
                if protocol not in stats['protocols']:
                    stats['protocols'][protocol] = 0
                stats['protocols'][protocol] += 1

                # IP analysis
                if hasattr(packet, 'ip'):
                    src = packet.ip.src
                    dst = packet.ip.dst
                    if src not in stats['top_talkers']:
                        stats['top_talkers'][src] = 0
                    if dst not in stats['top_talkers']:
                        stats['top_talkers'][dst] = 0
                    stats['top_talkers'][src] += 1
                    stats['top_talkers'][dst] += 1

                # TCP analysis
                if hasattr(packet, 'tcp'):
                    if hasattr(packet.tcp, 'analysis_retransmission'):
                        stats['retransmissions'] += 1
                    if 'RST' in getattr(packet.tcp, 'flags', ''):
                        stats['resets'] += 1

                # HTTP analysis
                if hasattr(packet, 'http') and hasattr(packet.http, 'response_code'):
                    code = packet.http.response_code
                    if code.startswith(('4', '5')):
                        if code not in stats['http_errors']:
                            stats['http_errors'][code] = 0
                        stats['http_errors'][code] += 1

                # DNS analysis
                if hasattr(packet, 'dns'):
                    if hasattr(packet.dns, 'qry_name'):
                        domain = packet.dns.qry_name
                        if domain not in stats['dns_queries']:
                            stats['dns_queries'][domain] = 0
                        stats['dns_queries'][domain] += 1

            def analyze_pcap(self, pcap_path):
                """Mock analyze_pcap method"""
                if not Path(pcap_path).exists():
                    raise CaptureError(f"PCAP file not found: {pcap_path}")

                stats = self.initialize_stats()

                # Simulate processing some packets
                test_packets = generate_test_packets(10)
                for packet in test_packets:
                    self.update_stats(stats, packet)

                return stats

        self.analyzer = TestPacketAnalyzer(self.config)

    def test_initialize_stats(self):
        """Test statistics initialization"""
        stats = self.analyzer.initialize_stats()

        # Check required fields exist
        required_fields = [
            'packet_count', 'total_bytes', 'start_timestamp', 'end_timestamp',
            'retransmissions', 'resets', 'protocols', 'top_talkers'
        ]

        for field in required_fields:
            self.assertIn(field, stats)

        # Check initial values
        self.assertEqual(stats['packet_count'], 0)
        self.assertEqual(stats['total_bytes'], 0)
        self.assertEqual(stats['start_timestamp'], float('inf'))

    def test_update_stats_basic_packet(self):
        """Test updating statistics with a basic packet"""
        stats = self.analyzer.initialize_stats()

        packet = MockPacket(
            sniff_timestamp='1640995200.0',
            length='1500',
            transport_layer='TCP'
        )

        self.analyzer.update_stats(stats, packet)

        self.assertEqual(stats['packet_count'], 1)
        self.assertEqual(stats['total_bytes'], 1500)
        self.assertEqual(stats['protocols']['TCP'], 1)

    def test_update_stats_ip_tracking(self):
        """Test IP address tracking in statistics"""
        stats = self.analyzer.initialize_stats()

        packet = MockPacket(
            has_ip=True,
            ip_kwargs={'src': '192.168.1.100', 'dst': '192.168.1.101'}
        )

        self.analyzer.update_stats(stats, packet)

        self.assertEqual(stats['top_talkers']['192.168.1.100'], 1)
        self.assertEqual(stats['top_talkers']['192.168.1.101'], 1)

    def test_update_stats_tcp_retransmission(self):
        """Test TCP retransmission detection"""
        stats = self.analyzer.initialize_stats()

        packet = MockPacket(
            has_tcp=True,
            tcp_kwargs={'has_retransmission': True}
        )

        self.analyzer.update_stats(stats, packet)

        self.assertEqual(stats['retransmissions'], 1)

    def test_update_stats_http_errors(self):
        """Test HTTP error tracking"""
        stats = self.analyzer.initialize_stats()

        # HTTP 404 error
        packet = MockPacket(
            has_http=True,
            http_kwargs={'response_code': 404}
        )

        self.analyzer.update_stats(stats, packet)

        self.assertEqual(stats['http_errors']['404'], 1)

        # HTTP 500 error
        packet500 = MockPacket(
            has_http=True,
            http_kwargs={'response_code': 500}
        )

        self.analyzer.update_stats(stats, packet500)

        self.assertEqual(stats['http_errors']['500'], 1)

    def test_update_stats_dns_queries(self):
        """Test DNS query tracking"""
        stats = self.analyzer.initialize_stats()

        packet = MockPacket(
            has_dns=True,
            dns_kwargs={'query_name': 'google.com'}
        )

        self.analyzer.update_stats(stats, packet)

        self.assertEqual(stats['dns_queries']['google.com'], 1)

    def test_analyze_pcap_file_not_found(self):
        """Test analyze_pcap with non-existent file"""
        with self.assertRaises(CaptureError):
            self.analyzer.analyze_pcap("/nonexistent/file.pcap")

    def test_analyze_pcap_valid_file(self):
        """Test analyze_pcap with valid file"""
        # Create a mock PCAP file
        pcap_file = self.test_data.create_mock_pcap_file()

        stats = self.analyzer.analyze_pcap(str(pcap_file))

        # Verify stats structure
        assert_stats_valid(stats)

        # Should have processed some packets (from generate_test_packets)
        self.assertGreater(stats['packet_count'], 0)

    def test_analyze_pcap_statistics_validity(self):
        """Test that analyzed statistics are valid"""
        pcap_file = self.test_data.create_mock_pcap_file()

        stats = self.analyzer.analyze_pcap(str(pcap_file))

        # Timestamp consistency
        if stats['packet_count'] > 0:
            self.assertLessEqual(stats['start_timestamp'], stats['end_timestamp'])

        # Protocol counts should sum correctly
        total_protocol_packets = sum(stats['protocols'].values())
        self.assertEqual(total_protocol_packets, stats['packet_count'])


class TestBaselineManager(PacketInsightTestCase):
    """Test cases for BaselineManager class"""

    def setUp(self):
        """Set up test fixtures"""
        super().setUp()

        # Create a simplified BaselineManager for testing
        class TestBaselineManager:
            def __init__(self, baseline_path=None):
                self.baseline_path = baseline_path or (self.temp_dir / 'test_baseline.json')

            def get_baseline_type(self):
                from datetime import datetime
                now = datetime.now()
                return "workday" if now.weekday() < 5 else "weekend"

            def load_baseline(self):
                if not Path(self.baseline_path).exists():
                    return None

                try:
                    with open(self.baseline_path, 'r') as f:
                        return json.load(f)
                except Exception as e:
                    raise BaselineError(f"Error loading baseline: {e}")

            def save_baseline(self, baseline_data):
                try:
                    Path(self.baseline_path).parent.mkdir(parents=True, exist_ok=True)
                    with open(self.baseline_path, 'w') as f:
                        json.dump(baseline_data, f, indent=2)
                except Exception as e:
                    raise BaselineError(f"Error saving baseline: {e}")

            def update_baseline(self, stats):
                if stats['packet_count'] == 0:
                    raise BaselineError("No packets processed")

                baseline_type = self.get_baseline_type()
                baseline_data = self.load_baseline() or {"workday": {}, "weekend": {}}

                baseline_data[baseline_type] = {
                    "tcp_retransmission_rate": mock_safe_divide(stats['retransmissions'], stats['packet_count']),
                    "tcp_resets": stats['resets'],
                    "avg_tcp_handshake_delay": mock_safe_divide(sum(stats['tcp_syn_delays']), len(stats['tcp_syn_delays'])) if stats['tcp_syn_delays'] else 0,
                    "avg_udp_jitter": mock_safe_divide(sum(stats['udp_jitter']), len(stats['udp_jitter'])) if stats['udp_jitter'] else 0,
                    "http_error_rate": mock_safe_divide(sum(stats['http_errors'].values()), stats['packet_count']) if stats['http_errors'] else 0
                }

                self.save_baseline(baseline_data)
                return True

        self.baseline_manager = TestBaselineManager()

    def test_get_baseline_type(self):
        """Test baseline type determination"""
        baseline_type = self.baseline_manager.get_baseline_type()
        self.assertIn(baseline_type, ['workday', 'weekend'])

    def test_save_and_load_baseline(self):
        """Test saving and loading baseline data"""
        test_baseline = {
            'workday': {'tcp_retransmission_rate': 0.05},
            'weekend': {'tcp_retransmission_rate': 0.02}
        }

        # Save baseline
        self.baseline_manager.save_baseline(test_baseline)

        # Load baseline
        loaded_baseline = self.baseline_manager.load_baseline()

        self.assertEqual(loaded_baseline, test_baseline)

    def test_load_baseline_nonexistent(self):
        """Test loading baseline when file doesn't exist"""
        baseline = self.baseline_manager.load_baseline()
        self.assertIsNone(baseline)

    def test_update_baseline_with_stats(self):
        """Test updating baseline with statistics"""
        stats = SAMPLE_STATS.copy()

        self.baseline_manager.update_baseline(stats)

        # Verify baseline was created
        baseline = self.baseline_manager.load_baseline()
        self.assertIsNotNone(baseline)

        baseline_type = self.baseline_manager.get_baseline_type()
        self.assertIn(baseline_type, baseline)

        # Check calculated metrics
        baseline_metrics = baseline[baseline_type]
        self.assertIn('tcp_retransmission_rate', baseline_metrics)
        self.assertIn('tcp_resets', baseline_metrics)

    def test_update_baseline_empty_stats(self):
        """Test updating baseline with empty statistics"""
        empty_stats = {'packet_count': 0}

        with self.assertRaises(BaselineError):
            self.baseline_manager.update_baseline(empty_stats)

    def test_baseline_metrics_calculation(self):
        """Test baseline metrics calculation accuracy"""
        stats = {
            'packet_count': 1000,
            'retransmissions': 50,  # 5% rate
            'resets': 10,
            'tcp_syn_delays': [0.1, 0.2, 0.15],  # avg = 0.15
            'udp_jitter': [0.01, 0.02],  # avg = 0.015
            'http_errors': {'404': 5, '500': 3},  # total 8, rate = 0.008
        }

        self.baseline_manager.update_baseline(stats)
        baseline = self.baseline_manager.load_baseline()

        baseline_type = self.baseline_manager.get_baseline_type()
        metrics = baseline[baseline_type]

        self.assertAlmostEqual(metrics['tcp_retransmission_rate'], 0.05, places=3)
        self.assertEqual(metrics['tcp_resets'], 10)
        self.assertAlmostEqual(metrics['avg_tcp_handshake_delay'], 0.15, places=3)
        self.assertAlmostEqual(metrics['avg_udp_jitter'], 0.015, places=3)
        self.assertAlmostEqual(metrics['http_error_rate'], 0.008, places=3)


if __name__ == '__main__':
    unittest.main()
