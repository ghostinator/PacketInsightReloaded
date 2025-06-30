#!/usr/bin/env python3
"""
Packet Insight Core Analytics Engine
Extracted from packet_insight.py for better modularity and testability
"""

import json
import os
import time
import logging
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Union
from tqdm import tqdm
import pyshark
from pathlib import Path

from .exceptions import PacketInsightError, CaptureError, AnalysisError, BaselineError
from .config import PacketInsightConfig
from .utils import get_tshark_path, safe_divide

logger = logging.getLogger(__name__)


class PacketAnalyzer:
    """Core packet analysis engine with proper error handling and type hints"""

    def __init__(self, config: Optional[PacketInsightConfig] = None):
        self.config = config or PacketInsightConfig()
        self.logger = logging.getLogger(__name__)
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Configure logging for the analyzer"""
        logging.basicConfig(
            level=getattr(logging, self.config.get('log_level', 'INFO')),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    def initialize_stats(self) -> Dict[str, Any]:
        """Initialize statistics dictionary with proper typing"""
        return {
            'packet_count': 0,
            'total_bytes': 0,
            'start_time': time.time(),
            'start_timestamp': float('inf'),
            'end_timestamp': 0,
            'retransmissions': 0,
            'resets': 0,
            'dns_issues': 0,
            'http_errors': defaultdict(int),
            'tcp_syn_delays': [],
            'udp_jitter': [],
            'top_talkers': defaultdict(int),
            'protocols': defaultdict(int),
            'conversations': defaultdict(int),
            'throughput_samples': [],
            'prev_udp_time': {},
            'malformed_packets': 0,
            # TLS stats
            'tls_handshakes': 0,
            'tls_versions': defaultdict(int),
            'tls_cipher_suites': defaultdict(int),
            'tls_alerts': 0,
            'expired_certs': [],
            'self_signed_certs': [],
            # DNS stats
            'dns_queries': defaultdict(int),
            'dns_response_times': [],
            'dns_record_types': defaultdict(int),
            'pending_dns_queries': {},
            # DHCP stats
            'dhcp_servers': defaultdict(int),
            'dhcp_discover': 0,
            'dhcp_offer': 0,
            'dhcp_request': 0,
            'dhcp_ack': 0,
            'dhcp_nak': 0
        }

    def update_stats(self, stats: Dict[str, Any], packet: Any) -> None:
        """Update statistics with packet data"""
        try:
            stats['packet_count'] += 1
            current_time = float(packet.sniff_timestamp)

            # Update time range
            stats['start_timestamp'] = min(stats['start_timestamp'], current_time)
            stats['end_timestamp'] = max(stats['end_timestamp'], current_time)

            # Update packet size
            if hasattr(packet, 'length'):
                packet_size = int(packet.length)
                stats['total_bytes'] += packet_size
                stats['throughput_samples'].append((current_time, packet_size))

            # Update protocols
            protocol = packet.transport_layer or packet.highest_layer
            stats['protocols'][protocol] += 1

            # IP layer analysis
            if 'IP' in packet:
                self._analyze_ip_layer(stats, packet, current_time)

            # TCP diagnostics
            if 'TCP' in packet:
                self._analyze_tcp_layer(stats, packet, current_time)

            # UDP diagnostics
            if 'UDP' in packet:
                self._analyze_udp_layer(stats, packet, current_time)

            # Application layer analysis
            if 'HTTP' in packet:
                self._analyze_http_layer(stats, packet)

            if 'TLS' in packet:
                self._analyze_tls_layer(stats, packet)

            if 'DNS' in packet:
                self._analyze_dns_layer(stats, packet, current_time)

            if 'DHCP' in packet or 'BOOTP' in packet:
                self._analyze_dhcp_layer(stats, packet)

        except Exception as e:
            self.logger.debug(f"Error processing packet: {e}")
            stats['malformed_packets'] += 1

    def _analyze_ip_layer(self, stats: Dict[str, Any], packet: Any, current_time: float) -> None:
        """Analyze IP layer information"""
        try:
            src, dst = packet.ip.src, packet.ip.dst
            stats['top_talkers'][src] += 1
            stats['top_talkers'][dst] += 1
            stats['conversations'][(src, dst)] += 1
        except AttributeError as e:
            self.logger.debug(f"IP layer analysis error: {e}")

    def _analyze_tcp_layer(self, stats: Dict[str, Any], packet: Any, current_time: float) -> None:
        """Analyze TCP layer information"""
        try:
            if hasattr(packet.tcp, 'analysis_retransmission'):
                stats['retransmissions'] += 1
            if 'RST' in str(packet.tcp.flags):
                stats['resets'] += 1
            if 'SYN' in str(packet.tcp.flags) and not hasattr(packet.tcp, 'analysis_acks_frame'):
                stats['tcp_syn_delays'].append(current_time)
        except AttributeError as e:
            self.logger.debug(f"TCP layer analysis error: {e}")

    def _analyze_udp_layer(self, stats: Dict[str, Any], packet: Any, current_time: float) -> None:
        """Analyze UDP layer information"""
        try:
            if 'IP' in packet:
                flow_key = (packet.ip.src, packet.ip.dst, packet.udp.srcport, packet.udp.dstport)
                if flow_key in stats['prev_udp_time']:
                    stats['udp_jitter'].append(current_time - stats['prev_udp_time'][flow_key])
                stats['prev_udp_time'][flow_key] = current_time
        except AttributeError as e:
            self.logger.debug(f"UDP layer analysis error: {e}")

    def _analyze_http_layer(self, stats: Dict[str, Any], packet: Any) -> None:
        """Analyze HTTP layer information"""
        try:
            if hasattr(packet.http, 'response_code'):
                code = packet.http.response_code
                if code.startswith(('4', '5')):
                    stats['http_errors'][code] += 1
        except AttributeError as e:
            self.logger.debug(f"HTTP layer analysis error: {e}")

    def _analyze_tls_layer(self, stats: Dict[str, Any], packet: Any) -> None:
        """Analyze TLS/SSL layer information"""
        try:
            # Check for handshake records
            if hasattr(packet.tls, 'record_content_type') and packet.tls.record_content_type == '22':
                stats['tls_handshakes'] += 1

            # Extract TLS version and cipher from Server Hello
            if hasattr(packet.tls, 'handshake_type') and packet.tls.handshake_type == '2':
                if hasattr(packet.tls, 'handshake_version'):
                    stats['tls_versions'][packet.tls.handshake_version] += 1
                if hasattr(packet.tls, 'handshake_ciphersuite'):
                    stats['tls_cipher_suites'][packet.tls.handshake_ciphersuite] += 1

            # Check for alerts
            if hasattr(packet.tls, 'record_content_type') and packet.tls.record_content_type == '21':
                stats['tls_alerts'] += 1

        except AttributeError as e:
            self.logger.debug(f"TLS layer analysis error: {e}")

    def _analyze_dns_layer(self, stats: Dict[str, Any], packet: Any, current_time: float) -> None:
        """Analyze DNS layer information"""
        try:
            # Basic DNS issues tracking
            if packet.dns.flags_response == '0' and not hasattr(packet.dns, 'response_time'):
                stats['dns_issues'] += 1

            # Track query types and names
            if hasattr(packet.dns, 'qry_name'):
                stats['dns_queries'][packet.dns.qry_name] += 1
                stats['dns_record_types'][packet.dns.qry_type] += 1

            # Handle query/response timing
            if packet.dns.flags_response == '0':  # Query
                query_id = packet.dns.id
                stats['pending_dns_queries'][query_id] = current_time
            elif packet.dns.flags_response == '1':  # Response
                query_id = packet.dns.id
                if query_id in stats['pending_dns_queries']:
                    response_time = current_time - stats['pending_dns_queries'].pop(query_id)
                    stats['dns_response_times'].append(response_time)

        except AttributeError as e:
            self.logger.debug(f"DNS layer analysis error: {e}")

    def _analyze_dhcp_layer(self, stats: Dict[str, Any], packet: Any) -> None:
        """Analyze DHCP layer information"""
        try:
            if hasattr(packet, 'dhcp') and hasattr(packet.dhcp, 'option_dhcp_message_type'):
                dhcp_type = packet.dhcp.option_dhcp_message_type

                if dhcp_type == '1':  # Discover
                    stats['dhcp_discover'] += 1
                elif dhcp_type == '2':  # Offer
                    stats['dhcp_offer'] += 1
                    if 'IP' in packet:
                        stats['dhcp_servers'][packet.ip.src] += 1
                elif dhcp_type == '3':  # Request
                    stats['dhcp_request'] += 1
                elif dhcp_type == '5':  # ACK
                    stats['dhcp_ack'] += 1
                elif dhcp_type == '6':  # NAK
                    stats['dhcp_nak'] += 1

        except AttributeError as e:
            self.logger.debug(f"DHCP layer analysis error: {e}")

    def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """Analyze a PCAP file and return network statistics"""
        if not os.path.exists(pcap_path):
            raise CaptureError(f"PCAP file not found: {pcap_path}")

        stats = self.initialize_stats()
        cap = None

        try:
            # Create pyshark capture object
            cap = pyshark.FileCapture(
                pcap_path,
                display_filter='tcp || udp || icmp || dns || http || dhcp || bootp || tls',
                only_summaries=False,
                custom_parameters=['-s 128'],
                debug=False,
                keep_packets=False
            )

            # Process all packets
            all_packets = list(cap)

            for packet in tqdm(all_packets, desc="Processing packets", unit="pkt"):
                self.update_stats(stats, packet)

        except pyshark.capture.capture.TSharkCrashException as e:
            raise CaptureError(f"TShark crashed while processing {pcap_path}: {e}")
        except FileNotFoundError as e:
            raise CaptureError(f"Required tools not found: {e}")
        except PermissionError as e:
            raise CaptureError(f"Permission denied accessing {pcap_path}: {e}")
        except Exception as e:
            raise AnalysisError(f"Unexpected error analyzing {pcap_path}: {e}")
        finally:
            # Clean up capture object
            if cap:
                try:
                    # Safe cleanup to avoid event loop issues
                    def noop(*args, **kwargs):
                        pass
                    cap.close = noop
                    cap = None
                except Exception as e:
                    self.logger.debug(f"Error closing capture: {e}")

        # Clean up non-serializable data
        self._cleanup_stats(stats)
        return stats

    def _cleanup_stats(self, stats: Dict[str, Any]) -> None:
        """Clean up statistics for serialization"""
        # Remove non-serializable data
        if 'prev_udp_time' in stats:
            del stats['prev_udp_time']

        # Convert conversations dictionary to use string keys
        if 'conversations' in stats:
            conversations = {}
            for k, v in stats['conversations'].items():
                if isinstance(k, tuple):
                    new_key = "_".join(str(item) for item in k)
                    conversations[new_key] = v
                else:
                    conversations[k] = v
            stats['conversations'] = conversations


class BaselineManager:
    """Manages baseline data for network analysis"""

    def __init__(self, baseline_path: str = "network_baselines.json"):
        self.baseline_path = Path(baseline_path)
        self.logger = logging.getLogger(__name__)

    def get_baseline_type(self) -> str:
        """Determine baseline type based on current time"""
        now = datetime.now()
        return "workday" if now.weekday() < 5 else "weekend"

    def load_baseline(self) -> Optional[Dict[str, Dict[str, float]]]:
        """Load baseline data from file"""
        try:
            if self.baseline_path.exists():
                with open(self.baseline_path, 'r') as f:
                    return json.load(f)
            return None
        except (json.JSONDecodeError, IOError) as e:
            raise BaselineError(f"Error loading baseline from {self.baseline_path}: {e}")

    def save_baseline(self, baseline_data: Dict[str, Dict[str, float]]) -> None:
        """Save baseline data to file"""
        try:
            # Ensure parent directory exists
            self.baseline_path.parent.mkdir(parents=True, exist_ok=True)

            # Atomic write to prevent corruption
            temp_path = self.baseline_path.with_suffix('.tmp')
            with open(temp_path, 'w') as f:
                json.dump(baseline_data, f, indent=2)

            # Atomic move
            temp_path.replace(self.baseline_path)

        except (IOError, OSError) as e:
            raise BaselineError(f"Error saving baseline to {self.baseline_path}: {e}")

    def update_baseline(self, stats: Dict[str, Any]) -> bool:
        """Update baseline from analysis statistics"""
        try:
            if stats['packet_count'] == 0:
                raise BaselineError("No packets processed. Cannot create baseline.")

            baseline_type = self.get_baseline_type()
            baseline_data = self.load_baseline() or {"workday": {}, "weekend": {}}

            # Calculate metrics with safety checks
            baseline_data[baseline_type] = {
                "tcp_retransmission_rate": safe_divide(stats['retransmissions'], stats['packet_count']),
                "tcp_resets": stats['resets'],
                "avg_tcp_handshake_delay": (
                    safe_divide(sum(stats['tcp_syn_delays']), len(stats['tcp_syn_delays']))
                    if stats['tcp_syn_delays'] else 0
                ),
                "avg_udp_jitter": (
                    safe_divide(sum(stats['udp_jitter']), len(stats['udp_jitter']))
                    if stats['udp_jitter'] else 0
                ),
                "http_error_rate": safe_divide(sum(stats['http_errors'].values()), stats['packet_count'])
            }

            self.save_baseline(baseline_data)
            self.logger.info(f"{baseline_type.capitalize()} baseline updated")
            return True

        except Exception as e:
            self.logger.error(f"Failed to update baseline: {e}")
            return False
