#!/usr/bin/env python3
"""
Report Generation Module for Packet Insight
Handles console output and file export in various formats
"""

import os
import json
import csv
import time
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

from .config import PacketInsightConfig
from .exceptions import ExportError
from .utils import format_bytes, format_duration, format_throughput, safe_divide

import logging

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates reports in various formats from analysis statistics"""

    def __init__(self, config: Optional[PacketInsightConfig] = None):
        self.config = config or PacketInsightConfig()

    def generate_console_report(self, stats: Dict[str, Any]) -> None:
        """Generate formatted analysis report for console output"""
        try:
            # Calculate metrics
            processing_time = time.time() - stats['start_time']
            capture_duration = stats['end_timestamp'] - stats['start_timestamp']
            avg_packet_size = safe_divide(stats['total_bytes'], stats['packet_count'])
            throughput = safe_divide(stats['total_bytes'] * 8, capture_duration) if capture_duration > 0 else 0

            # Print report header
            print(f"\n[✓] Analysis completed in {processing_time:.2f}s")
            print(f"\n## Network Summary [Packets: {stats['packet_count']} | Duration: {capture_duration:.2f}s]")
            print(f"- Total Data: {format_bytes(stats['total_bytes'])}")
            print(f"- Avg Packet Size: {avg_packet_size:.0f} bytes")
            print(f"- Estimated Throughput: {format_throughput(stats['total_bytes'], capture_duration)}")

            if stats['malformed_packets'] > 0:
                print(f"- Malformed Packets: {stats['malformed_packets']} ({stats['malformed_packets']/stats['packet_count']:.1%})")

            # Protocol distribution
            self._print_protocol_distribution(stats)

            # Network issues
            self._print_network_issues(stats)

            # Connection quality metrics
            self._print_quality_metrics(stats)

            # Critical warnings
            self._print_critical_warnings(stats)

            # TLS/SSL Analysis
            self._print_tls_analysis(stats)

            # DNS Analysis
            self._print_dns_analysis(stats)

            # DHCP Analysis
            self._print_dhcp_analysis(stats)

            # Top talkers and conversations
            self._print_top_talkers(stats)
            self._print_conversations(stats)

        except Exception as e:
            logger.error(f"Error generating console report: {e}")
            raise ExportError(f"Failed to generate console report: {e}")

    def _print_protocol_distribution(self, stats: Dict[str, Any]) -> None:
        """Print protocol distribution section"""
        print("\n### Protocol Distribution")
        for proto, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:10]:
            percentage = safe_divide(count, stats['packet_count']) * 100
            print(f"- {proto}: {count} packets ({percentage:.1f}%)")

    def _print_network_issues(self, stats: Dict[str, Any]) -> None:
        """Print network issues section"""
        print("\n### Network Issues")
        print(f"- TCP Retransmissions: {stats['retransmissions']}")
        print(f"- TCP Resets: {stats['resets']}")
        print(f"- DNS Timeouts/Failures: {stats['dns_issues']}")

        if stats['http_errors']:
            total_http_errors = sum(stats['http_errors'].values())
            print(f"- HTTP Errors: {total_http_errors} total")
            for code, count in stats['http_errors'].items():
                print(f"  • {code}: {count} errors")

    def _print_quality_metrics(self, stats: Dict[str, Any]) -> None:
        """Print connection quality metrics"""
        if stats['tcp_syn_delays']:
            avg_delay = safe_divide(sum(stats['tcp_syn_delays']), len(stats['tcp_syn_delays']))
            print(f"- Avg TCP Handshake Delay: {avg_delay:.4f}s")
            if avg_delay > self.config.get('syn_delay_threshold', 0.5):
                print(f"  ⚠️ WARNING: High SYN delay (>{self.config.get('syn_delay_threshold', 0.5)}s)")

        if stats['udp_jitter']:
            avg_jitter = safe_divide(sum(stats['udp_jitter']), len(stats['udp_jitter']))
            print(f"- Avg UDP Jitter: {avg_jitter:.4f}s")
            if avg_jitter > self.config.get('high_jitter_threshold', 0.1):
                print(f"  ⚠️ WARNING: High jitter (>{self.config.get('high_jitter_threshold', 0.1)}s)")

    def _print_critical_warnings(self, stats: Dict[str, Any]) -> None:
        """Print critical warnings"""
        retrans_threshold = self.config.get('retransmission_threshold', 0.05)
        if stats['retransmissions'] > stats['packet_count'] * retrans_threshold:
            rate = safe_divide(stats['retransmissions'], stats['packet_count'])
            print(f"\n⚠️ CRITICAL: High retransmission rate ({rate:.1%} > {retrans_threshold:.0%} threshold)")

    def _print_tls_analysis(self, stats: Dict[str, Any]) -> None:
        """Print TLS/SSL analysis"""
        if stats['tls_handshakes'] > 0:
            print("\n### TLS/SSL Analysis")
            print(f"- Total TLS Handshakes: {stats['tls_handshakes']}")
            print(f"- TLS Alerts: {stats['tls_alerts']}")

            if stats['tls_versions']:
                print("- TLS Versions Detected:")
                version_map = {
                    '0x0301': 'TLS 1.0', '0x0302': 'TLS 1.1',
                    '0x0303': 'TLS 1.2', '0x0304': 'TLS 1.3'
                }
                for version, count in stats['tls_versions'].items():
                    version_name = version_map.get(version, f"Unknown ({version})")
                    warning = "⚠️ (Insecure)" if version in ['0x0301', '0x0302'] else ""
                    print(f"  • {version_name}: {count} handshakes {warning}")

            if stats['expired_certs']:
                print("  ⚠️ WARNING: Expired Certificates Found:")
                for ip in set(stats['expired_certs']):
                    print(f"    - Server: {ip}")

            if stats['self_signed_certs']:
                print("  ⚠️ WARNING: Self-Signed Certificates Found:")
                for ip in set(stats['self_signed_certs']):
                    print(f"    - Server: {ip}")

    def _print_dns_analysis(self, stats: Dict[str, Any]) -> None:
        """Print DNS analysis"""
        if stats['dns_queries']:
            print("\n### DNS Analysis")

            # Performance
            if stats['dns_response_times']:
                avg_dns_response = safe_divide(sum(stats['dns_response_times']), len(stats['dns_response_times']))
                max_dns_response = max(stats['dns_response_times'])
                print(f"- Avg DNS Response Time: {avg_dns_response:.4f}s (Max: {max_dns_response:.4f}s)")
                if avg_dns_response > 0.2:
                    print("  ⚠️ WARNING: High average DNS response time (>0.2s)")

            # Top Queried Domains
            if stats['dns_queries']:
                print("- Top 5 Queried Domains:")
                sorted_queries = sorted(stats['dns_queries'].items(), key=lambda item: item[1], reverse=True)
                for domain, count in sorted_queries[:5]:
                    print(f"  • {domain}: {count} queries")

            # Record Types
            if stats['dns_record_types']:
                print("- Query Types Distribution:")
                record_type_map = {
                    '1': 'A (IPv4)', '28': 'AAAA (IPv6)', '5': 'CNAME',
                    '15': 'MX', '16': 'TXT', '6': 'SOA', '2': 'NS'
                }
                for record_type, count in stats['dns_record_types'].items():
                    type_name = record_type_map.get(record_type, f"Type {record_type}")
                    print(f"  • {type_name}: {count} queries")

    def _print_dhcp_analysis(self, stats: Dict[str, Any]) -> None:
        """Print DHCP analysis"""
        if stats['dhcp_discover'] > 0 or stats['dhcp_offer'] > 0:
            print("\n### DHCP Analysis")
            print(f"- DHCP Process: {stats['dhcp_discover']} Discovers, {stats['dhcp_offer']} Offers, "
                  f"{stats['dhcp_request']} Requests, {stats['dhcp_ack']} ACKs, {stats['dhcp_nak']} NAKs")

            # Success rate
            if stats['dhcp_discover'] > 0:
                success_rate = safe_divide(stats['dhcp_ack'], stats['dhcp_discover'])
                print(f"- DHCP Success Rate: {success_rate:.1%}")
                if success_rate < 0.9 and stats['dhcp_discover'] > 5:
                    print("  ⚠️ WARNING: Low DHCP success rate (<90%)")

            # Multiple DHCP servers
            if len(stats['dhcp_servers']) > 1:
                print("  ⚠️ WARNING: Multiple DHCP servers detected:")
                for server_ip, count in stats['dhcp_servers'].items():
                    print(f"    - {server_ip}: {count} offers")

    def _print_top_talkers(self, stats: Dict[str, Any]) -> None:
        """Print top talkers"""
        print("\n### Top 15 Talkers")
        sorted_talkers = sorted(stats['top_talkers'].items(), key=lambda x: x[1], reverse=True)[:15]
        for ip, count in sorted_talkers:
            print(f"- {ip}: {count} packets")

    def _print_conversations(self, stats: Dict[str, Any]) -> None:
        """Print top conversations"""
        print("\n### Top 5 Conversations")
        sorted_convos = sorted(stats['conversations'].items(), key=lambda x: x[1], reverse=True)[:5]
        for convo, count in sorted_convos:
            if isinstance(convo, str) and "_" in convo:
                parts = convo.split("_")
                if len(parts) >= 2:
                    print(f"- {parts[0]} ↔ {parts[1]}: {count} packets")
            elif isinstance(convo, tuple) and len(convo) >= 2:
                print(f"- {convo[0]} ↔ {convo[1]}: {count} packets")
            else:
                print(f"- {convo}: {count} packets")

    def export_report(self, stats: Dict[str, Any], format_type: str, 
                     output_path: Optional[str] = None) -> str:
        """Export analysis results in the specified format"""
        try:
            if format_type == 'json':
                return self._export_json(stats, output_path)
            elif format_type == 'csv':
                return self._export_csv(stats, output_path)
            elif format_type == 'html':
                return self._export_html(stats, output_path)
            else:
                raise ExportError(f"Unsupported export format: {format_type}")
        except Exception as e:
            logger.error(f"Export error: {e}")
            raise ExportError(f"Failed to export {format_type} report: {e}")

    def _export_json(self, stats: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Export analysis results as JSON"""
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = self.config.get('default_output_dir', 'reports')
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, f"packet_insight_report_{timestamp}.json")

        # Prepare serializable stats
        serializable_stats = self._prepare_for_serialization(stats)

        # Add metadata
        serializable_stats['metadata'] = {
            'generated_at': datetime.now().isoformat(),
            'app_version': '2.0.0',
            'report_type': 'packet_analysis'
        }

        with open(output_path, 'w') as f:
            json.dump(serializable_stats, f, indent=2)

        return output_path

    def _export_csv(self, stats: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Export analysis results as CSV"""
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = self.config.get('default_output_dir', 'reports')
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, f"packet_insight_report_{timestamp}.csv")

        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)

            # Write header
            writer.writerow(['Category', 'Metric', 'Value'])

            # Basic metrics
            writer.writerow(['Basic', 'Packet Count', stats['packet_count']])
            writer.writerow(['Basic', 'Total Bytes', stats['total_bytes']])
            writer.writerow(['Basic', 'Duration (s)', stats['end_timestamp'] - stats['start_timestamp']])

            # Issues
            writer.writerow(['Issues', 'TCP Retransmissions', stats['retransmissions']])
            writer.writerow(['Issues', 'TCP Resets', stats['resets']])
            writer.writerow(['Issues', 'DNS Issues', stats['dns_issues']])
            writer.writerow(['Issues', 'Malformed Packets', stats['malformed_packets']])

            # Protocol distribution
            for proto, count in stats['protocols'].items():
                writer.writerow(['Protocols', proto, count])

            # Top talkers
            sorted_talkers = sorted(stats['top_talkers'].items(), key=lambda x: x[1], reverse=True)[:15]
            for ip, count in sorted_talkers:
                writer.writerow(['Top Talkers', ip, count])

        return output_path

    def _export_html(self, stats: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Export analysis results as HTML"""
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = self.config.get('default_output_dir', 'reports')
            os.makedirs(output_dir, exist_ok=True)
            output_path = os.path.join(output_dir, f"packet_insight_report_{timestamp}.html")

        # Generate HTML content
        html_content = self._generate_html_content(stats)

        with open(output_path, 'w') as f:
            f.write(html_content)

        return output_path

    def _generate_html_content(self, stats: Dict[str, Any]) -> str:
        """Generate HTML content for the report"""
        capture_duration = stats['end_timestamp'] - stats['start_timestamp']
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Packet Insight Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .metric {{ margin: 10px 0; }}
        .warning {{ color: #ff6600; }}
        .critical {{ color: #ff0000; font-weight: bold; }}
        table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Packet Insight Report</h1>
        <p>Generated on {timestamp}</p>
    </div>

    <h2>Summary</h2>
    <div class="metric">Packets Analyzed: {stats['packet_count']:,}</div>
    <div class="metric">Total Data: {format_bytes(stats['total_bytes'])}</div>
    <div class="metric">Duration: {format_duration(capture_duration)}</div>
    <div class="metric">Throughput: {format_throughput(stats['total_bytes'], capture_duration)}</div>

    <h2>Protocol Distribution</h2>
    <table>
        <tr><th>Protocol</th><th>Packets</th><th>Percentage</th></tr>"""

        for protocol, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:10]:
            percentage = safe_divide(count, stats['packet_count']) * 100
            html += f"<tr><td>{protocol}</td><td>{count:,}</td><td>{percentage:.2f}%</td></tr>"

        html += """
    </table>

    <h2>Issues</h2>"""

        if stats['retransmissions'] > stats['packet_count'] * self.config.get('retransmission_threshold', 0.05):
            rate = safe_divide(stats['retransmissions'], stats['packet_count'])
            html += f'<div class="critical">High retransmission rate: {rate:.1%}</div>'

        html += f"""
    <div class="metric">TCP Retransmissions: {stats['retransmissions']}</div>
    <div class="metric">TCP Resets: {stats['resets']}</div>
    <div class="metric">DNS Issues: {stats['dns_issues']}</div>
    <div class="metric">Malformed Packets: {stats['malformed_packets']}</div>

    <h2>Top Talkers</h2>
    <table>
        <tr><th>IP Address</th><th>Packets</th></tr>"""

        sorted_talkers = sorted(stats['top_talkers'].items(), key=lambda x: x[1], reverse=True)[:15]
        for ip, count in sorted_talkers:
            html += f"<tr><td>{ip}</td><td>{count:,}</td></tr>"

        html += """
    </table>

    <footer>
        <p>Generated by Packet Insight v2.0.0</p>
    </footer>
</body>
</html>"""

        return html

    def _prepare_for_serialization(self, obj) -> Any:
        """Convert objects to JSON-serializable format"""
        if isinstance(obj, dict):
            result = {}
            for k, v in obj.items():
                if isinstance(k, tuple):
                    new_key = "_".join(str(item) for item in k)
                else:
                    new_key = str(k)
                result[new_key] = self._prepare_for_serialization(v)
            return result
        elif isinstance(obj, list):
            return [self._prepare_for_serialization(item) for item in obj]
        elif isinstance(obj, (datetime,)):
            return obj.isoformat()
        elif hasattr(obj, '__dict__'):
            return self._prepare_for_serialization(obj.__dict__)
        else:
            return obj
