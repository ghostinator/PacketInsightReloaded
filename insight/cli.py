#!/usr/bin/env python3
"""
Packet Insight CLI - Thin wrapper around core analytics engine
Refactored for better separation of concerns and testability
"""

import argparse
import sys
import os
from pathlib import Path
from typing import Optional, List

from .core import PacketAnalyzer, BaselineManager
from .config import PacketInsightConfig
from .exceptions import PacketInsightError, CaptureError, AnalysisError, ConfigurationError
from .utils import get_active_interfaces, extract_device_name, detect_primary_interface
from .telemetry import TelemetryManager
from .report import ReportGenerator
from .live_capture import LiveCaptureManager
from .version import __version__

import logging

logger = logging.getLogger(__name__)


class PacketInsightCLI:
    """Main CLI application class with proper separation of concerns"""

    def __init__(self):
        self.config: Optional[PacketInsightConfig] = None
        self.analyzer: Optional[PacketAnalyzer] = None
        self.baseline_manager: Optional[BaselineManager] = None
        self.telemetry: Optional[TelemetryManager] = None
        self.report_generator: Optional[ReportGenerator] = None

    def setup(self, config_path: Optional[str] = None) -> None:
        """Initialize CLI components with configuration"""
        try:
            # Load configuration
            self.config = PacketInsightConfig.from_file(config_path)

            # Setup logging
            self._setup_logging()

            # Initialize components
            self.analyzer = PacketAnalyzer(self.config)
            self.baseline_manager = BaselineManager()
            self.report_generator = ReportGenerator(self.config)

            # Initialize telemetry if enabled
            if self.config.get('telemetry_enabled', False):
                self.telemetry = TelemetryManager(self.config)

        except ConfigurationError as e:
            print(f"Configuration error: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Initialization error: {e}")
            sys.exit(1)

    def _setup_logging(self) -> None:
        """Configure application logging"""
        log_level = getattr(logging, self.config.get('log_level', 'INFO'))
        log_file = self.config.get('log_file')

        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename=log_file
        )

        if self.config.get('enable_debug_mode', False):
            logging.getLogger().setLevel(logging.DEBUG)

    def run_analysis(self, pcap_file: str, output_format: str = 'text', 
                    output_file: Optional[str] = None) -> None:
        """Run analysis on a PCAP file"""
        try:
            if self.telemetry:
                self.telemetry.record_feature_usage('pcap_analysis')

            # Verify file exists
            if not os.path.exists(pcap_file):
                raise CaptureError(f"PCAP file not found: {pcap_file}")

            print(f"Analyzing {pcap_file}...")

            # Analyze PCAP
            stats = self.analyzer.analyze_pcap(pcap_file)

            # Generate report
            if output_format == 'text':
                self.report_generator.generate_console_report(stats)
            else:
                report_file = self.report_generator.export_report(
                    stats, output_format, output_file
                )
                print(f"Report saved to: {report_file}")

            # Record performance metrics
            if self.telemetry:
                self.telemetry.record_performance_metric(
                    'analysis_packet_count', stats['packet_count'], 'packets'
                )

        except (CaptureError, AnalysisError) as e:
            if self.telemetry:
                self.telemetry.record_error(type(e).__name__, str(e))
            print(f"Analysis error: {e}")
            sys.exit(1)
        except Exception as e:
            if self.telemetry:
                self.telemetry.record_error(type(e).__name__, str(e))
            print(f"Unexpected error: {e}")
            sys.exit(1)

    def run_live_capture(self, interface: Optional[str] = None, 
                        duration: int = 60, output_format: str = 'text') -> None:
        """Run live packet capture and analysis"""
        try:
            if self.telemetry:
                self.telemetry.record_feature_usage('live_capture')

            # Auto-detect interface if not specified
            if not interface:
                interfaces = get_active_interfaces()
                if not interfaces:
                    raise CaptureError("No active interfaces found")
                interface = self._prompt_interface_selection(interfaces)

            print(f"Starting live capture on {interface} for {duration} seconds...")

            # Initialize live capture manager
            live_manager = LiveCaptureManager(self.config)

            # Start capture and analysis
            capture_file = live_manager.start_capture(interface, duration)
            if capture_file:
                # Analyze captured data
                stats = self.analyzer.analyze_pcap(capture_file)

                # Generate report
                if output_format == 'text':
                    self.report_generator.generate_console_report(stats)
                else:
                    self.report_generator.export_report(stats, output_format)

        except (CaptureError, AnalysisError) as e:
            if self.telemetry:
                self.telemetry.record_error(type(e).__name__, str(e))
            print(f"Live capture error: {e}")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\nCapture stopped by user.")
        except Exception as e:
            if self.telemetry:
                self.telemetry.record_error(type(e).__name__, str(e))
            print(f"Unexpected error: {e}")
            sys.exit(1)

    def interactive_mode(self) -> None:
        """Launch interactive mode for troubleshooting"""
        try:
            if self.telemetry:
                self.telemetry.record_feature_usage('interactive_mode')

            print("\n" + "="*50)
            print("Packet Insight - Network Diagnostics")
            print("="*50)

            # Check for existing baseline
            baseline = self.baseline_manager.load_baseline()
            baseline_exists = baseline and any(baseline.values())

            while True:
                self._show_main_menu()
                choice = input("\nEnter your choice: ").strip()

                if choice == "1":
                    self._handle_capture_baseline()
                elif choice == "2":
                    self._handle_analyze_pcap()
                elif choice == "3":
                    self._handle_live_capture()
                elif choice == "4":
                    self._handle_view_baseline()
                elif choice == "5":
                    self._handle_clear_baseline()
                elif choice == "6":
                    self._handle_manage_config()
                elif choice == "7":
                    self._handle_telemetry_settings()
                elif choice == "8":
                    print("Exiting...")
                    break
                else:
                    print("[!] Invalid choice")

                input("\nPress Enter to continue...")

        except KeyboardInterrupt:
            print("\nExiting...")
        except Exception as e:
            if self.telemetry:
                self.telemetry.record_error(type(e).__name__, str(e))
            print(f"Interactive mode error: {e}")

    def _show_main_menu(self) -> None:
        """Display the main menu options"""
        print("\nOptions:")
        print("1. Capture new baseline")
        print("2. Analyze existing PCAP file")
        print("3. Capture and analyze live traffic")
        print("4. View current baseline")
        print("5. Clear baseline")
        print("6. Manage configuration")
        print("7. Telemetry settings")
        print("8. Exit")

    def _handle_capture_baseline(self) -> None:
        """Handle baseline capture option"""
        duration = int(input("Capture duration (seconds) [60]: ") or 60)
        filename = input("Output filename [baseline.pcap]: ") or "baseline.pcap"

        interfaces = get_active_interfaces()
        if not interfaces:
            print("⚠️ No active interfaces found!")
            return

        interface = self._prompt_interface_selection(interfaces)

        # Start capture
        live_manager = LiveCaptureManager(self.config)
        captured_file = live_manager.start_capture(interface, duration, filename)

        if captured_file:
            print("\n[+] Creating baseline from capture...")
            stats = self.analyzer.analyze_pcap(captured_file)
            self.baseline_manager.update_baseline(stats)

    def _handle_analyze_pcap(self) -> None:
        """Handle PCAP analysis option"""
        pcap_file = input("Path to PCAP file: ").strip()
        if not os.path.exists(pcap_file):
            print(f"[!] File not found: {pcap_file}")
            return

        # Ask for output format
        format_choice = self._prompt_output_format()

        # Analyze the file
        stats = self.analyzer.analyze_pcap(pcap_file)

        # Generate report
        if format_choice == 'text':
            self.report_generator.generate_console_report(stats)
        else:
            self.report_generator.export_report(stats, format_choice)

        # Offer to save as baseline
        if input("\nSave as baseline? [y/N]: ").lower() == 'y':
            self.baseline_manager.update_baseline(stats)

    def _handle_live_capture(self) -> None:
        """Handle live capture option"""
        duration = int(input("Capture duration (seconds) [60]: ") or 60)
        format_choice = self._prompt_output_format()

        interfaces = get_active_interfaces()
        if not interfaces:
            print("⚠️ No active interfaces found!")
            return

        interface = self._prompt_interface_selection(interfaces)
        self.run_live_capture(interface, duration, format_choice)

    def _handle_view_baseline(self) -> None:
        """Handle view baseline option"""
        baseline = self.baseline_manager.load_baseline()
        if baseline and any(baseline.values()):
            print("\nCurrent Baseline Values:")
            for period, metrics in baseline.items():
                print(f"\n{period.capitalize()}:")
                for metric, value in metrics.items():
                    print(f"  - {metric}: {value:.4f}")
        else:
            print("\nNo baseline established yet")

    def _handle_clear_baseline(self) -> None:
        """Handle clear baseline option"""
        if self.baseline_manager.baseline_path.exists():
            self.baseline_manager.baseline_path.unlink()
            print("[✓] Baseline cleared")
        else:
            print("[!] Baseline file not found")

    def _handle_manage_config(self) -> None:
        """Handle configuration management"""
        print("\nConfiguration Management:")
        print("1. Export current configuration")
        print("2. Import configuration from file")
        print("3. Reset to defaults")

        choice = input("Select option: ").strip()

        if choice == "1":
            output_path = input("Output path [packet_insight.yaml]: ") or "packet_insight.yaml"
            self.config.save_to_file(output_path)
            print(f"Configuration exported to {output_path}")
        elif choice == "2":
            config_path = input("Path to configuration file: ").strip()
            if os.path.exists(config_path):
                new_config = PacketInsightConfig.from_file(config_path)
                self.config = new_config
                print(f"Configuration imported from {config_path}")
            else:
                print(f"File not found: {config_path}")
        elif choice == "3":
            self.config.reset_to_defaults()
            print("Configuration reset to defaults")

    def _handle_telemetry_settings(self) -> None:
        """Handle telemetry settings"""
        if not self.telemetry:
            print("\nTelemetry is currently disabled.")
            if input("Enable telemetry? [y/N]: ").lower() == 'y':
                self.telemetry = TelemetryManager(self.config)
                self.telemetry.enable_telemetry()
                print("\nTelemetry enabled. Privacy notice:")
                print(self.telemetry.get_privacy_notice())
        else:
            print("\nTelemetry Settings:")
            print("1. View privacy notice")
            print("2. Export my data")
            print("3. Clear my data")
            print("4. Disable telemetry")

            choice = input("Select option: ").strip()

            if choice == "1":
                print(self.telemetry.get_privacy_notice())
            elif choice == "2":
                data = self.telemetry.export_data()
                print(f"\nYour telemetry data: {data}")
            elif choice == "3":
                self.telemetry.clear_data()
                print("Telemetry data cleared")
            elif choice == "4":
                self.telemetry.disable_telemetry()
                self.telemetry = None
                print("Telemetry disabled")

    def _prompt_interface_selection(self, interfaces: List[str]) -> str:
        """Prompt user to select a network interface"""
        if len(interfaces) == 1:
            print(f"Using interface: {interfaces[0]}")
            return extract_device_name(interfaces[0])

        print("\nAvailable interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")

        while True:
            try:
                selection = int(input("Select interface number: "))
                if 1 <= selection <= len(interfaces):
                    selected = interfaces[selection - 1]
                    print(f"Using interface: {selected}")
                    return extract_device_name(selected)
                else:
                    print("Invalid selection. Please enter a valid number.")
            except ValueError:
                print("Please enter a number.")

    def _prompt_output_format(self) -> str:
        """Prompt user to select output format"""
        print("\nOutput format options:")
        print("1. Text (console output)")
        print("2. JSON file")
        print("3. CSV file")
        print("4. HTML report")

        choice = input("Select format [1]: ").strip() or "1"

        format_map = {
            "1": "text",
            "2": "json", 
            "3": "csv",
            "4": "html"
        }

        return format_map.get(choice, "text")


def main():
    """Main entry point for the CLI application"""
    parser = argparse.ArgumentParser(
        description='Packet Insight - Advanced PCAP Analysis for Support Engineers',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  packet-insight capture.pcap                    # Analyze PCAP file
  packet-insight --live --interface eth0         # Live capture on eth0
  packet-insight --interactive                   # Interactive mode
  packet-insight --config config.yaml file.pcap # Use custom config
        """
    )

    # Positional arguments
    parser.add_argument('pcap_file', nargs='?', help='Path to PCAP file to analyze')

    # Mode selection
    parser.add_argument('--interactive', action='store_true', 
                       help='Launch interactive mode')
    parser.add_argument('--live', action='store_true', 
                       help='Perform live capture instead of analyzing a file')

    # Configuration
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--export-config', help='Export configuration to specified file')

    # Live capture options
    parser.add_argument('--interface', help='Network interface for live capture')
    parser.add_argument('--duration', type=int, default=60, 
                       help='Duration in seconds for live capture')

    # Output options
    parser.add_argument('--format', choices=['text', 'json', 'csv', 'html'], 
                       default='text', help='Output format for analysis results')
    parser.add_argument('--output', help='Output file path for reports')

    # Utility options
    parser.add_argument('--list-interfaces', action='store_true',
                       help='List available network interfaces')
    parser.add_argument('--version', action='version', 
                    version=f'Packet Insight {__version__}')


    args = parser.parse_args()

    # Initialize CLI
    cli = PacketInsightCLI()
    cli.setup(args.config)

    try:
        # Handle utility commands
        if args.export_config:
            cli.config.save_to_file(args.export_config)
            print(f"Configuration exported to {args.export_config}")
            return

        if args.list_interfaces:
            interfaces = get_active_interfaces()
            print("Available network interfaces:")
            for i, iface in enumerate(interfaces, 1):
                print(f"  {i}. {iface}")
            return

        # Handle main functionality
        if args.interactive or (not args.pcap_file and not args.live):
            cli.interactive_mode()
        elif args.live:
            cli.run_live_capture(args.interface, args.duration, args.format)
        elif args.pcap_file:
            cli.run_analysis(args.pcap_file, args.format, args.output)
        else:
            parser.print_help()

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        logger.exception("Unhandled exception in main")
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
