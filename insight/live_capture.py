#!/usr/bin/env python3
"""
Live Capture Management for Packet Insight
Handles live packet capture with proper error handling and resource management
"""

import os
import sys
import time
import datetime
import subprocess
import threading
from pathlib import Path
from typing import Optional, List
import logging

from .config import PacketInsightConfig
from .exceptions import CaptureError, InterfaceError
from .utils import get_tshark_path, validate_interface, extract_device_name

logger = logging.getLogger(__name__)


class LiveCaptureManager:
    """Manages live packet capture operations"""

    def __init__(self, config: Optional[PacketInsightConfig] = None):
        self.config = config or PacketInsightConfig()
        self.capture_process: Optional[subprocess.Popen] = None
        self.is_capturing = False

    def start_capture(self, interface: str, duration: Optional[int] = None, 
                     output_file: Optional[str] = None, 
                     packet_limit: Optional[int] = None,
                     capture_filter: str = "") -> str:
        """Start a live capture on the specified interface"""
        try:
            # Validate interface
            device_name = extract_device_name(interface)
            if not validate_interface(device_name):
                raise InterfaceError(f"Interface not found or inactive: {device_name}")

            # Get tshark path
            tshark_path = get_tshark_path()

            # Generate output filename if not provided
            if not output_file:
                output_file = self._generate_capture_filename(device_name)

            # Ensure output directory exists
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            # Build capture command
            cmd = self._build_capture_command(
                tshark_path, device_name, output_file, 
                duration, packet_limit, capture_filter
            )

            # Show capture information
            self._print_capture_info(device_name, duration, packet_limit, output_file)

            # Start capture
            self._execute_capture(cmd, output_file)

            return output_file

        except Exception as e:
            logger.error(f"Capture failed: {e}")
            raise CaptureError(f"Failed to start capture: {e}")

    def _generate_capture_filename(self, interface: str) -> str:
        """Generate a filename for the capture file"""
        safe_interface = interface.replace(' ', '_').replace('(', '').replace(')', '').replace('/', '_')
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"live_capture_{safe_interface}_{timestamp}.pcap"

    def _build_capture_command(self, tshark_path: str, interface: str, 
                              output_file: str, duration: Optional[int],
                              packet_limit: Optional[int], 
                              capture_filter: str) -> List[str]:
        """Build the tshark capture command"""
        cmd = [tshark_path, '-i', interface, '-w', output_file]

        # Add duration if specified
        if duration:
            cmd.extend(['-a', f'duration:{duration}'])

        # Add packet limit if specified
        if packet_limit:
            cmd.extend(['-c', str(packet_limit)])

        # Add capture filter if specified
        if capture_filter:
            cmd.extend(['-f', capture_filter])

        # Add packet snapshot length for efficiency
        cmd.extend(['-s', '128'])

        return cmd

    def _print_capture_info(self, interface: str, duration: Optional[int],
                           packet_limit: Optional[int], output_file: str) -> None:
        """Print capture information"""
        print(f"\nStarting capture:")
        print(f"  Interface: {interface}")
        print(f"  Output file: {output_file}")

        if duration:
            print(f"  Duration: {duration} seconds")
        if packet_limit:
            print(f"  Packet limit: {packet_limit}")

        print(f"  Press Ctrl+C to stop capture manually")
        print()

    def _execute_capture(self, cmd: List[str], output_file: str) -> None:
        """Execute the capture command"""
        try:
            self.is_capturing = True
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            # Wait for capture to complete
            stdout, stderr = self.capture_process.wait(), ""

            if self.capture_process.returncode != 0:
                # Get error output
                _, stderr = self.capture_process.communicate()
                raise CaptureError(f"tshark failed: {stderr}")

            print(f"\n[✓] Capture completed. Saved to {output_file}")

            # Verify output file exists and has content
            if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                raise CaptureError("Capture file is empty or was not created")

        except KeyboardInterrupt:
            print("\n[!] Capture stopped by user")
            self._stop_capture()
        except subprocess.TimeoutExpired:
            print("\n[!] Capture timed out")
            self._stop_capture()
            raise CaptureError("Capture operation timed out")
        finally:
            self.is_capturing = False

    def _stop_capture(self) -> None:
        """Stop the current capture process"""
        if self.capture_process and self.capture_process.poll() is None:
            try:
                self.capture_process.terminate()
                # Give process time to terminate gracefully
                try:
                    self.capture_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    self.capture_process.kill()
                    self.capture_process.wait()
            except Exception as e:
                logger.warning(f"Error stopping capture process: {e}")

    def start_rolling_capture(self, interface: str, 
                             rolling_size_mb: Optional[int] = None,
                             rolling_interval_min: Optional[int] = None,
                             max_files: int = 10) -> List[str]:
        """Start rolling capture with file rotation"""
        try:
            device_name = extract_device_name(interface)
            if not validate_interface(device_name):
                raise InterfaceError(f"Interface not found or inactive: {device_name}")

            capture_files = []
            file_count = 0

            print(f"Starting rolling capture on {device_name}")
            if rolling_size_mb:
                print(f"  - New file every {rolling_size_mb}MB")
            if rolling_interval_min:
                print(f"  - New file every {rolling_interval_min} minutes")
            print(f"  - Maximum {max_files} files")

            while file_count < max_files:
                # Generate filename for this segment
                output_file = self._generate_rolling_filename(device_name, file_count)

                # Determine capture duration for this segment
                segment_duration = rolling_interval_min * 60 if rolling_interval_min else None

                print(f"\nStarting capture segment {file_count + 1}/{max_files}")

                # Start capture for this segment
                try:
                    result_file = self.start_capture(
                        interface=device_name,
                        duration=segment_duration,
                        output_file=output_file
                    )

                    capture_files.append(result_file)
                    file_count += 1

                    # Check file size if size-based rolling is enabled
                    if rolling_size_mb:
                        file_size_mb = os.path.getsize(result_file) / (1024 * 1024)
                        if file_size_mb < rolling_size_mb * 0.8:  # If significantly under limit
                            print(f"Warning: Capture file only {file_size_mb:.1f}MB")

                except KeyboardInterrupt:
                    print("\nRolling capture stopped by user")
                    break
                except Exception as e:
                    logger.error(f"Error in rolling capture segment {file_count + 1}: {e}")
                    break

            print(f"\n[✓] Rolling capture completed. Created {len(capture_files)} files:")
            for file in capture_files:
                file_size = os.path.getsize(file) / (1024 * 1024)
                print(f"  - {file} ({file_size:.1f}MB)")

            return capture_files

        except Exception as e:
            logger.error(f"Rolling capture failed: {e}")
            raise CaptureError(f"Rolling capture failed: {e}")

    def _generate_rolling_filename(self, interface: str, segment: int) -> str:
        """Generate filename for rolling capture segment"""
        safe_interface = interface.replace(' ', '_').replace('(', '').replace(')', '').replace('/', '_')
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"rolling_capture_{safe_interface}_{timestamp}_part{segment:03d}.pcap"

    def check_capture_prerequisites(self) -> bool:
        """Check if capture prerequisites are met"""
        try:
            # Check if tshark is available
            tshark_path = get_tshark_path()

            # Test tshark execution
            result = subprocess.run(
                [tshark_path, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                return False

            # Check for required permissions (platform-specific)
            return self._check_capture_permissions()

        except Exception as e:
            logger.debug(f"Prerequisites check failed: {e}")
            return False

    def _check_capture_permissions(self) -> bool:
        """Check if the user has necessary permissions for packet capture"""
        import platform

        system = platform.system()

        if system == "Linux":
            # Check if running as root or if user has cap_net_raw capability
            return os.geteuid() == 0 or self._check_linux_capabilities()
        elif system == "Darwin":  # macOS
            # On macOS, check if user is in admin group or running as root
            return os.geteuid() == 0 or self._check_macos_permissions()
        elif system == "Windows":
            # On Windows, check if running as administrator
            return self._check_windows_admin()
        else:
            # Unknown platform, assume permissions are OK
            return True

    def _check_linux_capabilities(self) -> bool:
        """Check Linux capabilities for packet capture"""
        try:
            # Check if user has cap_net_raw capability
            result = subprocess.run(
                ['getcap', '/usr/bin/dumpcap'],
                capture_output=True,
                text=True
            )
            return 'cap_net_raw' in result.stdout
        except:
            return False

    def _check_macos_permissions(self) -> bool:
        """Check macOS permissions for packet capture"""
        try:
            # Check if user is in admin group
            result = subprocess.run(
                ['groups'],
                capture_output=True,
                text=True
            )
            return 'admin' in result.stdout
        except:
            return False

    def _check_windows_admin(self) -> bool:
        """Check if running as Windows administrator"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def get_capture_status(self) -> dict:
        """Get current capture status"""
        return {
            'is_capturing': self.is_capturing,
            'process_id': self.capture_process.pid if self.capture_process else None,
            'prerequisites_ok': self.check_capture_prerequisites()
        }

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure cleanup"""
        if self.is_capturing:
            self._stop_capture()
