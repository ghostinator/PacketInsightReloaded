#!/usr/bin/env python3
"""
Consolidated Utility Functions for Packet Insight
Eliminates code duplication and provides cross-platform helpers
"""

import os
import sys
import platform
import subprocess
import logging
from typing import List, Optional, Dict, Union
from pathlib import Path

import netifaces

from .exceptions import InterfaceError, CaptureError

logger = logging.getLogger(__name__)


def safe_divide(numerator: Union[int, float], denominator: Union[int, float]) -> float:
    """Safe division with zero handling and proper typing"""
    if denominator == 0:
        return 0.0
    return float(numerator) / float(denominator)


def get_tshark_path() -> str:
    """Find tshark executable with cross-platform support and proper error handling"""
    system = platform.system()

    # Common paths by platform
    common_paths = {
        "Windows": [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe"
        ],
        "Darwin": [
            "/Applications/Wireshark.app/Contents/MacOS/tshark",
            "/usr/local/bin/tshark"
        ],
        "Linux": [
            "/usr/bin/tshark",
            "/usr/local/bin/tshark"
        ]
    }

    # Check if tshark is in PATH first
    try:
        subprocess.run(["tshark", "-v"], check=True, 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return "tshark"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Check PyInstaller bundle path
    if getattr(sys, 'frozen', False):
        bundle_dir = sys._MEIPASS
        if system == "Windows":
            bundled_path = os.path.join(bundle_dir, 'tshark', 'tshark.exe')
            if os.path.exists(bundled_path):
                return bundled_path

    # Check platform-specific paths
    for path in common_paths.get(system, []):
        if os.path.exists(path):
            return path

    raise CaptureError("tshark not found. Please ensure Wireshark is installed.")


def get_active_interfaces() -> List[str]:
    """Detect active network interfaces with IP addresses cross-platform"""
    active_interfaces = []
    system = platform.system()

    try:
        if system == "Windows":
            active_interfaces = _get_windows_interfaces()
        elif system == "Linux":
            active_interfaces = _get_linux_interfaces()
        elif system == "Darwin":  # macOS
            active_interfaces = _get_macos_interfaces()
        else:
            # Fallback to netifaces for unknown platforms
            active_interfaces = _get_netifaces_interfaces()

    except Exception as e:
        logger.error(f"Error detecting interfaces: {e}")
        raise InterfaceError(f"Failed to detect network interfaces: {e}")

    if not active_interfaces:
        raise InterfaceError("No active network interfaces found")

    return active_interfaces


def _get_windows_interfaces() -> List[str]:
    """Get active Windows network interfaces"""
    active_interfaces = []

    try:
        # Use tshark to list interfaces
        tshark_path = get_tshark_path()
        result = subprocess.run([tshark_path, "-D"], capture_output=True, text=True, check=True)
        interfaces = result.stdout.splitlines()

        # Parse tshark output
        for iface in interfaces:
            if " (" in iface and ")" in iface:
                # Extract interface name from "1. \Device\NPF_{GUID} (Ethernet)"
                name = iface.split("(", 1)[1].split(")", 1)[0].strip()
                active_interfaces.append(name)

    except Exception:
        # Fallback to netsh
        try:
            result = subprocess.run(["netsh", "interface", "show", "interface"], 
                                  capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if "Connected" in line and "Dedicated" in line:
                    parts = line.split()
                    if len(parts) > 3:
                        active_interfaces.append(" ".join(parts[3:]))
        except Exception as e:
            logger.debug(f"Netsh fallback failed: {e}")

    return active_interfaces


def _get_linux_interfaces() -> List[str]:
    """Get active Linux network interfaces"""
    active_interfaces = []

    try:
        # Preferred method: netifaces
        active_interfaces = _get_netifaces_interfaces()
    except ImportError:
        # Fallback to ip command
        try:
            result = subprocess.run(["ip", "-o", "link", "show"], 
                                  capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if "state UP" in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        iface = parts[1].strip().split('@')[0]
                        active_interfaces.append(iface)
        except Exception as e:
            logger.debug(f"IP command fallback failed: {e}")

    return active_interfaces


def _get_macos_interfaces() -> List[str]:
    """Get active macOS network interfaces with friendly names"""
    active_interfaces = []

    try:
        # Get mapping of device names to friendly names
        name_map = get_macos_interface_names()
        result = subprocess.run(["ifconfig"], capture_output=True, text=True, check=True)
        current_if = None

        for line in result.stdout.splitlines():
            if not line.startswith('\t') and ':' in line:
                current_if = line.split(':')[0]
            if current_if and "inet " in line and "127.0.0.1" not in line:
                if current_if not in active_interfaces:
                    active_interfaces.append(current_if)

        # Attach friendly names for display
        interface_display = []
        for iface in active_interfaces:
            friendly = name_map.get(iface, "")
            if friendly:
                interface_display.append(f"{iface} ({friendly})")
            else:
                interface_display.append(iface)

        return interface_display

    except Exception as e:
        logger.debug(f"macOS interface detection failed: {e}")
        # Fallback to netifaces
        return _get_netifaces_interfaces()


def _get_netifaces_interfaces() -> List[str]:
    """Get active interfaces using netifaces library"""
    active_interfaces = []

    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs or netifaces.AF_INET6 in addrs:
                active_interfaces.append(iface)
    except Exception as e:
        logger.debug(f"Netifaces detection failed: {e}")

    return active_interfaces


def get_macos_interface_names() -> Dict[str, str]:
    """Return a dict mapping device names (en0) to human-friendly names (Wi-Fi, USB Ethernet, etc)"""
    if platform.system() != 'Darwin':
        return {}

    try:
        output = subprocess.check_output(['networksetup', '-listallhardwareports'], text=True)
        lines = output.splitlines()
        mapping = {}
        current_port = None

        for line in lines:
            if line.startswith('Hardware Port:'):
                current_port = line.split(':', 1)[1].strip()
            elif line.startswith('Device:') and current_port:
                device = line.split(':', 1)[1].strip()
                mapping[device] = current_port
                current_port = None

        return mapping
    except Exception as e:
        logger.debug(f"Failed to get macOS interface names: {e}")
        return {}


def extract_device_name(interface_display_name: str) -> str:
    """Extract device name from display string (e.g., 'en11 (USB LAN)' -> 'en11')"""
    return interface_display_name.split(' (', 1)[0]


def detect_primary_interface() -> str:
    """Automatically detect primary network interface"""
    system = platform.system()

    try:
        if system == "Darwin":  # macOS
            result = subprocess.run(["route", "-n", "get", "default"], 
                                  capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if "interface:" in line:
                    return line.split()[-1]
        elif system == "Linux":
            result = subprocess.run(["ip", "route", "show", "default"], 
                                  capture_output=True, text=True, check=True)
            if result.stdout:
                return result.stdout.split()[4]
    except Exception as e:
        logger.debug(f"Primary interface detection failed: {e}")

    # Fallback
    return "en0" if system == "Darwin" else "eth0"


def validate_interface(interface: str) -> bool:
    """Validate that an interface exists and is active"""
    try:
        active_interfaces = get_active_interfaces()
        # Check both exact match and extracted device name
        for active_iface in active_interfaces:
            if interface == active_iface or interface == extract_device_name(active_iface):
                return True
        return False
    except Exception:
        return False


def format_bytes(bytes_value: Union[int, float]) -> str:
    """Format bytes into human-readable format"""
    if bytes_value < 1024:
        return f"{bytes_value:.0f} bytes"
    elif bytes_value < 1024 * 1024:
        return f"{bytes_value / 1024:.2f} KB"
    elif bytes_value < 1024 * 1024 * 1024:
        return f"{bytes_value / (1024 * 1024):.2f} MB"
    else:
        return f"{bytes_value / (1024 * 1024 * 1024):.2f} GB"


def format_duration(seconds: Union[int, float]) -> str:
    """Format duration in seconds to human-readable format"""
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.2f} hours"


def format_throughput(bytes_value: Union[int, float], seconds: Union[int, float]) -> str:
    """Calculate and format throughput"""
    if seconds <= 0:
        return "N/A"

    bits_per_second = (bytes_value * 8) / seconds

    if bits_per_second < 1000:
        return f"{bits_per_second:.2f} bps"
    elif bits_per_second < 1000 * 1000:
        return f"{bits_per_second / 1000:.2f} Kbps"
    elif bits_per_second < 1000 * 1000 * 1000:
        return f"{bits_per_second / (1000 * 1000):.2f} Mbps"
    else:
        return f"{bits_per_second / (1000 * 1000 * 1000):.2f} Gbps"


def is_pyinstaller_bundle() -> bool:
    """Check if running as a PyInstaller bundle"""
    return getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')


def get_bundle_dir() -> Optional[Path]:
    """Get the PyInstaller bundle directory if running as a bundle"""
    if is_pyinstaller_bundle():
        return Path(sys._MEIPASS)
    return None


def setup_pyshark():
    """Set up pyshark configuration for bundled environments"""
    if is_pyinstaller_bundle():
        try:
            import pyshark
            tshark_path = get_tshark_path()
            pyshark.config.config.set_tshark_path(tshark_path)
            logger.info(f"Set tshark path to: {tshark_path}")
        except Exception as e:
            logger.warning(f"Failed to configure pyshark: {e}")
