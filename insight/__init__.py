"""
Packet Insight - Advanced PCAP Analysis for Support Engineers

A comprehensive toolkit for network packet analysis with enhanced modularity,
comprehensive testing, and production-ready error handling.
"""

from .version import __version__, __version_info__
from .core import PacketAnalyzer, BaselineManager
from .config import PacketInsightConfig
from .exceptions import PacketInsightError, CaptureError, AnalysisError
from .utils import get_tshark_path, get_active_interfaces, safe_divide

__all__ = [
    "__version__",
    "__version_info__",
    "PacketAnalyzer",
    "BaselineManager", 
    "PacketInsightConfig",
    "PacketInsightError",
    "CaptureError",
    "AnalysisError",
    "get_tshark_path",
    "get_active_interfaces",
    "safe_divide",
]
