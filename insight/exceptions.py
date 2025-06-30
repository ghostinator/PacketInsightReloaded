#!/usr/bin/env python3
"""
Custom exceptions for Packet Insight
Provides specific exception types for better error handling and debugging
"""

class PacketInsightError(Exception):
    """Base exception class for Packet Insight"""
    pass


class CaptureError(PacketInsightError):
    """Raised when packet capture operations fail"""
    pass


class AnalysisError(PacketInsightError):
    """Raised when packet analysis operations fail"""
    pass


class ConfigurationError(PacketInsightError):
    """Raised when configuration is invalid or missing"""
    pass


class BaselineError(PacketInsightError):
    """Raised when baseline operations fail"""
    pass


class InterfaceError(PacketInsightError):
    """Raised when network interface operations fail"""
    pass


class ExportError(PacketInsightError):
    """Raised when report export operations fail"""
    pass


class TelemetryError(PacketInsightError):
    """Raised when telemetry operations fail"""
    pass
