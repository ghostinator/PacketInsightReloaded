#!/usr/bin/env python3
"""
Anonymous Telemetry Module for Packet Insight
Provides opt-in anonymous usage analytics to improve the product
"""

import json
import hashlib
import platform
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List
import logging
import threading
import urllib.request
import urllib.parse
import urllib.error

from .config import PacketInsightConfig
from .exceptions import TelemetryError
from .version import __version__, __api_version__

logger = logging.getLogger(__name__)


class TelemetryManager:
    """Manages anonymous telemetry data collection and transmission"""

    def __init__(self, config: PacketInsightConfig):
        self.config = config
        self.enabled = config.get('telemetry_enabled', False)
        self.endpoint = config.get('telemetry_endpoint', 'https://api.packetinsight.local/v1/telemetry')
        self.interval_hours = config.get('telemetry_interval_hours', 24)

        # Paths for telemetry data
        self.data_dir = Path.home() / '.packet_insight'
        self.data_dir.mkdir(exist_ok=True)

        self.session_file = self.data_dir / 'session.json'
        self.telemetry_file = self.data_dir / 'telemetry.json'
        self.user_id_file = self.data_dir / 'user_id'

        # Initialize session
        self.session_id = self._generate_session_id()
        self.user_id = self._get_or_create_user_id()

        # Initialize telemetry data
        self.telemetry_data = self._load_telemetry_data()

        # Background thread for periodic sending
        self._sender_thread = None
        self._stop_event = threading.Event()

        if self.enabled:
            self._start_background_sender()

    def _generate_session_id(self) -> str:
        """Generate a unique session identifier"""
        return str(uuid.uuid4())

    def _get_or_create_user_id(self) -> str:
        """Get or create an anonymous user identifier"""
        if self.user_id_file.exists():
            try:
                return self.user_id_file.read_text().strip()
            except Exception as e:
                logger.debug(f"Error reading user ID: {e}")

        # Create new anonymous user ID
        user_id = str(uuid.uuid4())
        try:
            self.user_id_file.write_text(user_id)
        except Exception as e:
            logger.debug(f"Error saving user ID: {e}")

        return user_id

    def _load_telemetry_data(self) -> Dict[str, Any]:
        """Load existing telemetry data or create new"""
        if self.telemetry_file.exists():
            try:
                with open(self.telemetry_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.debug(f"Error loading telemetry data: {e}")

        return {
            'sessions': [],
            'feature_usage': {},
            'performance_metrics': {},
            'error_counts': {},
            'last_sent': None
        }

    def _save_telemetry_data(self) -> None:
        """Save telemetry data to file"""
        try:
            with open(self.telemetry_file, 'w') as f:
                json.dump(self.telemetry_data, f, indent=2)
        except Exception as e:
            logger.debug(f"Error saving telemetry data: {e}")

    def enable_telemetry(self) -> None:
        """Enable telemetry collection"""
        self.enabled = True
        self.config.set('telemetry_enabled', True)
        self._start_background_sender()
        logger.info("Telemetry enabled")

    def disable_telemetry(self) -> None:
        """Disable telemetry collection"""
        self.enabled = False
        self.config.set('telemetry_enabled', False)
        self._stop_background_sender()
        logger.info("Telemetry disabled")

    def record_session_start(self) -> None:
        """Record the start of a new session"""
        if not self.enabled:
            return

        session_data = {
            'session_id': self.session_id,
            'start_time': datetime.now().isoformat(),
            'platform': platform.system(),
            'python_version': platform.python_version(),
            'app_version': __version__,
            'features_used': []
        }

        self.telemetry_data['sessions'].append(session_data)
        self._save_telemetry_data()

    def record_session_end(self) -> None:
        """Record the end of the current session"""
        if not self.enabled:
            return

        # Find current session and update end time
        for session in self.telemetry_data['sessions']:
            if session['session_id'] == self.session_id:
                session['end_time'] = datetime.now().isoformat()
                break

        self._save_telemetry_data()

    def record_feature_usage(self, feature: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Record usage of a specific feature"""
        if not self.enabled:
            return

        if feature not in self.telemetry_data['feature_usage']:
            self.telemetry_data['feature_usage'][feature] = {
                'count': 0,
                'first_used': datetime.now().isoformat(),
                'last_used': datetime.now().isoformat()
            }

        self.telemetry_data['feature_usage'][feature]['count'] += 1
        self.telemetry_data['feature_usage'][feature]['last_used'] = datetime.now().isoformat()

        # Add to current session
        for session in self.telemetry_data['sessions']:
            if session['session_id'] == self.session_id:
                if feature not in session['features_used']:
                    session['features_used'].append(feature)
                break

        self._save_telemetry_data()

    def record_performance_metric(self, metric: str, value: float, unit: str = 'ms') -> None:
        """Record a performance metric"""
        if not self.enabled:
            return

        if metric not in self.telemetry_data['performance_metrics']:
            self.telemetry_data['performance_metrics'][metric] = {
                'values': [],
                'unit': unit,
                'count': 0,
                'sum': 0.0,
                'min': float('inf'),
                'max': 0.0
            }

        metrics = self.telemetry_data['performance_metrics'][metric]
        metrics['values'].append(value)
        metrics['count'] += 1
        metrics['sum'] += value
        metrics['min'] = min(metrics['min'], value)
        metrics['max'] = max(metrics['max'], value)

        # Keep only last 100 values to limit storage
        if len(metrics['values']) > 100:
            metrics['values'] = metrics['values'][-100:]

        self._save_telemetry_data()

    def record_error(self, error_type: str, error_message: str) -> None:
        """Record an error occurrence"""
        if not self.enabled:
            return

        # Hash the error message to anonymize it
        error_hash = hashlib.sha256(error_message.encode()).hexdigest()[:16]

        if error_type not in self.telemetry_data['error_counts']:
            self.telemetry_data['error_counts'][error_type] = {}

        if error_hash not in self.telemetry_data['error_counts'][error_type]:
            self.telemetry_data['error_counts'][error_type][error_hash] = {
                'count': 0,
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat()
            }

        self.telemetry_data['error_counts'][error_type][error_hash]['count'] += 1
        self.telemetry_data['error_counts'][error_type][error_hash]['last_seen'] = datetime.now().isoformat()

        self._save_telemetry_data()

    def _start_background_sender(self) -> None:
        """Start background thread for periodic telemetry transmission"""
        if self._sender_thread and self._sender_thread.is_alive():
            return

        self._stop_event.clear()
        self._sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
        self._sender_thread.start()

    def _stop_background_sender(self) -> None:
        """Stop background telemetry sender"""
        self._stop_event.set()
        if self._sender_thread and self._sender_thread.is_alive():
            self._sender_thread.join(timeout=5)

    def _sender_loop(self) -> None:
        """Background loop for sending telemetry data"""
        while not self._stop_event.is_set():
            try:
                if self._should_send_telemetry():
                    self._send_telemetry()
            except Exception as e:
                logger.debug(f"Telemetry sender error: {e}")

            # Wait for interval or stop event
            self._stop_event.wait(self.interval_hours * 3600)

    def _should_send_telemetry(self) -> bool:
        """Check if it's time to send telemetry data"""
        if not self.enabled:
            return False

        last_sent = self.telemetry_data.get('last_sent')
        if not last_sent:
            return True

        try:
            last_sent_time = datetime.fromisoformat(last_sent)
            return datetime.now() - last_sent_time > timedelta(hours=self.interval_hours)
        except Exception:
            return True

    def _send_telemetry(self) -> None:
        """Send telemetry data to the endpoint"""
        try:
            payload = self._prepare_payload()
            self._transmit_payload(payload)
            self.telemetry_data['last_sent'] = datetime.now().isoformat()
            self._save_telemetry_data()
            logger.debug("Telemetry data sent successfully")
        except Exception as e:
            raise TelemetryError(f"Failed to send telemetry: {e}")

    def _prepare_payload(self) -> Dict[str, Any]:
        """Prepare telemetry payload for transmission"""
        return {
            'user_id': self.user_id,
            'api_version': __api_version__,
            'app_version': __version__,
            'platform': platform.system(),
            'python_version': platform.python_version(),
            'timestamp': datetime.now().isoformat(),
            'data': self.telemetry_data
        }

    def _transmit_payload(self, payload: Dict[str, Any]) -> None:
        """Transmit payload to telemetry endpoint"""
        data = json.dumps(payload).encode('utf-8')

        req = urllib.request.Request(
            self.endpoint,
            data=data,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': f'PacketInsight/{__version__}'
            }
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status != 200:
                    raise TelemetryError(f"HTTP {response.status}: {response.reason}")
        except urllib.error.URLError as e:
            raise TelemetryError(f"Network error: {e}")

    def force_send(self) -> None:
        """Force immediate transmission of telemetry data"""
        if not self.enabled:
            raise TelemetryError("Telemetry is disabled")

        self._send_telemetry()

    def export_data(self) -> Dict[str, Any]:
        """Export all telemetry data for user review"""
        return {
            'user_id': self.user_id,
            'session_id': self.session_id,
            'telemetry_data': self.telemetry_data,
            'config': {
                'enabled': self.enabled,
                'endpoint': self.endpoint,
                'interval_hours': self.interval_hours
            }
        }

    def clear_data(self) -> None:
        """Clear all stored telemetry data"""
        self.telemetry_data = {
            'sessions': [],
            'feature_usage': {},
            'performance_metrics': {},
            'error_counts': {},
            'last_sent': None
        }
        self._save_telemetry_data()
        logger.info("Telemetry data cleared")

    def get_privacy_notice(self) -> str:
        """Get privacy notice explaining what data is collected"""
        return """
Packet Insight Privacy Notice
============================

This application collects anonymous usage analytics to help improve the product.
The following data is collected when telemetry is enabled:

• Anonymous user ID (randomly generated UUID)
• Session information (start/end times, features used)
• Performance metrics (analysis duration, packet counts)
• Error types and frequency (error messages are hashed)
• Platform information (OS, Python version, app version)

NO personal information, network data, or packet contents are collected.

You can:
• Enable/disable telemetry at any time
• Export and review your data
• Clear stored data

For more information, visit: https://packet-insight.readthedocs.io/privacy
        """.strip()

    def __enter__(self):
        """Context manager entry"""
        self.record_session_start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if exc_type:
            self.record_error(exc_type.__name__, str(exc_val))
        self.record_session_end()
