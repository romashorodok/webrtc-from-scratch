"""
WebRTC Logging System

Structured logging for WebRTC components with configurable verbosity.
"""

import sys
from datetime import datetime
from enum import Enum
from typing import Any, Optional

# Use StrEnum if available (Python 3.11+), otherwise fall back to str, Enum
try:
    from enum import StrEnum
except ImportError:
    # Python < 3.11 fallback
    class StrEnum(str, Enum):
        pass

from webrtc.config import DebugConfig, LogLevel


class Color:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    GRAY = '\033[90m'
    WHITE = '\033[97m'


class Component(StrEnum):
    """WebRTC component identifiers."""
    ICE = "ICE"
    DTLS = "DTLS"
    SDP = "SDP"
    SRTP = "SRTP"
    RTP = "RTP"
    RTCP = "RTCP"
    TRANSCEIVER = "Transceiver"
    PEER_CONNECTION = "PeerConnection"
    OPUS = "Opus"
    UDP = "UDP"
    STUN = "STUN"


class WebRTCLogger:
    """
    Structured logger for WebRTC components.

    Uses the DebugConfig singleton to determine what to log.
    """

    def __init__(self):
        self.config = DebugConfig.get()
        self._log_file = None

        if self.config.log_to_file:
            try:
                self._log_file = open(self.config.log_file_path, 'a')
            except Exception as e:
                print(f"Failed to open log file: {e}", file=sys.stderr)

    def _get_component_log_level(self, component: Component) -> LogLevel:
        """Get the configured log level for a component."""
        level_map = {
            Component.ICE: self.config.ice_log_level,
            Component.DTLS: self.config.dtls_log_level,
            Component.SDP: self.config.peer_connection_log_level,
            Component.SRTP: self.config.srtp_log_level,
            Component.RTP: self.config.rtp_log_level,
            Component.RTCP: self.config.rtcp_log_level,
            Component.TRANSCEIVER: self.config.transceiver_log_level,
            Component.PEER_CONNECTION: self.config.peer_connection_log_level,
            Component.OPUS: self.config.opus_log_level,
            Component.UDP: self.config.ice_log_level,  # UDP uses ICE level
            Component.STUN: self.config.ice_log_level,  # STUN uses ICE level
        }
        return level_map.get(component, LogLevel.INFO)

    def _should_log(self, component: Component, level: LogLevel) -> bool:
        """Check if a message should be logged based on component and level."""
        component_level = self._get_component_log_level(component)
        return level <= component_level

    def _format_prefix(self, component: Component, level: LogLevel) -> str:
        """Format the log prefix with component and level."""
        # Level symbols
        level_symbols = {
            LogLevel.ERROR: '✗',
            LogLevel.WARN: '⚠',
            LogLevel.INFO: '•',
            LogLevel.DEBUG: '→',
            LogLevel.TRACE: '·',
        }

        # Component colors
        component_colors = {
            Component.ICE: Color.CYAN,
            Component.DTLS: Color.GREEN,
            Component.SDP: Color.WHITE,
            Component.SRTP: Color.MAGENTA,
            Component.RTP: Color.BLUE,
            Component.RTCP: Color.BLUE,
            Component.TRANSCEIVER: Color.YELLOW,
            Component.PEER_CONNECTION: Color.WHITE,
            Component.OPUS: Color.MAGENTA,
            Component.UDP: Color.CYAN,
            Component.STUN: Color.CYAN,
        }

        # Level colors
        level_colors = {
            LogLevel.ERROR: Color.RED,
            LogLevel.WARN: Color.YELLOW,
            LogLevel.INFO: Color.WHITE,
            LogLevel.DEBUG: Color.GRAY,
            LogLevel.TRACE: Color.GRAY,
        }

        symbol = level_symbols.get(level, '•')
        component_str = component.value

        if self.config.use_colors:
            comp_color = component_colors.get(component, Color.WHITE)
            level_color = level_colors.get(level, Color.WHITE)

            # Format: [COMPONENT] symbol
            prefix = f"{comp_color}[{component_str:<{self.config.component_prefix_width}}]{Color.RESET} {level_color}{symbol}{Color.RESET}"
        else:
            prefix = f"[{component_str:<{self.config.component_prefix_width}}] {symbol}"

        return prefix

    def _log(self, component: Component, level: LogLevel, message: str, **kwargs):
        """Internal logging method."""
        if not self._should_log(component, level):
            return

        prefix = self._format_prefix(component, level)

        # Add extra context if provided
        extra_parts = []
        for key, value in kwargs.items():
            extra_parts.append(f"{key}={value}")

        extra = f" ({', '.join(extra_parts)})" if extra_parts else ""

        full_message = f"{prefix} {message}{extra}"

        # Print to stdout
        print(full_message)

        # Write to file if configured
        if self._log_file:
            timestamp = datetime.now().isoformat()
            # Strip colors for file output
            clean_message = self._strip_colors(full_message)
            self._log_file.write(f"{timestamp} {clean_message}\n")
            self._log_file.flush()

    def _strip_colors(self, text: str) -> str:
        """Remove ANSI color codes from text."""
        import re
        ansi_escape = re.compile(r'\033\[[0-9;]+m')
        return ansi_escape.sub('', text)

    # Convenience methods for each level
    def error(self, component: Component, message: str, **kwargs):
        """Log an error message."""
        self._log(component, LogLevel.ERROR, message, **kwargs)

    def warn(self, component: Component, message: str, **kwargs):
        """Log a warning message."""
        self._log(component, LogLevel.WARN, message, **kwargs)

    def info(self, component: Component, message: str, **kwargs):
        """Log an info message."""
        self._log(component, LogLevel.INFO, message, **kwargs)

    def debug(self, component: Component, message: str, **kwargs):
        """Log a debug message."""
        self._log(component, LogLevel.DEBUG, message, **kwargs)

    def trace(self, component: Component, message: str, **kwargs):
        """Log a trace message."""
        self._log(component, LogLevel.TRACE, message, **kwargs)

    # Packet logging helpers
    def log_packet(self, component: Component, direction: str, packet_num: int,
                   seq: Optional[int] = None, ssrc: Optional[int] = None,
                   size: Optional[int] = None, **kwargs):
        """
        Log packet information with automatic verbosity control.

        Args:
            component: Component logging the packet
            direction: "RX" or "TX"
            packet_num: Packet number in this component's sequence
            seq: RTP sequence number (optional)
            ssrc: SSRC (optional)
            size: Packet size in bytes (optional)
            **kwargs: Additional packet info
        """
        if not self.config.log_packet_details:
            return

        # Determine if we should log this packet
        should_log = (
            packet_num <= self.config.log_first_n_packets or
            packet_num % self.config.log_every_n_packets == 0
        )

        if not should_log:
            return

        # Build message
        parts = [f"{direction} packet #{packet_num}"]

        if seq is not None:
            parts.append(f"seq={seq}")
        if ssrc is not None:
            parts.append(f"ssrc={ssrc}")
        if size is not None:
            parts.append(f"size={size}B")

        message = ": ".join(parts)
        self.debug(component, message, **kwargs)

    def log_sequence_gap(self, component: Component, last_seq: int,
                        current_seq: int, gap: int):
        """Log a sequence number gap."""
        if not self.config.track_sequence_gaps:
            return

        level = LogLevel.WARN if self.config.warn_on_sequence_gaps else LogLevel.DEBUG
        message = f"SEQ GAP! last={last_seq}, current={current_seq}, gap={gap} packets"

        self._log(component, level, message)

    def log_queue_size(self, component: Component, queue_name: str,
                       size: int, maxsize: int):
        """Log queue size information."""
        if not self.config.log_queue_sizes:
            return

        fill_pct = (size / maxsize * 100) if maxsize > 0 else 0
        message = f"{queue_name}: {size}/{maxsize} ({fill_pct:.1f}%)"

        self.trace(component, message)

    def log_stats(self, component: Component, **stats):
        """Log statistics."""
        if not self.config.log_packet_counts:
            return

        parts = [f"{k}={v}" for k, v in stats.items()]
        message = "Stats: " + ", ".join(parts)

        self.info(component, message)

    def close(self):
        """Close the logger and any open file handles."""
        if self._log_file:
            self._log_file.close()
            self._log_file = None

    def write_events_sync(self, events: list[Any]):
        """Write pre-built lifecycle/log events from PeerContext queues."""
        for event in events:
            component = getattr(event, "component", Component.PEER_CONNECTION)
            if isinstance(component, str):
                try:
                    component = Component(component)
                except ValueError:
                    component = Component.PEER_CONNECTION

            level = getattr(event, "level", LogLevel.INFO)
            if isinstance(level, str):
                try:
                    level = LogLevel[level.upper()]
                except KeyError:
                    level = LogLevel.INFO

            message = getattr(event, "message", None) or str(event)
            self._log(component, level, message)


# Global logger instance
_logger: Optional[WebRTCLogger] = None


def get_logger() -> WebRTCLogger:
    """Get the global WebRTC logger instance."""
    global _logger
    if _logger is None:
        _logger = WebRTCLogger()
    return _logger


# Convenience functions for direct use
def log_ice(level: LogLevel, message: str, **kwargs):
    """Log ICE message."""
    get_logger()._log(Component.ICE, level, message, **kwargs)


def log_dtls(level: LogLevel, message: str, **kwargs):
    """Log DTLS message."""
    get_logger()._log(Component.DTLS, level, message, **kwargs)


def log_srtp(level: LogLevel, message: str, **kwargs):
    """Log SRTP message."""
    get_logger()._log(Component.SRTP, level, message, **kwargs)


def log_rtp(level: LogLevel, message: str, **kwargs):
    """Log RTP message."""
    get_logger()._log(Component.RTP, level, message, **kwargs)


def log_opus(level: LogLevel, message: str, **kwargs):
    """Log Opus message."""
    get_logger()._log(Component.OPUS, level, message, **kwargs)
