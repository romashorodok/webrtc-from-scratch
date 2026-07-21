"""
WebRTC Configuration System

Singleton configuration for controlling logging and debugging behavior
across the WebRTC implementation.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional
import os


class LogLevel(IntEnum):
    """Logging verbosity levels."""
    SILENT = 0    # No logging
    ERROR = 1     # Errors only
    WARN = 2      # Warnings and errors
    INFO = 3      # Info, warnings, and errors
    DEBUG = 4     # Debug, info, warnings, and errors
    TRACE = 5     # All logging including packet traces


@dataclass
class DebugConfig:
    """
    Configuration for debugging WebRTC components.

    This is a singleton - use DebugConfig.get() to access the instance.
    """

    # Component-level logging
    ice_log_level: LogLevel = LogLevel.INFO
    dtls_log_level: LogLevel = LogLevel.INFO
    srtp_log_level: LogLevel = LogLevel.INFO
    rtp_log_level: LogLevel = LogLevel.INFO
    rtcp_log_level: LogLevel = LogLevel.INFO
    transceiver_log_level: LogLevel = LogLevel.INFO
    peer_connection_log_level: LogLevel = LogLevel.INFO

    # Audio-specific logging
    opus_log_level: LogLevel = LogLevel.INFO

    # Packet-level debugging
    log_packet_details: bool = True          # Log sequence numbers, timestamps, sizes
    log_first_n_packets: int = 20            # Log first N packets in detail
    log_every_n_packets: int = 100           # After first N, log every Nth packet

    # Sequence gap tracking
    track_sequence_gaps: bool = True         # Track and report sequence number gaps
    warn_on_sequence_gaps: bool = True       # Warn when gaps detected

    # Performance metrics
    log_queue_sizes: bool = True             # Log queue sizes periodically
    log_packet_counts: bool = True           # Log packet statistics

    # UDP/Network
    log_udp_socket_buffers: bool = True      # Log UDP socket buffer sizes

    # SRTP debugging
    log_srtp_decrypt_errors: bool = True     # Log SRTP decryption failures
    log_srtp_new_streams: bool = True        # Log when new SRTP streams created

    # File output
    log_to_file: bool = False
    log_file_path: str = "/tmp/webrtc_debug.log"

    # Color output (for terminal)
    use_colors: bool = True

    # Component prefixes for readability
    component_prefix_width: int = 15         # Width of component prefix in logs

    # Singleton instance
    _instance: Optional['DebugConfig'] = field(default=None, init=False, repr=False)

    def __post_init__(self):
        """Apply environment variable overrides."""
        # Allow environment variables to override config
        if env_level := os.getenv('WEBRTC_LOG_LEVEL'):
            try:
                global_level = LogLevel[env_level.upper()]
                self.set_all_log_levels(global_level)
            except (KeyError, ValueError):
                pass

        # Component-specific overrides
        component_map = {
            'WEBRTC_ICE_LOG': 'ice_log_level',
            'WEBRTC_DTLS_LOG': 'dtls_log_level',
            'WEBRTC_SRTP_LOG': 'srtp_log_level',
            'WEBRTC_RTP_LOG': 'rtp_log_level',
            'WEBRTC_OPUS_LOG': 'opus_log_level',
        }

        for env_var, attr_name in component_map.items():
            if env_value := os.getenv(env_var):
                try:
                    setattr(self, attr_name, LogLevel[env_value.upper()])
                except (KeyError, ValueError):
                    pass

    @classmethod
    def get(cls) -> 'DebugConfig':
        """Get the singleton instance of DebugConfig."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls):
        """Reset singleton instance (mainly for testing)."""
        cls._instance = None

    def set_all_log_levels(self, level: LogLevel):
        """Set all component log levels to the same value."""
        self.ice_log_level = level
        self.dtls_log_level = level
        self.srtp_log_level = level
        self.rtp_log_level = level
        self.rtcp_log_level = level
        self.transceiver_log_level = level
        self.peer_connection_log_level = level
        self.opus_log_level = level

    def enable_trace_all(self):
        """Enable TRACE level logging for all components."""
        self.set_all_log_levels(LogLevel.TRACE)

    def enable_debug_all(self):
        """Enable DEBUG level logging for all components."""
        self.set_all_log_levels(LogLevel.DEBUG)

    def quiet_mode(self):
        """Set all logging to minimal (ERROR only)."""
        self.set_all_log_levels(LogLevel.ERROR)
        self.log_packet_details = False
        self.log_queue_sizes = False
        self.log_packet_counts = False

    def verbose_mode(self):
        """Enable verbose logging with all details."""
        self.enable_trace_all()
        self.log_packet_details = True
        self.log_first_n_packets = 50
        self.log_every_n_packets = 50
        self.log_queue_sizes = True
        self.log_packet_counts = True

    def production_mode(self):
        """Minimal logging suitable for production."""
        self.set_all_log_levels(LogLevel.WARN)
        self.log_packet_details = False
        self.log_first_n_packets = 5
        self.log_every_n_packets = 1000
        self.track_sequence_gaps = False
        self.log_queue_sizes = False


# Convenience function for quick access
def get_config() -> DebugConfig:
    """Get the global debug configuration singleton."""
    return DebugConfig.get()
