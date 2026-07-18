"""
Pure Python SRTP implementation with stream demuxing, using Rust cipher backend.

This module provides SRTP (Secure Real-time Transport Protocol) encryption/decryption
with support for demultiplexing incoming packets by SSRC.

The crypto operations (AES-CM, HMAC-SHA1, key derivation, ROC tracking) are handled
by the Rust `SrtpContext` class from webrtc_rs. Python handles the async stream
demuxing and packet routing.

Based on RFC 3711: https://tools.ietf.org/html/rfc3711
"""

from webrtc.srtp.session import (
    Session, SessionAdmissionSnapshot, SessionReadinessSnapshot, Stream, SessionKeys,
)

__all__ = [
    "Session",
    "SessionAdmissionSnapshot",
    "SessionReadinessSnapshot",
    "Stream",
    "SessionKeys",
]
