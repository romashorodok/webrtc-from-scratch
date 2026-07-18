"""
Tests for Python SRTP implementation using Rust cipher backend.

These tests verify:
1. Encryption/decryption roundtrip works
2. Session demuxing works correctly
"""

import pytest
import asyncio

from webrtc.srtp import Session, SessionKeys


class TestSession:
    """Test SRTP session with Rust cipher backend."""

    def test_encrypt_decrypt_roundtrip(self):
        """Test that encrypt followed by decrypt returns original."""
        keys = SessionKeys(
            local_master_key=bytes(16),
            local_master_salt=bytes(14),
            remote_master_key=bytes(16),
            remote_master_salt=bytes(14),
        )

        session = Session(keys, is_rtp=True)

        # Create a simple RTP packet
        packet = bytes([
            0x80, 0x60, 0x00, 0x01,  # RTP header
            0x00, 0x00, 0x00, 0x00,  # timestamp
            0x12, 0x34, 0x56, 0x78,  # ssrc
            0xDE, 0xAD, 0xBE, 0xEF,  # payload
        ])

        encrypted = session.encrypt(packet)
        assert len(encrypted) == len(packet) + 10  # +10 for auth tag

        decrypted = session.decrypt(encrypted)
        assert decrypted == packet

    def test_encrypt_decrypt_multiple_packets(self):
        """Test encrypting/decrypting multiple packets with different sequence numbers."""
        keys = SessionKeys(
            local_master_key=bytes(16),
            local_master_salt=bytes(14),
            remote_master_key=bytes(16),
            remote_master_salt=bytes(14),
        )

        session = Session(keys, is_rtp=True)

        for seq in range(10):
            packet = bytes([
                0x80, 0x60,
                (seq >> 8) & 0xFF, seq & 0xFF,  # sequence number
                0x00, 0x00, 0x00, seq,  # timestamp
                0x12, 0x34, 0x56, 0x78,  # ssrc
                0xDE, 0xAD, 0xBE, 0xEF,  # payload
            ])

            encrypted = session.encrypt(packet)
            decrypted = session.decrypt(encrypted)
            assert decrypted == packet

    def test_from_keying_material(self):
        """Test creating session from DTLS keying material."""
        tx_key = bytes(30)  # 16 key + 14 salt
        rx_key = bytes(30)

        session = Session.from_keying_material(tx_key, rx_key, is_rtp=True)

        packet = bytes([
            0x80, 0x60, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x12, 0x34, 0x56, 0x78,
            0xDE, 0xAD, 0xBE, 0xEF,
        ])

        encrypted = session.encrypt(packet)
        decrypted = session.decrypt(encrypted)
        assert decrypted == packet

    @pytest.mark.asyncio
    async def test_stream_demux(self):
        """Test that incoming packets are demuxed to streams by SSRC."""
        keys = SessionKeys(
            local_master_key=bytes(16),
            local_master_salt=bytes(14),
            remote_master_key=bytes(16),
            remote_master_salt=bytes(14),
        )

        sender = Session(keys, is_rtp=True)
        receiver = Session(keys, is_rtp=True)

        # Send packets with different SSRCs
        ssrc1 = 0x11111111
        ssrc2 = 0x22222222

        packet1 = bytes([
            0x80, 0x60, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            (ssrc1 >> 24) & 0xFF, (ssrc1 >> 16) & 0xFF,
            (ssrc1 >> 8) & 0xFF, ssrc1 & 0xFF,
            0x11, 0x11, 0x11, 0x11,
        ])

        packet2 = bytes([
            0x80, 0x60, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            (ssrc2 >> 24) & 0xFF, (ssrc2 >> 16) & 0xFF,
            (ssrc2 >> 8) & 0xFF, ssrc2 & 0xFF,
            0x22, 0x22, 0x22, 0x22,
        ])

        # Encrypt and write incoming
        encrypted1 = sender.encrypt(packet1)
        encrypted2 = sender.encrypt(packet2)

        await receiver.write_incoming(encrypted1)
        await receiver.write_incoming(encrypted2)

        # Accept streams
        stream1, ssrc1_received = await receiver.accept_stream()
        stream2, ssrc2_received = await receiver.accept_stream()

        assert {ssrc1_received, ssrc2_received} == {ssrc1, ssrc2}

    @pytest.mark.asyncio
    async def test_async_encrypt_decrypt(self):
        """Test async encrypt/decrypt wrappers."""
        keys = SessionKeys(
            local_master_key=bytes(16),
            local_master_salt=bytes(14),
            remote_master_key=bytes(16),
            remote_master_salt=bytes(14),
        )

        session = Session(keys, is_rtp=True)

        packet = bytes([
            0x80, 0x60, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x12, 0x34, 0x56, 0x78,
            0xDE, 0xAD, 0xBE, 0xEF,
        ])

        encrypted = await session.encrypt(packet)
        decrypted = await session.decrypt(encrypted)
        assert decrypted == packet


class TestRtcp:
    """Test SRTCP encryption/decryption."""

    def test_rtcp_encrypt_decrypt(self):
        """Test RTCP packet encryption/decryption."""
        keys = SessionKeys(
            local_master_key=bytes(16),
            local_master_salt=bytes(14),
            remote_master_key=bytes(16),
            remote_master_salt=bytes(14),
        )

        session = Session(keys, is_rtp=False)

        # Create a simple RTCP SR packet
        rtcp_packet = bytes([
            0x80, 0xC8, 0x00, 0x06,  # V=2, P=0, RC=0, PT=200 (SR), length=6
            0x12, 0x34, 0x56, 0x78,  # SSRC
            0x00, 0x00, 0x00, 0x00,  # NTP timestamp (high)
            0x00, 0x00, 0x00, 0x00,  # NTP timestamp (low)
            0x00, 0x00, 0x00, 0x00,  # RTP timestamp
            0x00, 0x00, 0x00, 0x01,  # Sender packet count
            0x00, 0x00, 0x00, 0x10,  # Sender octet count
        ])

        encrypted = session.encrypt(rtcp_packet)
        # SRTCP adds 4 bytes for index + 10 bytes for auth tag
        assert len(encrypted) == len(rtcp_packet) + 14

        decrypted = session.decrypt(encrypted)
        assert decrypted == rtcp_packet


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
