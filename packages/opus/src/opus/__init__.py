"""
Opus codec Python interface

Usage:
    from opus import OpusEncoder, OpusDecoder

    # Encoder
    encoder = OpusEncoder(sample_rate=48000, channels=1, application="voip")
    encoder.set_bitrate(32000)
    opus_frame = encoder.encode(pcm_bytes)  # 960 samples * 2 bytes = 1920 bytes

    # Decoder
    decoder = OpusDecoder(sample_rate=48000, channels=1)
    pcm_bytes = decoder.decode(opus_frame, frame_size=960, decode_fec=False)
"""

from opus._core import OpusEncoder, OpusDecoder

__all__ = ["OpusEncoder", "OpusDecoder"]
