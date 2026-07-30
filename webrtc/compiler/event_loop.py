"""Compatibility import for the componentized reference event loop.

The compiler source moved to :mod:`webrtc.event_loop.loop`.  Keeping this
module avoids breaking development tools which used the original location.
"""

from webrtc.event_loop.loop import WebRTCSelectorEventLoop, new_event_loop

__all__ = ["WebRTCSelectorEventLoop", "new_event_loop"]
