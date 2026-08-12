"""Production entry point for the generated native event-loop module.

Keeping the artifact entry point separate from the reference implementation gives
the extension its stable production module name while the compiler still follows
the ordinary relative import to discover and prove the complete implementation.
"""

from .loop import LoopConfig, WebRTCSelectorEventLoop, new_event_loop

__all__ = ["LoopConfig", "WebRTCSelectorEventLoop", "new_event_loop"]
