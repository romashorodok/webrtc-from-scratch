import asyncio
from collections.abc import Awaitable, Callable
from enum import StrEnum


class ICECondition(StrEnum):
    GATHERING_COMPLETE = "ice.gathering_complete"
    CANDIDATE_PAIR_SUCCEEDED = "ice.candidate_pair_succeeded"
    NOMINATED = "ice.nominated"
    NOMINATED_TRANSPORT_READY = "ice.nominated_transport_ready"


class TransportCondition(StrEnum):
    HANDSHAKE_COMPLETE = "dtls.handshake_complete"
    SRTP_READY = "srtp.ready"


class PeerCondition(StrEnum):
    ICE_GATHERING_COMPLETE = "ice.gathering_complete"
    ICE_CANDIDATE_PAIR_SUCCEEDED = "ice.candidate_pair_succeeded"
    ICE_NOMINATED = "ice.nominated"
    NOMINATED_TRANSPORT_READY = "ice.nominated_transport_ready"
    DTLS_HANDSHAKE_COMPLETE = "dtls.handshake_complete"
    SRTP_READY = "srtp.ready"


def require_timeout(timeout: float | None) -> float:
    if timeout is None:
        raise ValueError("lifecycle waits require an explicit timeout")
    return timeout


async def wait_until(
    predicate: Callable[[], bool],
    *,
    timeout: float | None,
    interval: float = 0.01,
) -> None:
    deadline_timeout = require_timeout(timeout)

    async def poll() -> None:
        while not predicate():
            await asyncio.sleep(interval)

    await asyncio.wait_for(poll(), deadline_timeout)


async def wait_for_event(
    event: asyncio.Event,
    *,
    timeout: float | None,
) -> None:
    deadline_timeout = require_timeout(timeout)
    await asyncio.wait_for(event.wait(), deadline_timeout)


async def wait_for_all(
    awaitables: list[Awaitable[object]],
    *,
    timeout: float | None,
) -> None:
    deadline_timeout = require_timeout(timeout)
    await asyncio.wait_for(asyncio.gather(*awaitables), deadline_timeout)
