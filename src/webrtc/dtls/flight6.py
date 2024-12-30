import asyncio

from webrtc.dtls.dtls_record import Message, RecordLayer
from webrtc.dtls.flight_state import Flight, FlightTransition, State


class Flight6(FlightTransition):
    def generate(
        self,
        state: State,
    ) -> list[RecordLayer] | None:
        return

    async def parse(
        self, state: State, handshake_message_ch: asyncio.Queue[Message]
    ) -> Flight:
        return Flight.FLIGHT2
