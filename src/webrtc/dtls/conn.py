
class DTLSConn:

    def __init__(
        self,
        remote: DTLSRemote,
        layer_chan: asyncio.Queue[RecordLayer],
        flight: Flight = Flight.FLIGHT0,
    ) -> None:
