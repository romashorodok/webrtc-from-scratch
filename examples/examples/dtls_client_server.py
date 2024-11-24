import binascii
import asyncio
import socket
from contextlib import closing

from webrtc.dtls.dtlstransport import (
    DTLSConn,
    Flight,
    HandshakeState,
    RecordLayer,
    is_dtls_record_layer,
)


SERVER_IP = "127.0.0.1"
SERVER_PORT = 12345
CLIENT_PORT = 54321

client_hello_stub = b"16feff0000000000000000008c010000800000000000000080fefd13b3ac327e56ae1c96882705b7e69b21cbc30df1695e244570eb7943635866b000000016c02bc02fcca9cca8c009c013c00ac014009c002f003501000040000a00080006001d0017001800170000000d00140012040308040401050308050501080606010201000e0009000600010008000700000b00020100ff01000100"

record_layer_client_hello = RecordLayer.unmarshal(binascii.unhexlify(client_hello_stub))


class DTLSLocal:
    def __init__(self) -> None:
        self.socket: socket.socket | None = None
        self.addr: socket._RetAddress | None = None

    def sendto(self, data: bytes):
        if not self.socket or not self.addr:
            raise ValueError("Unable send a data to remote")

        loop = asyncio.get_running_loop()
        loop.create_task(loop.sock_sendto(self.socket, data, self.addr))


async def async_udp_server():
    loop = asyncio.get_running_loop()

    record_layer_chan = asyncio.Queue[RecordLayer]()

    dtls_local = DTLSLocal()
    dtls_conn = DTLSConn(dtls_local, record_layer_chan)
    asyncio.create_task(dtls_conn.handshake(Flight.FLIGHT0, HandshakeState.Preparing))

    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as server_socket:
        server_socket.bind((SERVER_IP, SERVER_PORT))
        server_socket.setblocking(False)
        print(f"Async UDP server listening on {SERVER_IP}:{SERVER_PORT}")

        while True:
            message, client_address = await loop.sock_recvfrom(server_socket, 1280)
            dtls_local.addr = client_address
            dtls_local.socket = server_socket

            if is_dtls_record_layer(message):
                try:
                    await record_layer_chan.put(RecordLayer.unmarshal(message))
                except Exception as e:
                    print("DTLS record error", e)

            # print(f"Server received from {client_address}: {message}")

            msg = RecordLayer.unmarshal(message)
            await loop.sock_sendto(server_socket, msg.marshal(), client_address)


async def async_udp_client():
    loop = asyncio.get_running_loop()

    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as client_socket:
        client_socket.bind((SERVER_IP, CLIENT_PORT))
        client_socket.setblocking(False)
        print(f"Async UDP client bound to {SERVER_IP}:{CLIENT_PORT}")

        while True:
            message = record_layer_client_hello.marshal()
            await loop.sock_sendto(client_socket, message, (SERVER_IP, SERVER_PORT))

            response, server_address = await loop.sock_recvfrom(client_socket, 1280)
            # print(f"Client received from {server_address}: {response}")
            await asyncio.sleep(4)


async def main():
    server_task = asyncio.create_task(async_udp_server())
    client_task = asyncio.create_task(async_udp_client())

    await asyncio.gather(server_task, client_task)


if __name__ == "__main__":
    asyncio.run(main())
