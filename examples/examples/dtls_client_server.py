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

from threading import Thread
from typing import Optional

SERVER_IP = "127.0.0.1"
SERVER_PORT = 12345
CLIENT_PORT = 54321

client_hello_stub = b"16feff0000000000000000008c010000800000000000000080fefd13b3ac327e56ae1c96882705b7e69b21cbc30df1695e244570eb7943635866b000000016c02bc02fcca9cca8c009c013c00ac014009c002f003501000040000a00080006001d0017001800170000000d00140012040308040401050308050501080606010201000e0009000600010008000700000b00020100ff01000100"

record_layer_client_hello = RecordLayer.unmarshal(binascii.unhexlify(client_hello_stub))


class DTLSLocal:
    def __init__(self) -> None:
        self.socket: Optional[socket.socket] = None
        self.addr: Optional[socket._RetAddress] = None

    async def sendto(self, data: bytes):
        if not self.socket or not self.addr:
            raise ValueError("Unable to send data to remote")

        loop = asyncio.get_running_loop()
        await loop.sock_sendto(self.socket, data, self.addr)


async def async_udp_server():
    loop = asyncio.get_running_loop()
    record_layer_chan = asyncio.Queue[RecordLayer]()

    dtls_local = DTLSLocal()
    dtls_conn = DTLSConn(dtls_local, record_layer_chan, Flight.FLIGHT0)
    asyncio.create_task(dtls_conn.handle_inbound_record_layers())
    asyncio.create_task(dtls_conn.fsm.dispatch())

    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as server_socket:
        server_socket.bind((SERVER_IP, SERVER_PORT))
        server_socket.setblocking(False)
        print(f"Async UDP server listening on {SERVER_IP}:{SERVER_PORT}")

        while True:
            message, client_address = await loop.sock_recvfrom(server_socket, 1280)
            dtls_local.addr = client_address
            dtls_local.socket = server_socket

            # print("Recv packet server")

            if is_dtls_record_layer(message):
                try:
                    test = RecordLayer.unmarshal(message)
                    # print("Try to put a record", test.header, test.content.content_type)
                    await record_layer_chan.put(test)
                    # await dtls_conn.fsm.dispatch()
                except Exception as e:
                    print("DTLS record error", e)


async def async_udp_client():
    loop = asyncio.get_running_loop()
    dtls_local = DTLSLocal()

    record_layer_chan = asyncio.Queue[RecordLayer]()
    dtls_conn = DTLSConn(dtls_local, record_layer_chan, Flight.FLIGHT1)
    asyncio.create_task(dtls_conn.handle_inbound_record_layers())
    asyncio.create_task(dtls_conn.fsm.dispatch())

    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as client_socket:
        client_socket.bind((SERVER_IP, CLIENT_PORT))
        client_socket.setblocking(False)
        print(f"Async UDP client bound to {SERVER_IP}:{CLIENT_PORT}")

        dtls_local.addr = (SERVER_IP, SERVER_PORT)
        dtls_local.socket = client_socket

        while True:
            message, _ = await loop.sock_recvfrom(client_socket, 1280)

            print("Recv packet client")

            if is_dtls_record_layer(message):
                try:
                    test = RecordLayer.unmarshal(message)
                    await record_layer_chan.put(test)
                    print("Recv packet client after put")
                except Exception as e:
                    print("DTLS record error", e)


def run_in_thread(coro):
    def wrapper():
        asyncio.run(coro())

    thread = Thread(target=wrapper)
    thread.daemon = True
    thread.start()
    return thread


if __name__ == "__main__":
    server_thread = run_in_thread(async_udp_server)
    client_thread = run_in_thread(async_udp_client)

    server_thread.join()
    client_thread.join()
