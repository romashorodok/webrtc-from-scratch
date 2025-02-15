import asyncio
import contextlib
import threading
import socket
import native

SERVER_IP = "127.0.0.1"
SERVER_PORT = 12345
CLIENT_PORT = 54321

MAX_MTU = 1280


async def async_udp_server():
    loop = asyncio.get_running_loop()
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
        sock.bind((SERVER_IP, SERVER_PORT))
        sock.setblocking(False)
        print(f"Async UDP server listening on {SERVER_IP}:{SERVER_PORT}")
        dtls = native.DTLS(False)
        dtls.do_handshake()
        while True:
            print("Start listen on ", SERVER_IP, SERVER_PORT)
            pkt, addr = await loop.sock_recvfrom(sock, MAX_MTU)
            print(
                "SERVER | Receive from", addr, "n=", len(pkt), "enqueue record layers"
            )
            await dtls.enqueue_record(pkt)
            print("SERVER | Start dequeue tokio result with asyncio")
            handshake_flight = await dtls.dequeue_record()
            print("SERVER | DTLS result done", handshake_flight)
            await loop.sock_sendto(sock, handshake_flight, addr)


async def async_udp_client():
    loop = asyncio.get_running_loop()
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
        sock.bind((SERVER_IP, CLIENT_PORT))
        sock.setblocking(False)
        print(f"Async UDP client bound to {SERVER_IP}:{CLIENT_PORT}")

        dtls = native.DTLS(True)
        dtls.do_handshake()
        handshake_flight1 = await dtls.dequeue_record()
        print("CLIENT | Start next flight")
        await loop.sock_sendto(sock, handshake_flight1, (SERVER_IP, SERVER_PORT))

        while True:
            pkt, addr = await loop.sock_recvfrom(sock, MAX_MTU)
            print("CLIENT | Receive flight from server", pkt)
            await dtls.enqueue_record(pkt)
            next_flight = await dtls.dequeue_record()
            print("CLIENT | Next flight from server n=", len(next_flight))
            await loop.sock_sendto(sock, next_flight, addr)


def run_in_thread(coro):
    def wrapper():
        asyncio.run(coro())

    thread = threading.Thread(target=wrapper)
    thread.daemon = True
    thread.start()
    return thread


if __name__ == "__main__":
    server_thread = run_in_thread(async_udp_server)
    client_thread = run_in_thread(async_udp_client)

    server_thread.join()
    client_thread.join()
