import asyncio
import contextlib
import threading
import socket
import native
from webrtc.dtls.certificate import generate_certificate


from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from OpenSSL import SSL, crypto

SERVER_IP = "127.0.0.1"
SERVER_PORT = 12345
CLIENT_PORT = 54321

MAX_MTU = 1280

# key = ec.generate_private_key(ec.SECP256R1(), default_backend())
# pkey_pem = key.private_bytes(
#     serialization.Encoding.PEM,
#     serialization.PrivateFormat.PKCS8,
#     serialization.NoEncryption(),
# )
# print(pkey_pem)
# cert = generate_certificate(key)
# cert_pem = pkey_pem + cert.public_bytes(serialization.Encoding.PEM)


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
            print("SERVER | Receive from", addr, "n=", len(pkt), "enqueue record layers")
            # dtls.enqueue_record(pkt)

            print("SERVER | Start dequeue tokio result with asyncio")
            # result = await dtls.dequeue_record()
            # print("SERVER | DTLS result done", result)


async def async_udp_client():
    loop = asyncio.get_running_loop()
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
        sock.bind((SERVER_IP, CLIENT_PORT))
        sock.setblocking(False)
        print(f"Async UDP client bound to {SERVER_IP}:{CLIENT_PORT}")

        dtls = native.DTLS(True)
        dtls.do_handshake()

        while True:
            print("CLIENT | Start next flight")
            handshake = await dtls.dequeue_record()
            print("CLIENT | Receive from dtls next flight", "n=", len(handshake))

            pkt, addr = await loop.sock_recvfrom(sock, MAX_MTU)


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
