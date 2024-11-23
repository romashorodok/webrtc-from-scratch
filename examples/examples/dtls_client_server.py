import socket
import threading
import time

SERVER_IP = "127.0.0.1"
SERVER_PORT = 12345
CLIENT_PORT = 54321


def udp_server():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind((SERVER_IP, SERVER_PORT))
        print(f"UDP server listening on {SERVER_IP}:{SERVER_PORT}")

        while True:
            message, client_address = server_socket.recvfrom(1024)
            print(f"Server received from {client_address}: {message.decode()}")

            server_socket.sendto(f"Echo: {message.decode()}".encode(), client_address)


def udp_client():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        client_socket.bind((SERVER_IP, CLIENT_PORT))
        print(f"UDP client bound to {SERVER_IP}:{CLIENT_PORT}")

        while True:
            # message = input("Client: Enter a message to send: ")
            message = "test"

            client_socket.sendto(message.encode(), (SERVER_IP, SERVER_PORT))

            response, server_address = client_socket.recvfrom(1024)
            print(f"Client received from {server_address}: {response.decode()}")

            time.sleep(4)


if __name__ == "__main__":
    server_thread = threading.Thread(target=udp_server, daemon=True)
    server_thread.start()

    udp_client()
