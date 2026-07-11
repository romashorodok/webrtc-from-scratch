#!/usr/bin/env python3
"""
DTLS Client Example

A standalone DTLS client for testing the Python DTLS handshake implementation.
This uses the Python flight-based DTLS rather than the Rust DTLS.

Usage:
    python dtls_client.py --host localhost --port 5000
"""

import asyncio
import argparse
import logging
from typing import Optional

import webrtc_rs
from webrtc.dtls.certificate import Certificate
from webrtc.dtls.dtls_cipher_suite import Keypair
from webrtc.dtls.flight_state import State, Flight
from webrtc.dtls.flight1 import Flight1
from webrtc.dtls.flight3 import Flight3
from webrtc.dtls.flight5 import Flight5
from webrtc.dtls.dtls_record import RecordLayer, RecordLayerBatch

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DTLSClientProtocol(asyncio.DatagramProtocol):
    """DTLS client protocol handler using Python flight implementation."""

    def __init__(self, certificate: Certificate, keypair: Keypair, server_addr: tuple):
        self.certificate = certificate
        self.keypair = keypair
        self.server_addr = server_addr
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.state: Optional[State] = None
        self.current_flight = Flight.FLIGHT1
        self.handshake_complete = asyncio.Event()
        self.message_queue = asyncio.Queue()

    def connection_made(self, transport):
        self.transport = transport
        logger.info(f"Connected to {self.server_addr}")

        # Initialize state for this connection
        self.state = State(
            remote=self,
            certificate=self.certificate,
            keypair=self.keypair,
        )

        # Start handshake by sending ClientHello
        asyncio.create_task(self._start_handshake())

    async def _start_handshake(self):
        """Initiate DTLS handshake."""
        logger.info("Starting DTLS handshake...")

        # Flight 1: Send ClientHello
        flight1 = Flight1()
        records = flight1.generate(self.state)
        if records:
            for record in records:
                data = record.marshal()
                await self.sendto(data)
            logger.info("Sent ClientHello (Flight 1)")

    def datagram_received(self, data: bytes, addr):
        """Handle incoming DTLS records."""
        if addr != self.server_addr:
            logger.warning(f"Ignoring packet from unknown addr {addr}")
            return

        try:
            # Parse incoming DTLS records
            for record, _raw in RecordLayerBatch(data):
                asyncio.create_task(self._process_record(record))
        except Exception as e:
            logger.error(f"Error parsing DTLS record: {e}")

    async def _process_record(self, record: RecordLayer):
        """Process a single DTLS record."""
        logger.info(f"Processing record: epoch={record.header.epoch}, type={record.header.content_type}")
        # Add record to message queue for flight processing
        await self.message_queue.put(record)

    async def sendto(self, data: bytes):
        """Send data to server."""
        if self.transport:
            self.transport.sendto(data, self.server_addr)

    def error_received(self, exc):
        logger.error(f"Error received: {exc}")

    def connection_lost(self, exc):
        logger.info("Connection lost")


async def run_client(host: str, port: int):
    """Start the DTLS client."""
    logger.info(f"Connecting to DTLS server at {host}:{port}")

    # Generate certificate and keypair
    rust_cert = webrtc_rs.Certificate()
    certificate = Certificate(rust_cert)
    keypair = Keypair.generate_P256()

    logger.info(f"Certificate fingerprint: {certificate.get_fingerprints()[0].value}")

    loop = asyncio.get_event_loop()

    server_addr = (host, port)

    # Create UDP socket
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DTLSClientProtocol(certificate, keypair, server_addr),
        remote_addr=server_addr
    )

    logger.info("Waiting for handshake to complete...")

    try:
        # Wait for handshake with timeout
        await asyncio.wait_for(protocol.handshake_complete.wait(), timeout=30.0)
        logger.info("Handshake completed successfully!")
    except asyncio.TimeoutError:
        logger.error("Handshake timed out")
    except KeyboardInterrupt:
        logger.info("Interrupted")
    finally:
        transport.close()


def main():
    parser = argparse.ArgumentParser(description="DTLS Client Example")
    parser.add_argument("--host", default="localhost", help="Server host")
    parser.add_argument("--port", type=int, default=5000, help="Server port")
    args = parser.parse_args()

    asyncio.run(run_client(args.host, args.port))


if __name__ == "__main__":
    main()
