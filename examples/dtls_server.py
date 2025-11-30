#!/usr/bin/env python3
"""
DTLS Server Example

A standalone DTLS server for testing the Python DTLS handshake implementation.
This uses the Python flight-based DTLS rather than the Rust DTLS.

Usage:
    python dtls_server.py --port 5000
"""

import asyncio
import argparse
import logging
import socket
from typing import Optional

import webrtc_rs
from webrtc.dtls.certificate import Certificate
from webrtc.dtls.dtls_cipher_suite import Keypair
from webrtc.dtls.flight_state import State, Flight
from webrtc.dtls.flight0 import Flight0
from webrtc.dtls.flight2 import Flight2
from webrtc.dtls.flight4 import Flight4
from webrtc.dtls.flight6 import Flight6
from webrtc.dtls.dtls_record import RecordLayer, unmarshal_record_layers

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DTLSServerProtocol(asyncio.DatagramProtocol):
    """DTLS server protocol handler using Python flight implementation."""

    def __init__(self, certificate: Certificate, keypair: Keypair):
        self.certificate = certificate
        self.keypair = keypair
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.state: Optional[State] = None
        self.current_flight = Flight.FLIGHT0
        self.handshake_complete = asyncio.Event()
        self.message_queue = asyncio.Queue()
        self._remote_addr = None

    def connection_made(self, transport):
        self.transport = transport
        logger.info("DTLS server listening...")

    def datagram_received(self, data: bytes, addr):
        """Handle incoming DTLS records."""
        if self._remote_addr is None:
            self._remote_addr = addr
            logger.info(f"New connection from {addr}")
            # Initialize state for this connection
            self.state = State(
                remote=self,
                certificate=self.certificate,
                keypair=self.keypair,
            )

        if self._remote_addr != addr:
            logger.warning(f"Ignoring packet from unknown addr {addr}")
            return

        try:
            # Parse incoming DTLS records
            records = unmarshal_record_layers(data)
            for record in records:
                asyncio.create_task(self._process_record(record))
        except Exception as e:
            logger.error(f"Error parsing DTLS record: {e}")

    async def _process_record(self, record: RecordLayer):
        """Process a single DTLS record."""
        logger.info(f"Processing record: epoch={record.header.epoch}, type={record.header.content_type}")
        # Add record to message queue for flight processing
        await self.message_queue.put(record)

    async def sendto(self, data: bytes):
        """Send data to remote peer."""
        if self.transport and self._remote_addr:
            self.transport.sendto(data, self._remote_addr)

    def error_received(self, exc):
        logger.error(f"Error received: {exc}")

    def connection_lost(self, exc):
        logger.info("Connection lost")


async def run_server(host: str, port: int):
    """Start the DTLS server."""
    logger.info(f"Starting DTLS server on {host}:{port}")

    # Generate certificate and keypair
    rust_cert = webrtc_rs.Certificate()
    certificate = Certificate(rust_cert)
    keypair = Keypair.generate_P256()

    logger.info(f"Certificate fingerprint: {certificate.get_fingerprints()[0].value}")

    loop = asyncio.get_event_loop()

    # Create UDP socket
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DTLSServerProtocol(certificate, keypair),
        local_addr=(host, port)
    )

    logger.info(f"DTLS server listening on {host}:{port}")
    logger.info("Press Ctrl+C to stop")

    try:
        # Keep server running
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        transport.close()


def main():
    parser = argparse.ArgumentParser(description="DTLS Server Example")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    args = parser.parse_args()

    asyncio.run(run_server(args.host, args.port))


if __name__ == "__main__":
    main()
