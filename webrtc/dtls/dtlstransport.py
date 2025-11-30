import asyncio
import logging
from enum import Enum
from typing import Protocol

import webrtc_rs

from webrtc import ice
from webrtc.dtls.certificate import Certificate
from webrtc.dtls.dtls_cipher_suite import Keypair
from webrtc.dtls.dtls_record import RecordLayer, is_dtls_record_layer
from webrtc.dtls.flight_state import Flight
from webrtc.dtls.fsm import DTLSConn
from webrtc.dtls.prf import SRTPKeyingMaterial
from webrtc.srtp import Session as SrtpSession, Stream as SrtpStream

logger = logging.getLogger("webrtc.dtls.transport")


class DTLSRole(Enum):
    Auto = "auto"
    Server = "server"
    Client = "client"


class ICETransportDTLS(Protocol):
    async def get_ice_pair_transport(self) -> ice.CandidatePairTransport | None: ...


class RTPReaderProtocol(Protocol):
    async def recv_rtp_bytes(self) -> bytes: ...


class DTLSLocal:
    """Adapter to send DTLS packets via ICE transport."""

    def __init__(self, transport: ice.CandidatePairTransport) -> None:
        self._t = transport

    async def sendto(self, data: bytes):
        self._t.sendto(data)


class DTLSTransport:
    """
    DTLS Transport using Python flight-based FSM.

    Uses Python PRF for key derivation and Rust for:
    - ECDH key exchange (ECDHKeyPair)
    - AES-GCM encryption (AesGcmCipher)
    - SRTP encryption (after handshake)
    """

    def __init__(
        self,
        certificate: webrtc_rs.Certificate,
    ) -> None:
        self.__rust_cert = certificate
        # Wrap Rust certificate for Python FSM
        self.__cert = Certificate(certificate)

        # Python FSM state
        self.__dtls_conn: DTLSConn | None = None
        self.__role: DTLSRole = DTLSRole.Auto
        self.__transport: ice.CandidatePairTransport | None = None

        # Record layer channel for incoming DTLS packets
        self.record_layer_chan: asyncio.Queue[tuple[RecordLayer, bytes]] = asyncio.Queue()

        # SRTP state - Python Session with Rust SrtpContext for crypto
        self.__srtp_rtp_lock = asyncio.Event()
        self.__srtp_rtcp_lock = asyncio.Event()
        self._srtp_rtp: SrtpSession | None = None
        self._srtp_rtcp: SrtpSession | None = None

        # Handshake completion
        self.__handshake_complete = asyncio.Event()
        self._srtp_keying_material: SRTPKeyingMaterial | None = None

    @property
    def handshake_complete(self) -> asyncio.Event:
        """Event signaling handshake completion."""
        return self.__handshake_complete

    def get_srtp_keying_material(self) -> SRTPKeyingMaterial | None:
        """Get SRTP keying material after handshake completion."""
        return self._srtp_keying_material

    async def bind(self, transport: ice.CandidatePairTransport):
        """Bind to ICE transport for sending/receiving DTLS packets."""
        self.__transport = transport

    def start(self, role: DTLSRole, transport: "ice.CandidatePairTransport | None" = None):
        """
        Start DTLS handshake using Python flight-based FSM.

        Args:
            role: DTLSRole.Server or DTLSRole.Client
            transport: Optional ICE transport (if not already bound)
        """
        print(f"[DTLS] start: role={role}, transport provided={transport is not None}")

        # If handshake already completed, skip
        if self.__handshake_complete.is_set():
            print("[DTLS] start: handshake already complete, skipping")
            return

        # If there's already a DTLS connection in progress, skip (don't restart mid-handshake)
        if self.__dtls_conn is not None:
            print("[DTLS] start: DTLS connection already in progress, skipping duplicate start")
            return

        self.__role = role
        is_client = role == DTLSRole.Client

        # Bind transport if provided
        if transport:
            self.__transport = transport

        if not self.__transport:
            print("[DTLS] start: ERROR - No transport bound")
            logger.error("No transport bound - cannot start DTLS handshake")
            return

        # Determine initial flight based on role
        if is_client:
            flight = Flight.FLIGHT1
        else:
            flight = Flight.FLIGHT0

        print(f"[DTLS] start: creating DTLSConn with flight={flight}")
        # Create Python DTLS connection with FSM
        self.__dtls_conn = DTLSConn(
            remote=DTLSLocal(self.__transport),
            certificate=self.__cert,
            layer_chan=self.record_layer_chan,
            flight=flight,
        )

        print(f"[DTLS] start: DTLSConn created, starting handshake as {'client' if is_client else 'server'}")
        logger.info(f"Starting DTLS handshake as {'client' if is_client else 'server'}")

        # Start handshake processing
        loop = asyncio.get_running_loop()
        loop.create_task(self._run_handshake(is_client))
        print("[DTLS] start: _run_handshake task created")

    async def _run_handshake(self, is_client: bool):
        """Run the DTLS handshake using Python FSM."""
        print(f"[DTLS] _run_handshake: STARTED, is_client={is_client}")
        if not self.__dtls_conn:
            print("[DTLS] _run_handshake: ERROR - DTLS connection not initialized")
            logger.error("DTLS connection not initialized")
            return

        try:
            # Start FSM processing
            print("[DTLS] _run_handshake: creating handle_inbound_record_layers task")
            asyncio.create_task(self.__dtls_conn.handle_inbound_record_layers())

            # Dispatch initial state
            print("[DTLS] _run_handshake: dispatching initial FSM state")
            await self.__dtls_conn.fsm.dispatch()
            print("[DTLS] _run_handshake: FSM dispatch complete, waiting for handshake")

            # Wait for handshake completion
            success = await self.__dtls_conn.wait_handshake_complete(timeout=30.0)

            if success:
                logger.info("DTLS handshake completed successfully")

                # Get SRTP keying material from Python FSM
                self._srtp_keying_material = self.__dtls_conn.get_srtp_keying_material()

                if self._srtp_keying_material:
                    # Initialize Rust SRTP with Python-derived keys
                    await self._init_srtp(is_client)

                self.__handshake_complete.set()
            else:
                logger.error("DTLS handshake timed out")

        except Exception as e:
            logger.error(f"DTLS handshake error: {e}")

    async def _init_srtp(self, is_client: bool):
        """
        Initialize Python SRTP sessions with Rust cipher backend.

        The SRTP keys are derived by Python PRF, crypto is done by Rust SrtpContext.
        Stream demuxing is handled by Python.
        """
        if not self._srtp_keying_material:
            logger.error("No SRTP keying material available")
            return

        keys = self._srtp_keying_material

        try:
            # Create SRTP with Python-derived keys
            # The SRTP master key format is: key (16 bytes) + salt (14 bytes) = 30 bytes
            if is_client:
                # Client sends with client key, receives with server key
                tx_master_key = keys.client_write_key + keys.client_write_salt
                rx_master_key = keys.server_write_key + keys.server_write_salt
            else:
                # Server sends with server key, receives with client key
                tx_master_key = keys.server_write_key + keys.server_write_salt
                rx_master_key = keys.client_write_key + keys.client_write_salt

            print(f"[DTLS] _init_srtp: is_client={is_client}")
            print(f"[DTLS] _init_srtp: tx_key (for encryption)={tx_master_key.hex()}")
            print(f"[DTLS] _init_srtp: rx_key (for decryption)={rx_master_key.hex()}")

            # Initialize Python SRTP sessions (uses Rust SrtpContext internally)
            self._srtp_rtp = SrtpSession.from_keying_material(
                tx_key=tx_master_key,
                rx_key=rx_master_key,
                is_rtp=True,
            )
            self.__srtp_rtp_lock.set()
            print("[DTLS] _init_srtp: RTP SRTP session created (Python + Rust crypto)")

            self._srtp_rtcp = SrtpSession.from_keying_material(
                tx_key=tx_master_key,
                rx_key=rx_master_key,
                is_rtp=False,
            )
            self.__srtp_rtcp_lock.set()
            print("[DTLS] _init_srtp: RTCP SRTP session created (Python + Rust crypto)")

            logger.info("SRTP sessions initialized with Python Session + Rust crypto")

            # Start internal receive loops to route incoming packets to streams
            asyncio.create_task(self._rtp_receive_loop())
            asyncio.create_task(self._rtcp_receive_loop())

        except Exception as e:
            logger.error(f"Failed to initialize SRTP: {e}")
            import traceback
            traceback.print_exc()
            # Signal completion so callers know handshake succeeded even if SRTP fails
            self.__srtp_rtp_lock.set()
            self.__srtp_rtcp_lock.set()

    async def enqueue_record(self, record_layer_bytes: bytes):
        """
        Enqueue incoming DTLS record for processing by Python FSM.

        Called when ICE transport receives a DTLS packet.
        A single UDP packet may contain multiple DTLS records (e.g., Flight 5).
        """
        print(f"[DTLS] enqueue_record: received {len(record_layer_bytes)} bytes")
        logger.info(f"enqueue_record: received {len(record_layer_bytes)} bytes")

        if not is_dtls_record_layer(record_layer_bytes):
            print(f"[DTLS] enqueue_record: non-DTLS packet (first byte: {record_layer_bytes[0] if record_layer_bytes else 'empty'})")
            logger.warning(f"enqueue_record: non-DTLS packet (first byte: {record_layer_bytes[0] if record_layer_bytes else 'empty'})")
            return

        try:
            from webrtc.dtls.dtls_record import RecordLayerBatch
            # Use RecordLayerBatch to iterate over all records in the packet
            record_count = 0
            for record, raw in RecordLayerBatch(record_layer_bytes):
                record_count += 1
                print(f"[DTLS] enqueue_record: parsed record #{record_count} content_type={record.header.content_type}, epoch={record.header.epoch}, seq={record.header.sequence_number}")
                logger.info(f"enqueue_record: parsed record #{record_count} content_type={record.header.content_type}, epoch={record.header.epoch}, seq={record.header.sequence_number}")
                await self.record_layer_chan.put((record, raw))
            print(f"[DTLS] enqueue_record: {record_count} record(s) added to queue (queue size: {self.record_layer_chan.qsize()})")
            logger.debug(f"enqueue_record: {record_count} record(s) added to queue (queue size now: {self.record_layer_chan.qsize()})")
        except Exception as e:
            print(f"[DTLS] enqueue_record: FAILED to parse: {e}")
            logger.error(f"enqueue_record: failed to parse DTLS record: {e}", exc_info=True)

    async def dequeue_record(self) -> bytes:
        """
        Dequeue outgoing DTLS record from Python FSM.

        Note: With Python FSM, records are sent directly via DTLSLocal.sendto().
        This method blocks forever since the Python FSM handles sending internally.
        The caller should not rely on this method for sending.
        """
        # Python FSM sends directly via DTLSLocal.sendto(), so this blocks forever
        # to prevent the caller from spinning in a tight loop.
        await asyncio.Event().wait()  # Never returns
        return bytes()

    async def wait_handshake(self, timeout: float | None = None) -> bool:
        """
        Wait for DTLS handshake to complete.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if handshake completed, False on timeout
        """
        try:
            await asyncio.wait_for(self.__handshake_complete.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def encrypt_rtp_bytes(self, data: bytes) -> bytes:
        """Encrypt RTP packet using SRTP (synchronous)."""
        if srtp := self._srtp_rtp:
            return srtp.encrypt(data)
        raise ValueError("SRTP not initialized")

    def encrypt_rtcp_bytes(self, data: bytes) -> bytes:
        """Encrypt RTCP packet using SRTP (synchronous)."""
        if srtp := self._srtp_rtcp:
            return srtp.encrypt(data)
        raise ValueError("SRTP not initialized")

    async def write_rtcp_bytes(self, data: bytes) -> int:
        """Write RTCP packet (encrypted via SRTP) and send to network."""
        await self.__srtp_rtcp_lock.wait()
        if not self._srtp_rtcp or not self.__transport:
            return 0
        try:
            # Encrypt synchronously (Rust crypto is fast)
            encrypted = self._srtp_rtcp.encrypt(data)
            # Send via ICE transport
            self.__transport.sendto(encrypted)
            return len(encrypted)
        except Exception as e:
            logger.error(f"Failed to send RTCP: {e}")
            return 0

    async def write_rtp_bytes(self, data: bytes) -> int:
        """Write RTP packet (encrypted via SRTP) and send to network."""
        await self.__srtp_rtp_lock.wait()
        if not self._srtp_rtp or not self.__transport:
            print(f"[DTLS] write_rtp_bytes: skipped - srtp={self._srtp_rtp is not None}, transport={self.__transport is not None}")
            return 0
        try:
            # Encrypt synchronously (Rust crypto is fast)
            encrypted = self._srtp_rtp.encrypt(data)
            # Send via ICE transport
            self.__transport.sendto(encrypted)
            return len(encrypted)
        except Exception as e:
            print(f"[DTLS] write_rtp_bytes: ERROR - {e}")
            logger.error(f"Failed to send RTP: {e}")
            import traceback
            traceback.print_exc()
            return 0

    async def srtp_rtp_stream(self, ssrc: int) -> SrtpStream:
        """Get or create SRTP stream for given SSRC."""
        await self.__srtp_rtp_lock.wait()
        if not self._srtp_rtp:
            raise ValueError("SRTP must be started to get the stream")
        return await self._srtp_rtp.open_stream(ssrc)

    async def srtp_rtcp_stream(self, ssrc: int) -> SrtpStream:
        """Get or create SRTCP stream for given SSRC."""
        await self.__srtp_rtcp_lock.wait()
        if not self._srtp_rtcp:
            raise ValueError("SRTP must be started to get the stream")
        return await self._srtp_rtcp.open_stream(ssrc)

    async def _rtp_receive_loop(self):
        """Internal loop that reads RTP from ICE and routes to SRTP streams."""
        if not self.__transport:
            logger.error("No transport for RTP receive loop")
            return

        logger.info("RTP receive loop started")
        while True:
            try:
                packet = await self.__transport.recv_rtp()
                if self._srtp_rtp:
                    await self._srtp_rtp.write_incoming(packet.data)
            except Exception as e:
                logger.error(f"RTP receive loop error: {e}")
                await asyncio.sleep(0.1)

    async def _rtcp_receive_loop(self):
        """Internal loop that reads RTCP from ICE and routes to SRTP streams."""
        if not self.__transport:
            logger.error("No transport for RTCP receive loop")
            return

        logger.info("RTCP receive loop started")
        while True:
            try:
                packet = await self.__transport.recv_rtcp()
                if self._srtp_rtcp:
                    await self._srtp_rtcp.write_incoming(packet.data)
            except Exception as e:
                logger.error(f"RTCP receive loop error: {e}")
                import traceback
                traceback.print_exc()
                await asyncio.sleep(0.1)
