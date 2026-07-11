import asyncio
import logging
import uuid
from enum import IntEnum
from typing import Protocol

from webrtc.dtls.certificate import Certificate
from webrtc.peer_context import spawn_peer_task
from webrtc.tracing import measure_perf_async

# Structured logging for DTLS handshake
logger = logging.getLogger("webrtc.dtls.fsm")
from webrtc.dtls.dtls_cipher_suite import Keypair
from webrtc.dtls.flight0 import Flight0
from webrtc.dtls.flight1 import Flight1
from webrtc.dtls.flight2 import Flight2
from webrtc.dtls.flight3 import Flight3
from webrtc.dtls.flight4 import Flight4
from webrtc.dtls.flight5 import Flight5
from webrtc.dtls.flight6 import Flight6

from webrtc.dtls.flight_state import FlightTransition, State, Flight
from webrtc.dtls.prf import SRTPKeyingMaterial
from webrtc.dtls.dtls_record import (
    CONTENT_TYPE_CLASSES,
    ContentType,
    Finished,
    Handshake,
    HandshakeMultipleMessages,
    Message,
    EncryptedHandshakeMessage,
    RecordLayer,
)

MAX_MTU = 1280

# RFC 6347 Section 4.2.4 - Retransmission timer constants
INITIAL_RETRANSMIT_TIMEOUT = 1.0  # 1 second initial timeout
MAX_RETRANSMIT_TIMEOUT = 60.0     # Maximum 60 seconds
MAX_RETRANSMISSIONS = 5           # Maximum retransmission attempts
HANDSHAKE_TIMEOUT = 30.0          # Total handshake timeout


class DTLSRemote(Protocol):
    async def sendto(self, data: bytes): ...


class FSMState(IntEnum):
    Errored = 0
    Preparing = 1
    Sending = 2
    Waiting = 3
    Finished = 4


FLIGHT_TRANSITIONS: dict[Flight, FlightTransition] = {
    # Server side
    Flight.FLIGHT0: Flight0(),
    Flight.FLIGHT2: Flight2(),
    Flight.FLIGHT4: Flight4(),
    Flight.FLIGHT6: Flight6(),
    # Client side
    Flight.FLIGHT1: Flight1(),
    Flight.FLIGHT3: Flight3(),
    Flight.FLIGHT5: Flight5(),
}


class FSM:
    def __init__(
        self,
        remote: DTLSRemote,
        certificate: Certificate,
        handshake_messages_chan: asyncio.Queue[Message],
        flight: Flight = Flight.FLIGHT0,
    ) -> None:
        if flight == Flight.FLIGHT0:
            self.is_server = True
        elif flight == Flight.FLIGHT1:
            self.is_server = False
        else:
            raise ValueError("FSM must be started as server or client")

        self.remote = remote
        self.handshake_message_chan = handshake_messages_chan

        self.state = State(remote, certificate, Keypair.generate_P256(), is_server=self.is_server)

        self.handshake_state_transition = asyncio.Queue[FSMState]()
        self.handshake_state_transition_lock = asyncio.Lock()

        self.handshake_state: FSMState = FSMState.Preparing
        self.flight: Flight = flight

        self.pending_record_layers: list[RecordLayer] | None = None

        # Handshake completion signaling
        self.handshake_complete = asyncio.Event()
        self._srtp_keying_material: SRTPKeyingMaterial | None = None

        # Retransmission state (RFC 6347 Section 4.2.4)
        self._retransmit_timeout = INITIAL_RETRANSMIT_TIMEOUT
        self._retransmit_count = 0
        self._last_sent_flight: bytes | None = None
        self._last_received_flight: Flight | None = None
        self._handshake_start_time: float | None = None

    def get_srtp_keying_material(self) -> SRTPKeyingMaterial | None:
        """
        Get SRTP keying material after handshake completion.

        Returns None if handshake is not yet complete.
        """
        return self._srtp_keying_material

    async def wait_handshake_complete(self, timeout: float | None = None) -> bool:
        """
        Wait for handshake to complete.

        Args:
            timeout: Maximum time to wait in seconds (None = no timeout)

        Returns:
            True if handshake completed, False on timeout
        """
        try:
            await asyncio.wait_for(self.handshake_complete.wait(), timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def _reset_retransmit_state(self) -> None:
        """Reset retransmission state after successful flight transition."""
        self._retransmit_timeout = INITIAL_RETRANSMIT_TIMEOUT
        self._retransmit_count = 0

    def _increase_retransmit_timeout(self) -> None:
        """Implement exponential backoff for retransmission timer (RFC 6347)."""
        self._retransmit_timeout = min(
            self._retransmit_timeout * 2,
            MAX_RETRANSMIT_TIMEOUT
        )
        self._retransmit_count += 1

    def _check_handshake_timeout(self) -> bool:
        """
        Check if the overall handshake timeout has been exceeded.

        Returns:
            True if timeout exceeded, False otherwise
        """
        if self._handshake_start_time is None:
            return False
        import time
        elapsed = time.time() - self._handshake_start_time
        return elapsed > HANDSHAKE_TIMEOUT

    def _is_duplicate_flight(self, flight: Flight) -> bool:
        """
        Detect if the received flight is a duplicate (retransmission from peer).

        Per RFC 6347, receiving a duplicate flight should trigger retransmission
        of the last sent flight.

        Args:
            flight: The flight number of the received message

        Returns:
            True if this is a duplicate flight, False otherwise
        """
        return self._last_received_flight == flight

    async def dispatch(self):
        metadata = {
            "flow_direction": "rx",
            "operation_id": uuid.uuid4().hex,
            "flight": self.flight.name,
            "fsm_state": self.handshake_state.name,
        }
        async with measure_perf_async(
            "dtls",
            "fsm.dispatch",
            metadata=metadata,
        ):
            try:
                async with self.handshake_state_transition_lock:
                    await self.handshake_state_transition.put(self.handshake_state)
            except Exception:
                metadata.update(
                    error_stage="state_transition_enqueue",
                    **{"counter.dtls.fsm_dispatch_failed": 1},
                )
                raise

    async def prepare(self) -> FSMState:
        # print("Prepare state", self.flight)
        flight = FLIGHT_TRANSITIONS.get(self.flight)
        if not flight:
            # TODO: DTLS alerting
            return FSMState.Errored

        try:
            self.pending_record_layers = flight.generate(self.state)
        except Exception as e:
            logger.error(f"FSM generate error in flight {self.flight}: {e}")
            raise e

        try:
            if self.pending_record_layers:
                for record in self.pending_record_layers:
                    if self.is_server or not record.header.sequence_number:
                        record.header.sequence_number += (
                            self.state.handshake_sequence_number
                        )
                        self.state.handshake_sequence_number += 1

                    # epoch += 1
                    #
                    #     if record.header.epoch > next_epoch:
                    #         next_epoch = record.header.epoch

                    if record.header.content_type == ContentType.HANDSHAKE:
                        if not isinstance(record.content, Handshake):
                            continue

                        # Update message_sequence to be continuous across all flights
                        # (like Rust's handshake_send_sequence)
                        record.content.header.message_sequence = self.state.handshake_send_sequence
                        print(f"[FSM] prepare: {record.content.message.message_type.name} gets msg_seq={self.state.handshake_send_sequence}")
                        self.state.handshake_send_sequence += 1

                        # record.header.sequence_number = (
                        #     self.state.handshake_sequence_number
                        # )
                        # self.state.handshake_sequence_number += 1

                        self.state.cache.put_and_notify_once(
                            False,
                            record.header.epoch,
                            record.content.message.message_type,
                            record.content.marshal(),
                            record.content.header.message_sequence,
                        )

        except Exception as e:
            logger.error(f"FSM prepare error in flight {self.flight}: {e}")
            raise e

        # if epoch != next_epoch:
        #     self.state.local_epoch = next_epoch

        return FSMState.Sending

    async def send(self) -> FSMState:
        # print("Send state", self.flight, "pending", self.pending_record_layers)
        # print("Send state", self.flight)

        # Start handshake timer on first send
        if self._handshake_start_time is None:
            import time
            self._handshake_start_time = time.time()

        if not self.pending_record_layers:
            return FSMState.Waiting

        send_batch = bytes()

        print(f"[FSM] send: Flight {self.flight}, sending {len(self.pending_record_layers)} record(s)")

        # TODO: message batch
        for idx, layer in enumerate(self.pending_record_layers):
            data = layer.marshal()
            print(f"[FSM] send: record {idx}: content_type={layer.header.content_type}, epoch={layer.header.epoch}, seq={layer.header.sequence_number}, len={len(data)}, encrypt={getattr(layer, 'encrypt', False)}")

            try:
                if layer.encrypt:
                    if not self.state.pending_cipher_suite:
                        raise ValueError(
                            "layer data must be encrypted but cipher suite undefined"
                        )

                    layer.header.sequence_number = 0
                    data = layer.marshal()

                    logger.debug(f"Send seq number: {layer.header.sequence_number}")
                    print(f"[FSM] send: encrypting layer content_type={layer.header.content_type}, epoch={layer.header.epoch}")
                    print(f"[FSM] send: plaintext payload ({len(data[layer.header_size():])} bytes): {data[layer.header_size():].hex()}")

                    data = self.state.pending_cipher_suite.encrypt(layer)
                    if not data:
                        raise ValueError("None data after encrypt,")
                    print(f"[FSM] send: encrypted result ({len(data)} bytes): {data.hex()}")

                if len(data) > MAX_MTU and len(send_batch) > MAX_MTU:
                    raise ValueError(
                        "layer data has too much bytes. Message must be fragmented"
                    )

                send_batch += data

            except Exception as e:
                # TODO: backoff
                logger.error(f"Unable to send packet: {e}, layer={layer}")
                await asyncio.sleep(10)
                return FSMState.Sending

        print(f"[FSM] send: total send_batch ({len(send_batch)} bytes): {send_batch.hex()}")
        await self.remote.sendto(send_batch)

        # Store last sent flight for retransmission
        self._last_sent_flight = send_batch

        # Check if handshake is complete (after sending Flight6 - server Finished)
        if self.flight == Flight.FLIGHT6 and not self.handshake_complete.is_set():
            self._complete_handshake()

        return FSMState.Waiting

    def _complete_handshake(self) -> None:
        """
        Complete the handshake and derive SRTP keying material.

        Called after Flight6 (server Finished) is sent.
        """
        try:
            # Derive SRTP keying material
            self._srtp_keying_material = self.state.get_srtp_keying_material()
            logger.info(f"SRTP keys derived: client_key={len(self._srtp_keying_material.client_write_key)}B, "
                        f"server_key={len(self._srtp_keying_material.server_write_key)}B, "
                        f"client_salt={len(self._srtp_keying_material.client_write_salt)}B, "
                        f"server_salt={len(self._srtp_keying_material.server_write_salt)}B")

            # Signal handshake completion
            self.handshake_complete.set()
            logger.info("DTLS handshake complete!")
        except Exception as e:
            logger.error(f"Error deriving SRTP keys: {e}")

    async def wait(self) -> FSMState:
        flight = FLIGHT_TRANSITIONS.get(self.flight)
        if not flight:
            return FSMState.Errored

        # Check overall handshake timeout
        if self._check_handshake_timeout():
            logger.error("Handshake timeout exceeded")
            return FSMState.Errored

        # Wait for next flight with retransmission timeout
        try:
            new_flight = await asyncio.wait_for(
                flight.parse(self.state, self.handshake_message_chan),
                timeout=self._retransmit_timeout
            )

            # Check for duplicate flight (peer retransmission)
            if self._is_duplicate_flight(new_flight):
                logger.debug(f"Duplicate flight {new_flight} detected, retransmitting last flight")
                # Retransmit last sent flight
                if self._last_sent_flight:
                    await self.remote.sendto(self._last_sent_flight)
                return FSMState.Waiting

            # Check if handshake is complete (client-side: Flight5.parse returns None)
            if new_flight is None:
                logger.info("FSM: Client-side handshake complete (Flight5 received server Finished)")
                self._complete_handshake()
                return FSMState.Finished

            # If parse() returns the same flight, it means we received retransmitted
            # messages from peer. Retransmit our last sent flight and stay waiting.
            if new_flight == self.flight:
                logger.debug(f"Flight{self.flight.value}.parse() returned same flight - peer retransmission detected")
                if self._last_sent_flight:
                    logger.debug(f"Retransmitting last sent flight ({len(self._last_sent_flight)} bytes)")
                    await self.remote.sendto(self._last_sent_flight)
                return FSMState.Waiting

            # Successful transition - reset retransmit state
            self._last_received_flight = self.flight
            self.flight = new_flight
            self._reset_retransmit_state()

        except asyncio.TimeoutError:
            # Retransmission timeout - check if we should retry
            if self._retransmit_count >= MAX_RETRANSMISSIONS:
                logger.error(f"Max retransmissions ({MAX_RETRANSMISSIONS}) exceeded")
                return FSMState.Errored

            logger.warning(f"Retransmission timeout ({self._retransmit_timeout}s), attempt {self._retransmit_count + 1}/{MAX_RETRANSMISSIONS}")
            self._increase_retransmit_timeout()

            # Retransmit last flight
            if self._last_sent_flight:
                await self.remote.sendto(self._last_sent_flight)

            return FSMState.Waiting

        except Exception as e:
            logger.error(f"transition Flight{flight} error: {e}")
            return FSMState.Errored

        # If we're at Flight 6 and handshake is complete, we're done
        if self.flight == Flight.FLIGHT6 and self.handshake_complete.is_set():
            logger.info("FSM: Handshake complete, transitioning to Finished state")
            return FSMState.Finished

        return FSMState.Preparing

    async def finish(self) -> FSMState: ...

    async def run(self):
        while True:
            next_state = await self.handshake_state_transition.get()

            async with self.handshake_state_transition_lock:
                while True:
                    if self.handshake_state_transition.empty() and not next_state:
                        logger.debug("Handshake state transition done")
                        break

                    handshake_state = (
                        next_state or await self.handshake_state_transition.get()
                    )
                    # print("after next_state lock", next_state)
                    if next_state:
                        next_state = None

                    match handshake_state:
                        case FSMState.Preparing:
                            await self.handshake_state_transition.put(
                                await self.prepare(),
                            )
                        case FSMState.Sending:
                            await self.handshake_state_transition.put(
                                await self.send(),
                            )
                        case FSMState.Waiting:
                            await self.handshake_state_transition.put(
                                await self.wait(),
                            )
                        case FSMState.Errored:
                            logger.error("FSM Error occurred, retrying...")
                            await asyncio.sleep(4)
                            await self.handshake_state_transition.put(
                                FSMState.Preparing
                            )
                        case FSMState.Finished:
                            logger.info("FSM: Handshake finished successfully!")
                            print("[FSM] Handshake finished successfully!")
                            return  # Exit the FSM run loop

                        case _:
                            break


# TODO: Validate epoch
# TODO: Anti-replay protection
# TODO: Decrypt
class DTLSConn:
    def __init__(
        self,
        remote: DTLSRemote,
        certificate: Certificate,
        layer_chan: asyncio.Queue[tuple[RecordLayer, bytes]],
        flight: Flight = Flight.FLIGHT0,
    ) -> None:
        self.record_layer_chan = layer_chan

        self.handshake_message_chan = asyncio.Queue[Message]()
        self.fsm = FSM(remote, certificate, self.handshake_message_chan, flight)
        self.recv_lock = asyncio.Lock()

    @property
    def handshake_complete(self) -> asyncio.Event:
        """Event signaling handshake completion."""
        return self.fsm.handshake_complete

    def get_srtp_keying_material(self) -> SRTPKeyingMaterial | None:
        """Get SRTP keying material after handshake completion."""
        return self.fsm.get_srtp_keying_material()

    async def wait_handshake_complete(self, timeout: float | None = None) -> bool:
        """Wait for handshake to complete."""
        return await self.fsm.wait_handshake_complete(timeout)

    def __handle_encrypted_message(
        self, layer: RecordLayer, raw: bytes, message: EncryptedHandshakeMessage
    ):
        logger.info(f"__handle_encrypted_message: processing encrypted message, epoch={layer.header.epoch}, seq={layer.header.sequence_number}")

        if not self.fsm.state.cipher_suite:
            logger.warning("__handle_encrypted_message: cipher_suite is None, cannot decrypt")
            return

        cipher_suite = self.fsm.state.cipher_suite
        logger.debug(f"__handle_encrypted_message: using cipher_suite, has_gcm={hasattr(cipher_suite, 'gcm') and cipher_suite.gcm is not None}")

        try:
            logger.debug(f"__handle_encrypted_message: attempting decrypt, raw_length={len(raw)}")
            if result := cipher_suite.decrypt(layer, raw):
                logger.info(f"__handle_encrypted_message: decrypt successful, result_length={len(result)}")

                record = RecordLayer.unmarshal(result, decrypted=True)
                logger.debug(f"__handle_encrypted_message: decrypted record content_type={record.header.content_type}")

                if isinstance(record.content, Handshake):
                    logger.info(f"__handle_encrypted_message: decrypted handshake message_type={record.content.message.message_type}")

                    self.fsm.state.cache.put_and_notify_once(
                        True,
                        record.header.epoch,
                        record.content.message.message_type,
                        result[13:],
                        record.content.header.message_sequence,
                    )
                    self.handshake_message_chan.put_nowait(record.content.message)
                    logger.info("__handle_encrypted_message: message added to cache and channel")

                return
        except Exception as e:
            logger.error(f"__handle_encrypted_message: decrypt error: {e}", exc_info=True)
            return

        logger.warning(f"__handle_encrypted_message: decrypt returned None/empty")

    async def handle_inbound_record_layers(self):
        print("[FSM] handle_inbound_record_layers: STARTED")
        logger.info("handle_inbound_record_layers: starting inbound message handler")
        fsm_runnable = spawn_peer_task(
            self.fsm.run(),
            name="dtls:fsm",
            component="dtls",
            kind="dtls",
            metadata={"expected_long_running": True, "loop_role": "fsm"},
        )

        # Queue for encrypted messages that arrive before cipher suite is ready
        pending_encrypted: list[tuple[RecordLayer, bytes, EncryptedHandshakeMessage]] = []

        try:
            while True:
                record_layer, raw = await self.record_layer_chan.get()
                print(f"[FSM] handle_inbound: GOT record content_type={record_layer.header.content_type}, epoch={record_layer.header.epoch}, seq={record_layer.header.sequence_number}")
                logger.info(f"handle_inbound: received record content_type={record_layer.header.content_type}, epoch={record_layer.header.epoch}, seq={record_layer.header.sequence_number}, length={len(raw)}")

                match record_layer.header.content_type:
                    case ContentType.CHANGE_CIPHER_SPEC:
                        print("[FSM] handle_inbound: CHANGE_CIPHER_SPEC received")
                        logger.info("handle_inbound: CHANGE_CIPHER_SPEC received")
                        # Wait for cipher suite to be ready (Flight4 must call __setup_cipher_suite first)
                        # This ensures pending_cipher_suite.start() has been called
                        logger.info("handle_inbound: waiting for cipher_suite_ready event...")
                        try:
                            await asyncio.wait_for(
                                self.fsm.state.cipher_suite_ready.wait(),
                                timeout=5.0  # 5 second timeout
                            )
                            logger.info("handle_inbound: cipher_suite_ready event received")
                        except asyncio.TimeoutError:
                            logger.error("handle_inbound: TIMEOUT waiting for cipher_suite_ready (5s)")
                            continue

                        self.fsm.state.cipher_suite = self.fsm.state.pending_cipher_suite
                        logger.info("handle_inbound: cipher_suite activated from pending_cipher_suite")

                        # Process any pending encrypted messages now that cipher suite is ready
                        if pending_encrypted:
                            logger.info(f"handle_inbound: processing {len(pending_encrypted)} pending encrypted messages")
                        for layer, raw_data, msg in pending_encrypted:
                            logger.debug("handle_inbound: processing queued encrypted message")
                            self.__handle_encrypted_message(layer, raw_data, msg)
                        pending_encrypted.clear()

                    case ContentType.HANDSHAKE:
                        if record_layer.header.epoch > 0:
                            logger.info(f"handle_inbound: encrypted HANDSHAKE (epoch={record_layer.header.epoch})")
                            if isinstance(
                                record_layer.content, EncryptedHandshakeMessage
                            ):
                                # Check if cipher suite is ready for decryption
                                cs = self.fsm.state.cipher_suite
                                if cs and hasattr(cs, 'gcm') and cs.gcm:
                                    logger.info("handle_inbound: cipher suite ready, decrypting now")
                                    self.__handle_encrypted_message(
                                        record_layer, raw, record_layer.content
                                    )
                                else:
                                    # Queue for later processing
                                    logger.info("handle_inbound: cipher suite NOT ready, queueing encrypted message")
                                    pending_encrypted.append((record_layer, raw, record_layer.content))
                                continue
                        else:
                            logger.debug(f"handle_inbound: unencrypted HANDSHAKE (epoch=0)")

                        if isinstance(record_layer.content, HandshakeMultipleMessages):
                            for (
                                handshake,
                                raw,
                            ) in record_layer.content.handshake_messages:
                                if not raw == handshake.marshal():
                                    raise ValueError("Different message")

                                self.fsm.state.cache.put_and_notify_once(
                                    True,
                                    record_layer.header.epoch,
                                    handshake.message.message_type,
                                    raw,
                                    handshake.header.message_sequence,
                                )
                                await self.handshake_message_chan.put(handshake.message)

                        if isinstance(record_layer.content, Handshake):
                            self.fsm.state.cache.put_and_notify_once(
                                True,
                                record_layer.header.epoch,
                                record_layer.content.message.message_type,
                                raw[13:],
                                record_layer.content.header.message_sequence,
                            )

                            await self.handshake_message_chan.put(
                                record_layer.content.message,
                            )

                        # elif isinstance(
                        #     record_layer.content, EncryptedHandshakeMessage
                        # ):
                        #     await self.__handle_encrypted_message(
                        #         record_layer, record_layer.content
                        #     )

                        # await self.fsm.dispatch()
                    case ContentType.ALERT:
                        # Handle Alert messages
                        from webrtc.dtls.dtls_record import Alert
                        if isinstance(record_layer.content, Alert):
                            print(f"[FSM] handle_inbound: ALERT received - level={record_layer.content.level}, description={record_layer.content.description}")
                            logger.warning(f"handle_inbound: ALERT received - level={record_layer.content.level}, description={record_layer.content.description}")
                        else:
                            print(f"[FSM] handle_inbound: Encrypted ALERT received (epoch={record_layer.header.epoch})")
                            logger.warning(f"handle_inbound: Encrypted ALERT (epoch={record_layer.header.epoch})")
                            # Try to decrypt the alert
                            cs = self.fsm.state.cipher_suite
                            if cs and hasattr(cs, 'gcm') and cs.gcm:
                                try:
                                    decrypted = cs.decrypt(record_layer, raw)
                                    if decrypted and len(decrypted) >= 15:  # 13 header + 2 alert
                                        alert_level = decrypted[13]
                                        alert_desc = decrypted[14]
                                        print(f"[FSM] Decrypted ALERT: level={alert_level}, description={alert_desc}")
                                        # Alert descriptions: 20=bad_record_mac, 40=handshake_failure, 51=decrypt_error
                                        alert_names = {20: "bad_record_mac", 40: "handshake_failure", 51: "decrypt_error", 10: "unexpected_message"}
                                        print(f"[FSM] Alert meaning: {alert_names.get(alert_desc, 'unknown')}")
                                except Exception as e:
                                    print(f"[FSM] Failed to decrypt alert: {e}")
                    case _:
                        logger.warning(
                            f"Unhandled record type: {record_layer.header.content_type}"
                        )

        except Exception as e:
            logger.error(f"DTLS handle inbound record layers error: {e}")
        finally:
            fsm_runnable.cancel()
