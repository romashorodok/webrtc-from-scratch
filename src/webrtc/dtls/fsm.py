import asyncio
from enum import IntEnum
from typing import Protocol

from webrtc.dtls.certificate import Certificate
from webrtc.dtls.dtls_cipher_suite import Keypair
from webrtc.dtls.flight0 import Flight0
from webrtc.dtls.flight1 import Flight1
from webrtc.dtls.flight2 import Flight2
from webrtc.dtls.flight3 import Flight3
from webrtc.dtls.flight4 import Flight4
from webrtc.dtls.flight5 import Flight5
from webrtc.dtls.flight6 import Flight6

from webrtc.dtls.flight_state import FlightTransition, State, Flight
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
    # Flight.FLIGHT1: Flight1(),
    # Flight.FLIGHT3: Flight3(),
    # Flight.FLIGHT5: Flight5(),
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

        self.state = State(remote, certificate, Keypair.generate_P256())

        self.handshake_state_transition = asyncio.Queue[FSMState]()
        self.handshake_state_transition_lock = asyncio.Lock()

        self.handshake_state: FSMState = FSMState.Preparing
        self.flight: Flight = flight

        self.pending_record_layers: list[RecordLayer] | None = None

    async def dispatch(self):
        async with self.handshake_state_transition_lock:
            await self.handshake_state_transition.put(self.handshake_state)

    async def prepare(self) -> FSMState:
        # print("Prepare state", self.flight)
        flight = FLIGHT_TRANSITIONS.get(self.flight)
        if not flight:
            # TODO: DTLS alerting
            return FSMState.Errored

        try:
            self.pending_record_layers = flight.generate(self.state)
        except Exception as e:
            print("FSM catch:", e)
            raise e

        try:
            message_sequence = 1

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

                        if not len(self.pending_record_layers) == 1:
                            record.content.header.message_sequence = message_sequence
                            message_sequence += 1

                        # record.header.sequence_number = (
                        #     self.state.handshake_sequence_number
                        # )
                        # self.state.handshake_sequence_number += 1

                        self.state.cache.put_and_notify_once(
                            False,
                            record.header.epoch,
                            record.content.message.message_type,
                            record.content.message,
                        )

        except Exception as e:
            print("FSM prepere err", e)
            raise e

        # if epoch != next_epoch:
        #     self.state.local_epoch = next_epoch

        return FSMState.Sending

    async def send(self) -> FSMState:
        # print("Send state", self.flight, "pending", self.pending_record_layers)
        # print("Send state", self.flight)
        if not self.pending_record_layers:
            return FSMState.Waiting

        send_batch = bytes()

        # TODO: message batch
        for layer in self.pending_record_layers:
            data = layer.marshal()

            try:
                if layer.encrypt:
                    if not self.state.pending_cipher_suite:
                        raise ValueError(
                            "layer data must be encrypted but cipher suite undefined"
                        )

                    layer.header.sequence_number = 0
                    data = layer.marshal()

                    print("Send seq number", layer.header.sequence_number)

                    data = self.state.pending_cipher_suite.encrypt(layer)
                    if not data:
                        raise ValueError("None data after encrypt,")

                if len(data) > MAX_MTU and len(send_batch) > MAX_MTU:
                    raise ValueError(
                        "layer data has too much bytes. Message must be fragmented"
                    )

                send_batch += data

            except Exception as e:
                # TODO: backoff
                print("Unable send packet. Err:", e, "layer", layer)
                await asyncio.sleep(10)
                return FSMState.Sending

        await self.remote.sendto(send_batch)

        return FSMState.Waiting

    async def wait(self) -> FSMState:
        flight = FLIGHT_TRANSITIONS.get(self.flight)
        if not flight:
            return FSMState.Errored

        # print("wait transition", flight)

        # TODO: On client side I must wait and buffer from ServerHello until ServerHelloDone
        # TODO: This waiting must support also a batch send
        # TODO: When wait a messages make a timeout and fallback to the flight of DTLS role
        try:
            self.flight = await flight.parse(self.state, self.handshake_message_chan)
        except Exception as e:
            print(f"transition Flight{flight} error", e)
            return FSMState.Errored

        return FSMState.Preparing

    async def finish(self) -> FSMState: ...

    async def run(self):
        while True:
            next_state = await self.handshake_state_transition.get()

            async with self.handshake_state_transition_lock:
                while True:
                    if self.handshake_state_transition.empty() and not next_state:
                        print("Handshake state transition done")
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
                            print("FSM Error occured")
                            await asyncio.sleep(4)
                            await self.handshake_state_transition.put(
                                FSMState.Preparing
                            )

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

    def __handle_encrypted_message(
        self, layer: RecordLayer, raw: bytes, message: EncryptedHandshakeMessage
    ):
        if not self.fsm.state.cipher_suite:
            return

        if self.fsm.state.cipher_suite:
            cipher_suite = self.fsm.state.cipher_suite
        else:
            cipher_suite = self.fsm.state.pending_cipher_suite

        try:
            if result := cipher_suite.decrypt(layer, raw):
                # print("Got decrypted message result", result)

                record = RecordLayer.unmarshal(result, decrypted=True)
                print("Dec result??", record, record.content)

                # content_type_cls = CONTENT_TYPE_CLASSES.get(layer.header.content_type)
                # if not content_type_cls:
                #     raise ValueError("Unable find a content type for decrypted message")
                # content = content_type_cls.unmarshal(result)
                # print("Decrypted", content)

                if isinstance(record.content, Handshake):
                    print("Recv dec record success dec", record.content.message)
                    # layer.content = content
                    # layer.header.length = len(result)

                    # if isinstance(content, Finished):
                    #     content.encrypted_payload =

                    self.fsm.state.cache.put_and_notify_once(
                        True,
                        record.header.epoch,
                        record.content.message.message_type,
                        record.content.message,
                    )
                    self.handshake_message_chan.put_nowait(record.content.message)

                return
        except Exception as e:
            print("Decrypt error", e)
            print("Unable decrypt message", layer, message)
            return

        print("Unable decrypt message", layer, message)

    async def handle_inbound_record_layers(self):
        fsm_runnable = asyncio.create_task(self.fsm.run())

        try:
            while True:
                record_layer, raw = await self.record_layer_chan.get()
                print("recv record seq", record_layer.header.sequence_number)

                match record_layer.header.content_type:
                    case ContentType.CHANGE_CIPHER_SPEC:
                        if not self.fsm.state.cipher_suite:
                            self.fsm.state.cipher_suite = (
                                self.fsm.state.pending_cipher_suite
                            )

                    case ContentType.HANDSHAKE:
                        # if isinstance(record_layer.content, EncryptedHandshakeMessage):
                        #     await self.__handle_encrypted_message(
                        #         record_layer, record_layer.content
                        #     )
                        #     continue

                        if record_layer.header.epoch > 0:
                            if isinstance(
                                record_layer.content, EncryptedHandshakeMessage
                            ):
                                self.__handle_encrypted_message(
                                    record_layer, raw, record_layer.content
                                )
                                continue

                        if isinstance(record_layer.content, HandshakeMultipleMessages):
                            for (
                                handshake,
                                raw,
                            ) in record_layer.content.handshake_messages:
                                self.fsm.state.cache.put_and_notify_once(
                                    True,
                                    record_layer.header.epoch,
                                    handshake.message.message_type,
                                    handshake.message,
                                )
                                await self.handshake_message_chan.put(handshake.message)

                        if isinstance(record_layer.content, Handshake):
                            self.fsm.state.cache.put_and_notify_once(
                                True,
                                record_layer.header.epoch,
                                record_layer.content.message.message_type,
                                record_layer.content.message,
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
                    case _:
                        print(
                            "Unhandled record type of",
                            record_layer.header.content_type,
                        )

        except Exception as e:
            print("DTLS handle inbound record layers err", e)
        finally:
            fsm_runnable.cancel()
