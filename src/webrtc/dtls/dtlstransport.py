import asyncio
from enum import Enum
from typing import Protocol

from OpenSSL import SSL
from pylibsrtp import Policy, Session

from webrtc import ice
from webrtc.ice import net

from .certificate import SRTPProtectionProfile, certificate_digest, Certificate, Fingerprint, SRTP_PROFILES


class DTLSRole(Enum):
    Auto = "auto"
    Server = "server"
    Client = "client"


class ICETransportDTLS(Protocol):
    def get_ice_role(self) -> ice.AgentRole: ...
    async def get_ice_pair_transport(self) -> ice.CandidatePairTransport | None: ...
    async def bind(self, transport: ice.CandidatePairTransport): ...

    # def get_ice_pair_transports(self) -> list[ice.CandidatePairTransport]: ...


class RTPReaderProtocol(Protocol):
    async def recv_rtp_bytes(self) -> bytes: ...


class DTLSTransport:
    def __init__(
        self, transport: ICETransportDTLS, certificate: Certificate
    ) -> None:
        self.__transport = transport

        self.__dtls_role: DTLSRole = DTLSRole.Auto
        self.__certificate = certificate
        # self.__media_fingerprints = list[dtls.Fingerprint]()

        self.__rx_srtp: Session | None = None
        self.__tx_srtp: Session | None = None

    async def bind(self, transport: ice.CandidatePairTransport):
        await self.__transport.bind(transport)

    def ice_transport(self) -> ICETransportDTLS:
        return self.__transport

    async def do_handshake_for(
        self,
        ssl: SSL.Connection,
        transport: ice.CandidatePairTransport,
        media_fingerprints: list[Fingerprint],
    ):
        print("Start candidate handshake")
        __encrypted = False
        while not __encrypted:
            try:
                ssl.do_handshake()
            except SSL.WantReadError:
                try:
                    print("Wait for dtls??")
                    dtls_pkt = await transport.recv_dtls()
                    ssl.bio_write(dtls_pkt.data)
                    try:
                        data = ssl.recv(1500)
                        if data:
                            print(f"Received data: {data}")
                    except SSL.ZeroReturnError as e:
                        print("Zero return", e)
                    except SSL.Error as e:
                        print("SSL error", e)

                    flight = ssl.bio_read(1500)
                    if flight:
                        transport.sendto(flight)
                        print(f"Sent flight data: {flight}")
                except SSL.WantReadError:
                    pass
            else:
                __encrypted = True

        x509 = ssl.get_peer_certificate()
        if x509 is None:
            print("Unable get x509 remotecandidate")
            return

        remote_fingerprint = certificate_digest(x509)
        remote_fingerprint_valid = False
        for f in media_fingerprints:
            print("media", f.value.lower(), "remote", remote_fingerprint.lower())
            if f.value.lower() == remote_fingerprint.lower():
                remote_fingerprint_valid = True
                break

        if not remote_fingerprint_valid:
            print("Invalid fingerprint not matched remote and media fingerprint")
            return

        openssl_profile = ssl.get_selected_srtp_profile()
        negotiated_profile: SRTPProtectionProfile

        for srtp_profile in SRTP_PROFILES:
            if srtp_profile.openssl_profile == openssl_profile:
                print(
                    "DTLS handshake negotiated with",
                    srtp_profile.openssl_profile.decode(),
                )
                negotiated_profile = srtp_profile
                break
        else:
            print("x DTLS handshake failed (no SRTP profile negotiated)")
            return

        view = ssl.export_keying_material(
            b"EXTRACTOR-dtls_srtp",
            2 * (negotiated_profile.key_length + negotiated_profile.salt_length),
        )

        if self.__dtls_role == DTLSRole.Server:
            srtp_tx_key = negotiated_profile.get_key_and_salt(view, 1)
            srtp_rx_key = negotiated_profile.get_key_and_salt(view, 0)
        else:
            srtp_tx_key = srtp_profile.get_key_and_salt(view, 0)
            srtp_rx_key = srtp_profile.get_key_and_salt(view, 1)

        rx_policy = Policy(
            key=srtp_rx_key,
            ssrc_type=Policy.SSRC_ANY_INBOUND,
            srtp_profile=srtp_profile.libsrtp_profile,
        )
        rx_policy.allow_repeat_tx = True
        rx_policy.window_size = 1024
        self.__rx_srtp = Session(rx_policy)

        tx_policy = Policy(
            key=srtp_tx_key,
            ssrc_type=Policy.SSRC_ANY_OUTBOUND,
            srtp_profile=srtp_profile.libsrtp_profile,
        )
        tx_policy.allow_repeat_tx = True
        tx_policy.window_size = 1024
        self.__tx_srtp = Session(tx_policy)
        print("Handshake completed??")

    async def start(self, media_fingerprints: list[Fingerprint]):
        # assert len(remote_fingerprints)
        print("Handshake start")

        transport = self.ice_transport()

        match transport.get_ice_role():
            case ice.AgentRole.Controlling:
                self.__dtls_role = DTLSRole.Server
            case ice.AgentRole.Controlled:
                self.__dtls_role = DTLSRole.Client

        print("Start DTLS role", self.__dtls_role)

        pair = await self.__transport.get_ice_pair_transport()
        if not pair:
            raise ValueError("Not found ice pair transport for dtls")

        ctx = self.__certificate.create_ssl_context(SRTP_PROFILES)
        ssl = SSL.Connection(ctx)

        match self.__dtls_role:
            case DTLSRole.Server:
                ssl.set_accept_state()
            case DTLSRole.Client:
                ssl.set_connect_state()

        asyncio.ensure_future(self.do_handshake_for(ssl, pair, media_fingerprints))

    def write_rtcp_bytes(self, data: bytes) -> int:
        # if not ice.net.is_rtcp(pkt.data):
        #     return 0
        #
        # if not self._tx_srtp:
        #     return 0
        # data = self._tx_srtp.protect_rtcp(pkt.data)
        # return len(data)
        print("TODO: Handle rtcp")
        return 0

    async def write_rtp_bytes(self, data: bytes) -> int:
        if not self.__tx_srtp:
            return 0

        transport = await self.__transport.get_ice_pair_transport()
        if not transport:
            return 0

        data = self.__tx_srtp.protect(data)
        transport.sendto(data)

        return len(data)

    async def read_rtp_bytes(self) -> tuple[bytes, int]:
        if not self.__rx_srtp:
            return bytes(), 0

        transport = await self.__transport.get_ice_pair_transport()
        if not transport:
            return bytes(), 0

        pkt = transport.recv_rtp_sync()
        data = self.__rx_srtp.unprotect(pkt.data)

        return data, len(data)
