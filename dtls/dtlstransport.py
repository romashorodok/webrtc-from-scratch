import asyncio
from enum import Enum
from typing import Protocol

from OpenSSL import SSL
from pylibsrtp import Policy, Session

import ice
import dtls

from .certificate import SRTPProtectionProfile, certificate_digest


class DTLSRole(Enum):
    Auto = "auto"
    Server = "server"
    Client = "client"


class ICETransportDTLS(Protocol):
    def get_ice_role(self) -> ice.AgentRole: ...
    def get_ice_pair_transports(self) -> list[ice.CandidatePairTransport]: ...


class DTLSTransport:
    def __init__(
        self, transport: ICETransportDTLS, certificate: dtls.Certificate
    ) -> None:
        self._transport = transport
        self._dtls_role: DTLSRole = DTLSRole.Auto
        self._certificate = certificate
        self.encrypted: bool = False

        self._media_fingerprints = list[dtls.Fingerprint]()

        self._rx_srtp: Session | None = None
        self._tx_srtp: Session | None = None

    def ice_transport(self) -> ICETransportDTLS:
        return self._transport

    async def do_handshake_for(
        self, ssl: SSL.Connection, transport: ice.CandidatePairTransport
    ):
        print("Start candidate handshake")
        encrypted = False
        while not encrypted:
            try:
                ssl.do_handshake()
            except SSL.WantReadError:
                pkt = await transport.recvfrom()
                first_byte = pkt.data[0]
                if first_byte > 19 and first_byte < 64:
                    ssl.bio_write(pkt.data)
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
            else:
                encrypted = True

        x509 = ssl.get_peer_certificate()
        if x509 is None:
            print("Unable get x509 remotecandidate")
            return

        remote_fingerprint = certificate_digest(x509)
        remote_fingerprint_valid = False
        for f in self._media_fingerprints:
            print("media", f.value.lower(), "remote", remote_fingerprint.lower())
            if f.value.lower() == remote_fingerprint.lower():
                remote_fingerprint_valid = True
                break

        if not remote_fingerprint_valid:
            print("Invalid fingerprint not matched remote and media fingerprint")
            return

        openssl_profile = ssl.get_selected_srtp_profile()
        negotiated_profile: SRTPProtectionProfile

        for srtp_profile in dtls.SRTP_PROFILES:
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

        # if self._role == "server":
        srtp_tx_key = negotiated_profile.get_key_and_salt(view, 1)
        srtp_rx_key = negotiated_profile.get_key_and_salt(view, 0)
        # else:
        #     srtp_tx_key = srtp_profile.get_key_and_salt(view, 0)
        #     srtp_rx_key = srtp_profile.get_key_and_salt(view, 1)

        rx_policy = Policy(
            key=srtp_rx_key,
            ssrc_type=Policy.SSRC_ANY_INBOUND,
            srtp_profile=srtp_profile.libsrtp_profile,
        )
        rx_policy.allow_repeat_tx = True
        rx_policy.window_size = 1024
        self._rx_srtp = Session(rx_policy)

        tx_policy = Policy(
            key=srtp_tx_key,
            ssrc_type=Policy.SSRC_ANY_OUTBOUND,
            srtp_profile=srtp_profile.libsrtp_profile,
        )
        tx_policy.allow_repeat_tx = True
        tx_policy.window_size = 1024
        self._tx_srtp = Session(tx_policy)
        print("Handshake completed??")

    async def start(self, remote_fingerprints: list[str] | None = None):
        # assert len(remote_fingerprints)

        transport = self.ice_transport()

        # match transport.get_ice_role():
        #     case ice.AgentRole.Controlling:
        self._dtls_role = DTLSRole.Server
        # case ice.AgentRole.Controlled:
        #     self._dtls_role = DTLSRole.Client

        for pair in transport.get_ice_pair_transports():
            ctx = self._certificate.create_ssl_context(dtls.SRTP_PROFILES)
            ssl = SSL.Connection(ctx)

            match self._dtls_role:
                case DTLSRole.Server:
                    ssl.set_accept_state()
                case DTLSRole.Client:
                    ssl.set_connect_state()

            asyncio.ensure_future(self.do_handshake_for(ssl, pair))

        # for pair in transport.get_ice_pair_transports():
        #     try:
        #         while not self.encrypted:
        #             self._ssl.do_handshake()
        #     except SSL.WantReadError:
        #         pkt = await pair.recvfrom()
        #
        #         first_byte = pkt.data[0]
        #         if first_byte > 19 and first_byte < 64:
        #             print("Is dtls packet")
        #
        #     except ConnectionError:
        #         print("DTLS handshake connection error")
        #         return
