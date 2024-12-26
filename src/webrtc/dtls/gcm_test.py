import binascii
from hashlib import sha256

from webrtc.dtls.dtlstransport import (
    ContentType,
    DTLSVersion,
    EncryptedHandshakeMessage,
    Finished,
    Handshake,
    HandshakeHeader,
    HandshakeMessageType,
    Keypair,
    Random,
    RecordHeader,
    RecordLayer,
    prf_master_secret,
)
from webrtc.dtls.gcm import GCM, prf_generate_encryption_keys

_PRF_MAC_LEN = 0
_PRF_KEY_LEN = 16
_PRF_IV_LEN = 4


class TestGCMEncodeDecodeDone:
    def setup_class(self):
        keypair = Keypair.generate_P256()

        encoder_random, decoder_random = Random(), Random()
        encoder_random.populate()
        decoder_random.populate()

        pre_master_secret = keypair.generate_shared_key()

        master_secret = prf_master_secret(
            pre_master_secret,
            encoder_random.marshal_fixed(),
            decoder_random.marshal_fixed(),
            sha256,
        )

        keys = prf_generate_encryption_keys(
            master_secret,
            encoder_random.marshal_fixed(),
            decoder_random.marshal_fixed(),
            _PRF_MAC_LEN,
            _PRF_KEY_LEN,
            _PRF_IV_LEN,
        )
        if not keys:
            raise ValueError("Unable prf enc keys")

        self.encoder = GCM(
            keys.server_write_key,
            keys.server_write_iv,
            keys.client_write_key,
            keys.client_write_iv,
        )
        self.decoder = GCM(
            keys.client_write_key,
            keys.client_write_iv,
            keys.server_write_key,
            keys.server_write_iv,
        )

    def test_record_layer_encrypt_decrypt(self):
        pkt = RecordLayer(
            header=RecordHeader(
                content_type=ContentType.HANDSHAKE,
                version=DTLSVersion.V1_2,
                epoch=1,
                sequence_number=0,
            ),
            content=Handshake(
                header=HandshakeHeader(
                    handshake_type=HandshakeMessageType.Finished,
                    message_sequence=1,
                    fragment_offset=0,
                ),
                message=Finished(bytes()),
            ),
        )
        raw = pkt.marshal()
        print("Raw", binascii.hexlify(raw))

        encoded = self.encoder.encrypt(pkt, raw)
        assert encoded
        print("Encoded", binascii.hexlify(encoded))

        encoded = RecordLayer.unmarshal(encoded)

        assert isinstance(encoded.content, EncryptedHandshakeMessage)

        decrypted_content = self.decoder.decrypt(
            encoded.header, encoded.content.encrypted_payload
        )

        decrypted = binascii.hexlify(decrypted_content)
        expected = binascii.hexlify(pkt.content.marshal())
        print("Decrypted", decrypted, "Expected", expected)
        for dec_nth, exp_nth in zip(decrypted, expected):
            assert dec_nth == exp_nth
