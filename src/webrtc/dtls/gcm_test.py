import binascii

from tests import testutils
from webrtc.dtls.dtls_record import (
    ContentType,
    DTLSVersion,
    EncryptedHandshakeMessage,
    Finished,
    Handshake,
    HandshakeHeader,
    HandshakeMessageType,
    RecordHeader,
    RecordLayer,
)

from webrtc.dtls.gcm import GCMCipherRecordLayer


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


class Test_GMCipherRecordLayer_Done:
    def setup_class(self):
        keys = testutils.stub_prf_encryption_keys()
        self.server = GCMCipherRecordLayer(
            keys.server_write_key,
            keys.server_write_iv,
            keys.client_write_key,
            keys.client_write_iv,
        )
        self.client = GCMCipherRecordLayer(
            keys.client_write_key,
            keys.client_write_iv,
            keys.server_write_key,
            keys.server_write_iv,
        )

    def test_record_layer_encrypt_decrypt(self):
        raw = pkt.marshal()
        print("Raw", binascii.hexlify(raw))

        encoded = self.server.encrypt(pkt)
        assert encoded
        print("Encoded", binascii.hexlify(encoded))

        encoded = RecordLayer.unmarshal(encoded)

        assert isinstance(encoded.content, EncryptedHandshakeMessage)

        decrypted_content = self.client.decrypt(
            encoded.header, encoded.content.encrypted_payload
        )

        decrypted = binascii.hexlify(decrypted_content)
        expected = binascii.hexlify(pkt.content.marshal())

        print("Decrypted", decrypted, "Expected", expected)

        for dec_nth, exp_nth in zip(decrypted, expected):
            assert dec_nth == exp_nth
