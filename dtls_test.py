class DtlsRecordLayer:
    def __init__(
        self, content_type, version, epoch, sequence_number, length, data, connection_id
    ):
        self.content_type = content_type
        self.version = version
        self.epoch = epoch
        self.sequence_number = sequence_number
        self.length = length
        self.data = data
        self.connection_id = connection_id

    def marshal(self):
        # Convert attributes to a byte representation
        # Structuring: content_type | version | epoch | sequence_number | length | data | connection_id
        version_bytes = self.version.to_bytes(2, byteorder="big")
        epoch_bytes = self.epoch.to_bytes(2, byteorder="big")
        sequence_number_bytes = self.sequence_number.to_bytes(
            6, byteorder="big"
        )  # 48-bit sequence number
        length_bytes = self.length.to_bytes(2, byteorder="big")

        # Create the marshalled byte sequence
        return (
            bytes([self.content_type])
            + version_bytes
            + epoch_bytes
            + sequence_number_bytes
            + length_bytes
            + self.data
            + self.connection_id
        )

    @staticmethod
    def unmarshal(data):
        # Extract the components of the marshalled data
        content_type = data[0]
        version = int.from_bytes(data[1:3], byteorder="big")
        epoch = int.from_bytes(data[3:5], byteorder="big")
        sequence_number = int.from_bytes(
            data[5:11], byteorder="big"
        )  # 48-bit sequence number
        length = int.from_bytes(data[11:13], byteorder="big")
        data_field = data[13 : 13 + length]  # Extract data based on length
        connection_id = data[13 + length :]

        return DtlsRecordLayer(
            content_type,
            version,
            epoch,
            sequence_number,
            length,
            data_field,
            connection_id,
        )


# Test Cases


def test_dtls_record_layer():
    # Test 1: Basic Record with Minimal Data
    record1 = DtlsRecordLayer(
        content_type=23,  # Application Data
        version=0x0303,  # TLS 1.2
        epoch=26,
        sequence_number=0,
        length=0,
        data=b"",
        connection_id=b"\x00\x00",
    )

    marshalled1 = record1.marshal()
    print("Test 1 - Marshalled Data:", marshalled1)
    unmarshalled1 = DtlsRecordLayer.unmarshal(marshalled1)
    print("Test 1 - Unmarshalled Record:", unmarshalled1.__dict__)

    # Test 2: Record with Non-Zero Length and Connection ID
    record2 = DtlsRecordLayer(
        content_type=22,  # Handshake
        version=0x0304,  # TLS 1.3
        epoch=100,
        sequence_number=12345,
        length=50,
        data=b"1234567890" * 5,  # 50 bytes of dummy data
        connection_id=b"\x12\x34\x56\x78\x90",
    )

    marshalled2 = record2.marshal()
    print("Test 2 - Marshalled Data:", marshalled2)
    unmarshalled2 = DtlsRecordLayer.unmarshal(marshalled2)
    print("Test 2 - Unmarshalled Record:", unmarshalled2.__dict__)

    # Test 3: Record with Large Sequence Number
    record3 = DtlsRecordLayer(
        content_type=23,  # Application Data
        version=0x0303,  # TLS 1.2
        epoch=1,
        sequence_number=0x0000FFFFFFFFFFFF,  # Max 48-bit value
        length=10,
        data=b"abcdefghij",  # 10 bytes of dummy data
        connection_id=b"\x01",
    )

    marshalled3 = record3.marshal()
    print("Test 3 - Marshalled Data:", marshalled3)
    unmarshalled3 = DtlsRecordLayer.unmarshal(marshalled3)
    print("Test 3 - Unmarshalled Record:", unmarshalled3.__dict__)


# Run tests
test_dtls_record_layer()
