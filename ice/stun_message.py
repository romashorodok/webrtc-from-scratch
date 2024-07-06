from ice import stun
from ice import net


def stun_message_parse_header(pkt: net.types.Packet) -> stun.Message:
    data = pkt.data

    if len(data) < stun.utils.MESSAGE_HEADER_LENGTH:
        raise ValueError("STUN data is too short to a header")

    msg_type = int.from_bytes(data[0:2], "big")
    msg_length = int.from_bytes(data[2:4], "big")
    cookie = int.from_bytes(data[4:8], "big")
    transaction_id = data[8:20]

    if cookie != stun.utils.COOKIE:
        raise ValueError("Invalid magic cookie")

    if msg_length != len(data[stun.utils.MESSAGE_HEADER_LENGTH :]):
        raise ValueError("Invalid message length")

    return stun.Message(stun.MessageType.from_int(msg_type), transaction_id)


def stun_message_parse_attrs(
    pkt: net.types.Packet, msg: stun.Message, pwd: bytes | None = None
) -> stun.Message:
    offset = stun.utils.MESSAGE_HEADER_LENGTH
    data = pkt.data[offset:]

    while len(data) > 0:
        attr_type = int.from_bytes(data[0:2], "big")
        attr_length = int.from_bytes(data[2:4], "big")

        if attr_type not in stun.attr.ATTRIBUTE_REGISTRY:
            print(
                f"STUN type not in registry or invalid deserialization: attr_type={attr_type}, attr_length={attr_length}",
            )
            total_length = stun.utils.ATTRIBUTE_HEADER_SIZE + attr_length
            padding_bytes_to_skip = stun.utils.nearest_padded_value_length(total_length)
            data = data[total_length + padding_bytes_to_skip :]
            offset += total_length + padding_bytes_to_skip
            continue

        attr_value = data[4 : 4 + attr_length]

        attr_cls = stun.attr.get_attribute_from_registry(attr_type)

        attr = attr_cls.unmarshal(
            data=bytearray(attr_value.tobytes()), transaction_id=msg.transaction_id
        )

        if isinstance(attr, stun.MessageIntegrity):
            if not pwd:
                raise ValueError("STUN message contain integrity provide key")

            expected_integrity = attr.value
            received_integrity = stun.utils.message_integrity(
                pkt.data[:offset].tobytes(), key=pwd
            )

            if expected_integrity != received_integrity:
                raise ValueError("STUN message integrity mismatch")

        elif isinstance(attr, stun.Fingerprint):
            expected_fingerprint = attr.value
            received_fingerprint = stun.utils.message_fingerprint(
                pkt.data[:offset].tobytes()
            )
            if expected_fingerprint != received_fingerprint:
                raise ValueError("STUN message fingerprint mismatch")
        else:
            msg.add_attribute(attr)

        total_length = stun.utils.ATTRIBUTE_HEADER_SIZE + attr_length
        padding_bytes_to_skip = stun.utils.nearest_padded_value_length(total_length)
        # print("Got padding", padding_bytes_to_skip)

        data = data[total_length + padding_bytes_to_skip :]
        offset += total_length + padding_bytes_to_skip

    return msg
