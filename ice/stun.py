MESSAGE_HEADER_SIZE = 20
MAGIC_COOKIE = 0x2112A442


def is_stun(b: bytes) -> bool:
    if len(b) < MESSAGE_HEADER_SIZE:
        return False
    extracted_value = (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7]
    return extracted_value == MAGIC_COOKIE


class Message:
    def __init__(self, data: bytes | None = None):
        self._data = data

        if self._data is not None:
            self._decode()

    def _decode(self):
        pass
