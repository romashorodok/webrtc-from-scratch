import secrets

_all_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

_ufrag_len = 16
_pwd_len = 32


def _random_string(length: int) -> str:
    return "".join(secrets.choice(_all_chars) for _ in range(length))


def generate_ufrag() -> str:
    return _random_string(_ufrag_len)


def generate_pwd() -> str:
    return _random_string(_pwd_len)
