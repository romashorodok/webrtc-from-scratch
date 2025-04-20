import secrets
import string


_ufrag_len = 16
_pwd_len = 32


def random_string(length: int) -> str:
    allchar = string.ascii_letters + string.digits
    return "".join(secrets.choice(allchar) for _ in range(length))


def generate_tie_breaker() -> int:
    return secrets.randbits(64)


def generate_ufrag() -> str:
    return random_string(_ufrag_len)


def generate_pwd() -> str:
    return random_string(_pwd_len)


def cmp(x: int, y: int) -> int:
    if x > y:
        return 1
    else:
        return 0
