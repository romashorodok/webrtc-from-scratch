import ipaddress

# Constants
IPV4_PROTOCOL = 0x01  # Example value, adjust according to your actual protocol value
IPV6_PROTOCOL = 0x02  # Example value, adjust according to your actual protocol value

# Pack Address Function
def pack_address(value: tuple[str, int]) -> bytes:
    ip_address = ipaddress.ip_address(value[0])
    if isinstance(ip_address, ipaddress.IPv4Address):
        protocol = IPV4_PROTOCOL
    else:
        protocol = IPV6_PROTOCOL

    print("pack_address addr", list(ip_address.packed))
    return (
        b"\x00"
        + protocol.to_bytes(1, "big")
        + value[1].to_bytes(2, "big")
        + ip_address.packed
    )

# Unpack Address Function
def unpack_address(data: bytes) -> tuple[str, int]:
    print(f"Data received for unpacking: {list(data)}")
    if len(data) < 8:  # Adjusted length check considering protocol, port, and address
        raise ValueError("STUN address length is less than 8 bytes")

    protocol = data[1]
    port = int.from_bytes(data[2:4], "big")
    address = data[4:]

    if protocol == IPV4_PROTOCOL:
        if len(address) != 4:
            raise ValueError(f"STUN address has invalid length for IPv4: {len(address)}")
        ip_str = str(ipaddress.IPv4Address(address))
    elif protocol == IPV6_PROTOCOL:
        if len(address) != 16:
            raise ValueError(f"STUN address has invalid length for IPv6: {len(address)}")
        ip_str = str(ipaddress.IPv6Address(address))
    else:
        raise ValueError("STUN address has unknown protocol")

    print(f"Unpacked address: protocol={protocol}, port={port}, address={ip_str}")
    return (ip_str, port)

# Test Function
def test():
    address = ("192.168.0.101", 8080)
    packed_address = pack_address(address)
    print(f"Packed address: {list(packed_address)}")

    unpacked_address = unpack_address(packed_address)  # Pass the full packed address
    print(f"Unpacked address: {unpacked_address}")

test()

