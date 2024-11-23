# Client Hello, Length 193, Message Sequence 0, Fragment Offset 0, Fragment Length 193
from binascii import hexlify
import binascii
from webrtc.dtls.dtlstransport import Handshake


# data = b"010000c100000000000000c1"
# # DTLS 1.0
# data += b"feff"
# # Random
# data += b"24dc8f65fb5970f29af7f330b6a00942d71783db3230cba5bdb98213efdbb99f"
# # Session ID Length 0, Cookie Length 0
# data += b"0000"
# # Cipher Suites Length 78
# data += b"004e"
# # Cipher Suites 39
# data += b"c014c00a0039003800880087c00fc00500350084"
# data += b"c013c00900330032009a009900450044c00ec004"
# data += b"002f009600410007c012c00800160013c00dc003"
# data += b"000a001500120009001400110008000600ff"
# # Compression Methods Length 1: null
# data += b"0100"
#
# # Extensions, Length 73
# data += b"0049000b000403000102000a00340032000e000d"
# data += b"0019000b000c00180009000a0016001700080006"
# data += b"0007001400150004000500120013000100020003"
# data += b"000f0010001100230000000f000101"
#
# assert Handshake.unmarshal(binascii.unhexlify(data))

# DTLSv1.2 Record Layer: Handshake Protocol: Client Hello
#     Content Type: Handshake (22)
#     Version: DTLS 1.0 (0xfeff)
#     Epoch: 0
#     Sequence Number: 0
#     Length: 140
#     Handshake Protocol: Client Hello
#         Handshake Type: Client Hello (1)
#         Length: 128
#         Message Sequence: 0
#         Fragment Offset: 0
#         Fragment Length: 128
#         Version: DTLS 1.2 (0xfefd)
#         Random: 13b3ac327e56ae1c96882705b7e69b21cbc30df1695e244570eb7943635866b0
#             GMT Unix Time: Jun 22, 1980 20:15:30.000000000 MSK
#             Random Bytes: 7e56ae1c96882705b7e69b21cbc30df1695e244570eb7943635866b0
#         Session ID Length: 0
#         Cookie Length: 0
#         Cipher Suites Length: 22
#         Cipher Suites (11 suites)
#             Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
#             Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
#             Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
#             Cipher Suite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
#             Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
#             Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
#             Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
#             Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
#             Cipher Suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
#             Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
#             Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
#         Compression Methods Length: 1
#         Compression Methods (1 method)
#             Compression Method: null (0)
#         Extensions Length: 64
#         Extension: supported_groups (len=8)
#             Type: supported_groups (10)
#             Length: 8
#             Supported Groups List Length: 6
#             Supported Groups (3 groups)
#                 Supported Group: x25519 (0x001d)
#                 Supported Group: secp256r1 (0x0017)
#                 Supported Group: secp384r1 (0x0018)
#         Extension: extended_master_secret (len=0)
#             Type: extended_master_secret (23)
#             Length: 0
#         Extension: signature_algorithms (len=20)
#             Type: signature_algorithms (13)
#             Length: 20
#             Signature Hash Algorithms Length: 18
#             Signature Hash Algorithms (9 algorithms)
#                 Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
#                     Signature Hash Algorithm Hash: SHA256 (4)
#                     Signature Hash Algorithm Signature: ECDSA (3)
#                 Signature Algorithm: rsa_pss_rsae_sha256 (0x0804)
#                     Signature Hash Algorithm Hash: Unknown (8)
#                     Signature Hash Algorithm Signature: Unknown (4)
#                 Signature Algorithm: rsa_pkcs1_sha256 (0x0401)
#                     Signature Hash Algorithm Hash: SHA256 (4)
#                     Signature Hash Algorithm Signature: RSA (1)
#                 Signature Algorithm: ecdsa_secp384r1_sha384 (0x0503)
#                     Signature Hash Algorithm Hash: SHA384 (5)
#                     Signature Hash Algorithm Signature: ECDSA (3)
#                 Signature Algorithm: rsa_pss_rsae_sha384 (0x0805)
#                     Signature Hash Algorithm Hash: Unknown (8)
#                     Signature Hash Algorithm Signature: Unknown (5)
#                 Signature Algorithm: rsa_pkcs1_sha384 (0x0501)
#                     Signature Hash Algorithm Hash: SHA384 (5)
#                     Signature Hash Algorithm Signature: RSA (1)
#                 Signature Algorithm: rsa_pss_rsae_sha512 (0x0806)
#                     Signature Hash Algorithm Hash: Unknown (8)
#                     Signature Hash Algorithm Signature: Unknown (6)
#                 Signature Algorithm: rsa_pkcs1_sha512 (0x0601)
#                     Signature Hash Algorithm Hash: SHA512 (6)
#                     Signature Hash Algorithm Signature: RSA (1)
#                 Signature Algorithm: rsa_pkcs1_sha1 (0x0201)
#                     Signature Hash Algorithm Hash: SHA1 (2)
#                     Signature Hash Algorithm Signature: RSA (1)
#         Extension: use_srtp (len=9)
#             Type: use_srtp (14)
#             Length: 9
#             SRTP Protection Profiles Length: 6
#             SRTP Protection Profile: SRTP_AES128_CM_HMAC_SHA1_80 (0x0001)
#             SRTP Protection Profile: SRTP_AEAD_AES_256_GCM (0x0008)
#             SRTP Protection Profile: SRTP_AEAD_AES_128_GCM (0x0007)
#             MKI Length: 0
#         Extension: ec_point_formats (len=2)
#             Type: ec_point_formats (11)
#             Length: 2
#             EC point formats Length: 1
#             Elliptic curves point formats (1)
#                 EC point format: uncompressed (0)
#         Extension: renegotiation_info (len=1)
#             Type: renegotiation_info (65281)
#             Length: 1
#             Renegotiation Info extension
#                 Renegotiation info extension length: 0
#         [JA4: dd2i110600_c45550529adf_279517677189]
#         [JA4_r: dd2i110600_002f,0035,009c,c009,c00a,c013,c014,c02b,c02f,cca8,cca9_000a,000b,000d,000e,0017,ff01_0403,0804,0401,0503,0805,0501,0806,0601,0201]
#         [JA3 Fullstring: 65277,49195-49199-52393-52392-49161-49171-49162-49172-156-47-53,10-23-13-14-11-65281,29-23-24,0]
#         [JA3: b6ca6458c519c677bff42327c3af386b]

data = b"010000800000000000000080fefd13b3ac327e56ae1c96882705b7e69b21cbc30df1695e244570eb7943635866b000000016c02bc02fcca9cca8c009c013c00ac014009c002f003501000040000a00080006001d0017001800170000000d00140012040308040401050308050501080606010201000e0009000600010008000700000b00020100ff01000100"

print(Handshake.unmarshal(binascii.unhexlify(data)))

# Frame 130: 80 bytes on wire (640 bits), 80 bytes captured (640 bits) on interface lo0, id 0
# Null/Loopback
# Internet Protocol Version 4, Src: 192.168.0.104, Dst: 192.168.0.104
# User Datagram Protocol, Src Port: 58423, Dst Port: 56632
# Datagram Transport Layer Security
#     DTLSv1.2 Record Layer: Handshake Protocol: Hello Verify Request
#         Content Type: Handshake (22)
#         Version: DTLS 1.2 (0xfefd)
#         Epoch: 0
#         Sequence Number: 0
#         Length: 35
#         Handshake Protocol: Hello Verify Request
#             Handshake Type: Hello Verify Request (3)
#             Length: 23
#             Message Sequence: 0
#             Fragment Offset: 0
#             Fragment Length: 23
#             Version: DTLS 1.2 (0xfefd)
#             Cookie Length: 20
#             Cookie: 422ee03ba02d7422500d8f8b84a3776bf5ada01c
data = b"030000170000000000000017fefd14422ee03ba02d7422500d8f8b84a3776bf5ada01c"

print(Handshake.unmarshal(binascii.unhexlify(data)))
