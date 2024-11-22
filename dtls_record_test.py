import binascii

from webrtc.dtls.dtlstransport import RecordLayer

# Handshake, DTLSv1.0, Epoch 0, Sequence Number 2, Length 78
# data = b"16feff0000000000000002004e"
# Handshake, DTLSv1.2, Epoch 0, Sequence Number 2, Length 78
data = b"16fefd0000000000000002004e"

# Client Key Exchange, Length 66, Message Sequence 2, Fragment Offset 0, Fragment Length 66
data += b"100000420002000000000042"

# Pubkey Length: 65
data += b"41"
# Pubkey
data += (
    b"0466c160c0cc7a657c0dbd19be373922ffed1e78315706332c17ccb79b"
    b"3b7d9050fd55bc74c37f36a8d4c6773b95314fe268e0385e490ef73079"
    b"c405f54c61265e"
)


record = RecordLayer.unmarshal(binascii.unhexlify(data))

d = record.marshal()

print(data)
print(binascii.hexlify(d))
