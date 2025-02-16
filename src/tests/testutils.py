from hashlib import sha256

from webrtc.dtls.dtls_cipher_suite import (
    Keypair,
    prf_master_secret,
)
from webrtc.dtls.dtls_typing import Random
from webrtc.dtls.gcm import prf_generate_encryption_keys


_PRF_MAC_LEN = 0
_PRF_KEY_LEN = 16
_PRF_IV_LEN = 4


def stub_prf_encryption_keys():
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

    return prf_generate_encryption_keys(
        master_secret,
        encoder_random.marshal_fixed(),
        decoder_random.marshal_fixed(),
        _PRF_MAC_LEN,
        _PRF_KEY_LEN,
        _PRF_IV_LEN,
    )
