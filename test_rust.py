import os
import native

keypair = native.Keypair(23)
print(keypair)


signature = keypair.generate_server_signature(b"client_random", b"server_random")
print("cert der", keypair.certificate_der())
print("cert finger", keypair.certificate_fingerprint())

pre_master_secret = native.prf_pre_master_secret(keypair.pubkey_der(), keypair)
print(pre_master_secret)

master_secret = native.prf_master_secret(
    pre_master_secret, os.urandom(16), os.urandom(16)
)
print(master_secret)
