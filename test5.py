import dtls

cert = dtls.Certificate.generate_certificate()

print(cert.get_fingerprints())
