from asn1crypto import pem, x509, keys, algos
from ecdsa import Ed25519, SigningKey, SECP256k1, SECP128r1, VerifyingKey
import datetime
import os


def generate_ecdsa_keys():
    # sk = SigningKey.generate(curve=SECP256k1)
    sk = SigningKey.generate(curve=SECP128r1)
    # sk = SigningKey.generate(curve=Ed25519)

    pk = sk.get_verifying_key()
    if not isinstance(pk, VerifyingKey):
        raise ValueError("test")

    # Convert compressed to uncompressed format (0x04 prefix + X and Y coordinates)
    public_key_uncompressed = b"\x04" + pk.to_string()

    return (
        sk,
        public_key_uncompressed,
    )


def create_self_signed_cert_with_ecdsa():
    sk, public_key_der = generate_ecdsa_keys()

    # cdomain_params = keys.ECDomainParameters(("named", "secp256k1"))
    ecdomain_params = keys.ECDomainParameters(("named", "secp128r1"))

    ec_point_bit_string = keys.ECPointBitString(public_key_der)

    if public_key_der[0] != 0x04:
        raise ValueError("Public key is not in uncompressed format")

    public_key_info = keys.PublicKeyInfo(
        {
            "algorithm": {
                "algorithm": "1.2.840.10045.2.1",
                "parameters": ecdomain_params,
            },
            "public_key": ec_point_bit_string,
        }
    )

    subject = x509.Name.build(
        {
            "common_name": "My Self-Signed ECDSA Cert",
            "country_name": "US",
            "organization_name": "Example Org",
        }
    )

    issuer = subject

    not_before = x509.Time({"utc_time": datetime.datetime.now(datetime.UTC)})
    not_after = x509.Time(
        {"utc_time": datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)}
    )

    tbs_certificate = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": int.from_bytes(os.urandom(16), "big"),
            "signature": algos.SignedDigestAlgorithm({"algorithm": "sha256_ecdsa"}),
            "issuer": issuer,
            "validity": x509.Validity(
                {"not_before": not_before, "not_after": not_after}
            ),
            "subject": subject,
            "subject_public_key_info": public_key_info,
        }
    )

    signature = sk.sign(tbs_certificate.dump())

    certificate = x509.Certificate(
        {
            "tbs_certificate": tbs_certificate,
            "signature_algorithm": algos.SignedDigestAlgorithm(
                {"algorithm": "sha256_ecdsa"}
            ),
            "signature_value": signature,
        }
    )

    cert_pem = pem.armor("CERTIFICATE", certificate.dump())

    return cert_pem


cert_pem = create_self_signed_cert_with_ecdsa()
print("Certificate:\n", cert_pem)

with open("test.pem", "wb") as f:
    f.write(cert_pem)

with open("test.pem", "rb") as cert_file:
    cert_data = cert_file.read()

_, _, pem_body = pem.unarmor(cert_data)
print(pem_body)
certificate = x509.Certificate.load(pem_body)

print("Issuer:", certificate["tbs_certificate"]["issuer"])
print("Subject:", certificate["tbs_certificate"]["subject"])
print("Serial Number:", certificate["tbs_certificate"]["serial_number"])
print("Not Before:", certificate["tbs_certificate"]["validity"]["not_before"])
print("Not After:", certificate["tbs_certificate"]["validity"]["not_after"])

public_key = certificate["tbs_certificate"]["subject_public_key_info"][
    "public_key"
].native
print("Public Key (Raw Bytes):", public_key)
