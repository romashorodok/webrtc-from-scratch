from asn1crypto import pem, x509, keys, algos
from ellipticcurve.privateKey import PrivateKey
from ellipticcurve.ecdsa import Ecdsa
import datetime
import os


def generate_starkbank_keys():
    # Generate ECDSA keys using starkbank-ecdsa
    private_key = PrivateKey()
    public_key = private_key.publicKey()

    # Export keys in DER format
    public_key_der = public_key.toDer()

    return private_key, public_key_der


def create_self_signed_cert_with_starkbank():
    # Generate ECDSA keys
    private_key, public_key_der = generate_starkbank_keys()

    # Define the curve OID for P-256 (NIST curve)

    # Correctly create the ECDomainParameters using the curve OID

    ecdomain_params = keys.ECDomainParameters(("named", "secp256r1"))

    # Create ASN.1 PublicKeyInfo
    public_key_info = keys.PublicKeyInfo(
        {
            "algorithm": {
                "algorithm": "1.2.840.10045.2.1",  # OID for id-ecPublicKey
                "parameters": ecdomain_params,
            },
            "public_key": keys.ECPointBitString(public_key_der),
        }
    )

    # Define certificate fields
    subject = x509.Name.build(
        {
            "common_name": "My Self-Signed Starkbank Cert",
            "country_name": "US",
            "organization_name": "Example Org",
        }
    )

    issuer = subject  # Self-signed certificate

    # Validity period
    not_before = x509.Time({"utc_time": datetime.datetime.now(datetime.UTC)})
    not_after = x509.Time(
        {"utc_time": datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)}
    )

    # Construct the TBS (to-be-signed) certificate
    tbs_certificate = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": int.from_bytes(
                os.urandom(16), "big"
            ),  # Random serial number
            "signature": algos.SignedDigestAlgorithm({"algorithm": "sha256_ecdsa"}),
            "issuer": issuer,
            "validity": x509.Validity(
                {"not_before": not_before, "not_after": not_after}
            ),
            "subject": subject,
            "subject_public_key_info": public_key_info,
        }
    )

    # Sign the TBS certificate using the private key
    tbs_certificate_bytes = str(tbs_certificate.dump())

    signature = Ecdsa.sign(tbs_certificate_bytes, private_key)
    signature._toString()
    # print(signature._toString())

    # Construct the final X.509 certificate
    certificate = x509.Certificate(
        {
            "tbs_certificate": tbs_certificate,
            "signature_algorithm": algos.SignedDigestAlgorithm(
                {"algorithm": "sha256_ecdsa"}
            ),
            # "signature_value": x509.BitString(signature.toDer()),
            "signature_value": signature.toDer(),
        }
    )

    # Export the certificate to PEM format
    cert_pem = pem.armor("CERTIFICATE", certificate.dump())

    return cert_pem


# Example usage
cert_pem = create_self_signed_cert_with_starkbank()
print("Certificate:\n", cert_pem)

with open("test.pem", "wb") as f:
    f.write(cert_pem)
