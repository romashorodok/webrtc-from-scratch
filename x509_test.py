import sys
import os
import unittest
import abc

from webrtc.dtls.pyasn1 import der_encoder, useful
from webrtc.dtls.pyasn1 import der_decoder

from webrtc.dtls.pyasn1.base_test_case import BaseTestCase
from webrtc.dtls.x509 import (
    AlgorithmIdentifier,
    AttributeType,
    AttributeTypeAndValue,
    AttributeValue,
    Certificate,
    RDNSequence,
    RelativeDistinguishedName,
    TBSCertificate,
    armor,
)


def random_serial_number() -> int:
    return int.from_bytes(os.urandom(20), "big") >> 1


VERSION = 0
SERIAL_NUMBER = 1
SERIAL_NUMBER_STATIC = 447692783348576470343654504716430034303219343191
SIGNATURE = 2
SIGNATURE_ALGORITHM = 0
ISSUER = 3
VALIDITY = 4
SUBJECT = 5
SUBJECT_PUBLIC_KEY_INFO = 6

CERTIFICATE_SIGNATURE_ALGORITHM = 1


class EllipticCurve(metaclass=abc.ABCMeta):
    _name: str
    _key_size: int
    _oid: str

    @property
    def name(self) -> str:
        """
        The name of the curve. e.g. secp256r1.
        """
        return self._name

    @property
    def key_size(self) -> int:
        """
        Bit size of a secret scalar for the curve.
        """
        return self._key_size

    @property
    def oid(self) -> str:
        return self._oid


class EllipticCurveOID:
    SECP256R1 = "1.2.840.10045.3.1.7"


class SECP256R1(EllipticCurve):
    _name = "secp256r1"
    _key_size = 256
    _oid = EllipticCurveOID.SECP256R1


OID_TO_CURVE = {
    EllipticCurveOID.SECP256R1: SECP256R1().name,
}

OID_CN_NAME = "2.5.4.3"

PUBLIC_KEY_VALUE = "04:ed:58:c9:c1:96:f1:49:6f:1a:4a:3c:19:15:c6:4a:45:3a:3c:23:fe:ec:1a:aa:af:04:5f:7b:d3:7f:1f:8b:44:fe:d4:75:1a:b9:46:fb:9d:93:cf:98:bd:00:b7:00:2d:df:e4:8b:ae:5d:e0:59:88:3a:c1:02:f6:e5:f9:51:78"

SIGNATURE_VALUE = "30:44:02:20:26:4c:f0:cc:69:d1:36:ad:42:01:71:6a:44:bc:7d:5f:af:6b:74:df:0e:b1:2d:40:bf:06:f8:a0:ee:65:38:5b:02:20:6c:6c:9e:7c:a8:c2:f0:cd:5b:37:12:19:f0:03:38:05:46:96:05:9c:f6:65:5e:e1:bb:df:10:1f:b4:8e:fc:f4"


class CertificateTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        self.cert = TBSCertificate()

    # def test_encode_certificate(self):
    #     self.cert[VERSION] = 2  # "v2 == 1 or v3 == 2"
    #     self.cert[SERIAL_NUMBER] = random_serial_number()
    #     self.cert[SERIAL_NUMBER] = SERIAL_NUMBER_STATIC
    #
    #     alg = SECP256R1()
    #
    #     self.cert[SIGNATURE][SIGNATURE_ALGORITHM] = alg.oid
    #
    #     issuer_cn_name_attr = AttributeTypeAndValue()
    #     issuer_cn_name_attr.setComponentByName("type", OID_CN_NAME)
    #     issuer_cn_name_attr.setComponentByName("value", "Test Certificate")
    #
    #     issuer_rdn = RelativeDistinguishedName()
    #     issuer_rdn.append(issuer_cn_name_attr)
    #
    #     # issuer_rdn_seq = RDNSequence()
    #     # issuer_rdn_seq.append(issuer_rdn)
    #
    #     # result = der_encoder.encode(issuer_rdn_seq)
    #     # print(result)
    #     # print(der_decoder.decode(result, asn1Spec=RDNSequence()))
    #
    #     self.cert[ISSUER][0].append(issuer_rdn)
    #
    #     self.cert[VALIDITY].getComponentByName("notBefore").setComponentByName(
    #         "utcTime", useful.UTCTime("990801120112Z")
    #     )
    #     self.cert[VALIDITY].getComponentByName("notBefore").setComponentByName(
    #         "generalTime", useful.GeneralizedTime("20170801120112.000Z")
    #     )
    #
    #     self.cert[VALIDITY].getComponentByName("notAfter").setComponentByName(
    #         "utcTime", useful.UTCTime("999801120112Z")
    #     )
    #     self.cert[VALIDITY].getComponentByName("notAfter").setComponentByName(
    #         "generalTime", useful.GeneralizedTime("20190801120112.000Z")
    #     )
    #
    #     self.cert[SUBJECT][0].append(issuer_rdn)
    #
    #     self.cert[SUBJECT_PUBLIC_KEY_INFO].setComponentByName(
    #         "subjectPublicKey",
    #         PUBLIC_KEY_VALUE,
    #     )
    #
    #     result: bytes = bytes(der_encoder.encode(self.cert))
    #
    #     print(result)
    #
    #     self.cert.clear()
    #     spec, ok = der_decoder.decode(result, asn1Spec=self.cert)
    #     print(spec, ok)

    # with open("certificate.der", "wb") as f:
    #     f.write(result)

    def test_certificate(self):
        certificate = Certificate()
        cert = certificate[0]

        cert[VERSION] = 2  # "v2 == 1 or v3 == 2"
        cert[SERIAL_NUMBER] = random_serial_number()
        cert[SERIAL_NUMBER] = SERIAL_NUMBER_STATIC

        alg = SECP256R1()

        cert[SIGNATURE][SIGNATURE_ALGORITHM] = alg.oid

        issuer_cn_name_attr = AttributeTypeAndValue()
        issuer_cn_name_attr.setComponentByName("type", OID_CN_NAME)
        issuer_cn_name_attr.setComponentByName("value", "Test Certificate")

        issuer_rdn = RelativeDistinguishedName()
        issuer_rdn.append(issuer_cn_name_attr)

        cert[ISSUER][0].append(issuer_rdn)

        cert[VALIDITY].getComponentByName("notBefore").setComponentByName(
            "utcTime", useful.UTCTime("990801120112Z")
        )
        cert[VALIDITY].getComponentByName("notBefore").setComponentByName(
            "generalTime", useful.GeneralizedTime("20170801120112.000Z")
        )

        cert[VALIDITY].getComponentByName("notAfter").setComponentByName(
            "utcTime", useful.UTCTime("999801120112Z")
        )
        cert[VALIDITY].getComponentByName("notAfter").setComponentByName(
            "generalTime", useful.GeneralizedTime("20190801120112.000Z")
        )

        cert[SUBJECT][0].append(issuer_rdn)

        cert[SUBJECT_PUBLIC_KEY_INFO].setComponentByName(
            "subjectPublicKey",
            PUBLIC_KEY_VALUE,
        )

        certificate.getComponentByName("signatureAlgorithm").setComponentByName(
            "algorithm", "ecdsa-with-SHA256"
        )
        certificate.setComponentByName("signatureValue", SIGNATURE_VALUE)

        result: bytes = bytes(der_encoder.encode(certificate))

        with open("test.pem", "wb") as f:
            result = armor("CERTIFICATE", result)
            f.write(result)

        print("x509 cert:", result)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)
