from io import BytesIO
from .pyasn1 import univ
from .pyasn1 import namedtype
from .pyasn1 import namedval
from .pyasn1 import useful
from .pyasn1 import tag
from .pyasn1 import char

import base64
import inspect
import textwrap
import re


class Extension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("extnID", univ.ObjectIdentifier()),
        namedtype.DefaultedNamedType("critical", univ.Boolean("False")),
        namedtype.NamedType("extnValue", univ.OctetString()),
    )


class Extensions(univ.SequenceOf):
    componentType = Extension()
    sizeSpec = univ.SequenceOf.sizeSpec


def tuple_to_OID(tuple):
    """
    Converts OID tuple to OID string
    """
    ln = len(tuple)
    buf = ""
    for idx in range(ln):
        if idx < ln - 1:
            buf += str(tuple[idx]) + "."
        else:
            buf += str(tuple[idx])
    return buf


class DirectoryString(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("teletexString", char.TeletexString()),
        namedtype.NamedType("printableString", char.PrintableString()),
        namedtype.NamedType("universalString", char.UniversalString()),
        namedtype.NamedType("utf8String", char.UTF8String()),
        namedtype.NamedType("bmpString", char.BMPString()),
        namedtype.NamedType("ia5String", char.IA5String()),  # for legacy pkcs9-email
        # namedtype.NamedType('gString', univ.OctetString()),
        namedtype.NamedType(
            "bitString", univ.BitString()
        ),  # needed for X500 Unique Identifier, RFC 4519
    )

    def __repr__(self):
        try:
            c = self.getComponent()
            return c.__str__()
        except Exception:
            return "Choice type not chosen"

    def __str__(self):
        return repr(self)


# class AttributeValue(DirectoryString):
class AttributeValue(univ.OctetString):
    pass


# class AttributeType(univ.ObjectIdentifier):
class AttributeType(univ.OctetString):
    pass
    # def __str__(self):
    #     return self._value
    # return tuple_to_OID(self._value)


class AttributeTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", AttributeType()),
        namedtype.NamedType("value", AttributeValue()),
    )

    # def __repr__(self):
    #     # s = "%s => %s" % [ self.getComponentByName('type'), self.getComponentByName('value')]
    #
    #     type = self.getComponentByName("type")
    #     value = self.getComponentByName("value")
    #     print("type", type, "value", value)
    #
    #     # s = "%s => %s" % (type, value)
    #     return "test"
    #
    # def __str__(self):
    #     return self.__repr__()


class RelativeDistinguishedName(univ.SetOf):
    componentType = AttributeTypeAndValue()

    def __str__(self):
        buf = ""
        for component in self._componentValues:  # pyright: ignore
            buf += str(component)
            buf += ","
        buf = buf[: len(buf) - 1]
        return buf


class RDNSequence(univ.SequenceOf):
    componentType = RelativeDistinguishedName()

    def __str__(self):
        buf = ""
        for component in self._componentValues:  # pyright: ignore
            buf += str(component)
            buf += ","
        buf = buf[: len(buf) - 1]
        return buf


class Name(univ.Choice):
    componentType = namedtype.NamedTypes(namedtype.NamedType("", RDNSequence()))

    def __str__(self):
        return str(self.getComponent())


class ConvertibleBitString(univ.BitString):
    """
    Extends uni.BitString with method that converts value
    to the octet string.
    """

    def toOctets(self):
        # oh $deity, please FIXME
        """
        Converts bit string into octets string
        """

        def _tuple_to_byte(tuple):
            # return chr(int(''.join(map(str, tuple)),2))
            return int("".join(map(str, tuple)), 2).to_bytes(1, byteorder="big")

        res = b""
        byte_len = int(len(self._value) / 8)  # pyright: ignore
        for byte_idx in range(byte_len):
            bit_idx = byte_idx * 8
            byte_tuple = self._value[bit_idx : bit_idx + 8]  # pyright: ignore
            byte = _tuple_to_byte(byte_tuple)
            res += byte
        return res


class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("algorithm", univ.OctetString()),
        # namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
        # namedtype.OptionalNamedType("parameters", univ.Any()),
        # XXX syntax screwed?
        # namedtype.OptionalNamedType("parameters", univ.ObjectIdentifier()),
    )

    # def __repr__(self):
    #     tuple = self.getComponentByName("algorithm")
    #     # str_oid = tuple_to_OID(tuple)
    #     # return str_oid
    #     return tuple

    # def __str__(self):
    #     return repr(self)


class SubjectPublicKeyInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        # namedtype.NamedType("algorithm", AlgorithmIdentifier()),
        # namedtype.NamedType("subjectPublicKey", ConvertibleBitString()),
        namedtype.NamedType("subjectPublicKey", univ.OctetString()),
    )


class UniqueIdentifier(ConvertibleBitString):
    pass


class Time(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("utcTime", useful.UTCTime()),
        namedtype.NamedType("generalTime", useful.GeneralizedTime()),
    )

    def __str__(self):
        return str(self.getComponent())


class Validity(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("notBefore", Time()),
        namedtype.NamedType("notAfter", Time()),
    )


class CertificateSerialNumber(univ.Integer):
    pass


class Version(univ.Integer):
    namedValues = namedval.NamedValues(("v1", 0), ("v2", 1), ("v3", 2))


# tbsCertificate          SEQUENCE {
#     version             [0] EXPLICIT INTEGER 2,
#     serialNumber        INTEGER 123456789, -- Example serial number
#     signature           SEQUENCE {
#         algorithm       OBJECT IDENTIFIER sha256WithRSAEncryption (1.2.840.113549.1.1.11),
#         parameters      NULL
#     },
#     issuer              SEQUENCE {
#         SET {
#             SEQUENCE {
#                 OBJECT IDENTIFIER commonName (2.5.4.3),
#                 UTF8String "abc1234deadbeef" -- Example random hex
#             }
#         }
#     },
#     validity            SEQUENCE {
#         notBefore        UTCTime "20231119120000Z", -- Example date
#         notAfter         UTCTime "20231219120000Z"  -- Example date
#     },
#     subject             SEQUENCE {
#         SET {
#             SEQUENCE {
#                 OBJECT IDENTIFIER commonName (2.5.4.3),
#                 UTF8String "abc1234deadbeef" -- Example random hex
#             }
#         }
#     },
#     subjectPublicKeyInfo SEQUENCE {
#         algorithm       SEQUENCE {
#             algorithm   OBJECT IDENTIFIER rsaEncryption (1.2.840.113549.1.1.1),
#             parameters  NULL
#         },
#         subjectPublicKey BIT STRING "..." -- Public key bits
#     }
# }


# TBSCertificate ::= SEQUENCE {
#     version                 [0] EXPLICIT Version DEFAULT v1,
#     serialNumber            INTEGER,
#     signature               AlgorithmIdentifier,
#     issuer                  Name,
#     validity                Validity,
#     subject                 Name,
#     subjectPublicKeyInfo    SubjectPublicKeyInfo,
#     ...
# }
class TBSCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType(
            "version",
            Version(
                "v1",
                tagSet=Version.tagSet.tagExplicitly(
                    tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
                ),
            ),
        ),
        namedtype.NamedType("serialNumber", CertificateSerialNumber()),
        namedtype.NamedType("signature", AlgorithmIdentifier()),
        namedtype.NamedType("issuer", Name()),
        namedtype.NamedType("validity", Validity()),
        namedtype.NamedType("subject", Name()),
        namedtype.NamedType("subjectPublicKeyInfo", SubjectPublicKeyInfo()),
    )


class Certificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tbsCertificate", TBSCertificate()),
        namedtype.NamedType("signatureAlgorithm", AlgorithmIdentifier()),
        # namedtype.NamedType("signatureValue", ConvertibleBitString()),
        namedtype.NamedType("signatureValue", univ.OctetString()),
    )


def type_name(value):
    """
    Returns a user-readable name for the type of an object

    :param value:
        A value to get the type name of

    :return:
        A unicode string of the object's type name
    """

    if inspect.isclass(value):
        cls = value
    else:
        cls = value.__class__
    if cls.__module__ in set(["builtins", "__builtin__"]):
        return cls.__name__
    return "%s.%s" % (cls.__module__, cls.__name__)


str_cls = str
byte_cls = bytes


def unwrap(string, *params):
    """
    Takes a multi-line string and does the following:

     - dedents
     - converts newlines with text before and after into a single line
     - strips leading and trailing whitespace

    :param string:
        The string to format

    :param *params:
        Params to interpolate into the string

    :return:
        The formatted string
    """

    output = textwrap.dedent(string)

    # Unwrap lines, taking into account bulleted lists, ordered lists and
    # underlines consisting of = signs
    if output.find("\n") != -1:
        output = re.sub("(?<=\\S)\n(?=[^ \n\t\\d\\*\\-=])", " ", output)

    if params:
        output = output % params

    output = output.strip()

    return output


def armor(type_name, der_bytes, headers=None):
    """
    Armors a DER-encoded byte string in PEM

    :param type_name:
        A unicode string that will be capitalized and placed in the header
        and footer of the block. E.g. "CERTIFICATE", "PRIVATE KEY", etc. This
        will appear as "-----BEGIN CERTIFICATE-----" and
        "-----END CERTIFICATE-----".

    :param der_bytes:
        A byte string to be armored

    :param headers:
        An OrderedDict of the header lines to write after the BEGIN line

    :return:
        A byte string of the PEM block
    """

    if not isinstance(der_bytes, byte_cls):
        raise TypeError(
            unwrap(
                """
            der_bytes must be a byte string, not %s
            """
                % type_name(der_bytes)
            )
        )

    if not isinstance(type_name, str_cls):
        raise TypeError(
            unwrap(
                """
            type_name must be a unicode string, not %s
            """,
                type_name(type_name),
            )
        )

    type_name = type_name.upper().encode("ascii")

    output = BytesIO()
    output.write(b"-----BEGIN ")
    output.write(type_name)
    output.write(b"-----\n")
    if headers:
        for key in headers:
            output.write(key.encode("ascii"))
            output.write(b": ")
            output.write(headers[key].encode("ascii"))
            output.write(b"\n")
        output.write(b"\n")
    b64_bytes = base64.b64encode(der_bytes)
    b64_len = len(b64_bytes)
    i = 0
    while i < b64_len:
        output.write(b64_bytes[i : i + 64])
        output.write(b"\n")
        i += 64
    output.write(b"-----END ")
    output.write(type_name)
    output.write(b"-----\n")

    return output.getvalue()
