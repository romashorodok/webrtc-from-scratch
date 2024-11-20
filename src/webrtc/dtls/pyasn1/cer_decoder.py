#
# This file is part of pyasn1 software.
#
import warnings

from . import error
from .streaming import readFromStream
from . import ber_decoder
from . import univ

__all__ = ["decode", "StreamingDecoder"]

SubstrateUnderrunError = error.SubstrateUnderrunError


class BooleanPayloadDecoder(ber_decoder.AbstractSimplePayloadDecoder):
    protoComponent = univ.Boolean(0)

    def valueDecoder(
        self,
        substrate,
        asn1Spec,
        tagSet=None,
        length=None,
        state=None,
        decodeFun=None,
        substrateFun=None,
        **options,
    ):
        if length != 1:
            raise error.PyAsn1Error("Not single-octet Boolean payload")

        for chunk in readFromStream(substrate, length, options):
            if isinstance(chunk, SubstrateUnderrunError):
                yield chunk

        byte = chunk[0]

        # CER/DER specifies encoding of TRUE as 0xFF and FALSE as 0x0, while
        # BER allows any non-zero value as TRUE; cf. sections 8.2.2. and 11.1
        # in https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
        if byte == 0xFF:
            value = 1

        elif byte == 0x00:
            value = 0

        else:
            raise error.PyAsn1Error("Unexpected Boolean payload: %s" % byte)

        yield self._createComponent(asn1Spec, tagSet, value, **options)


# TODO: prohibit non-canonical encoding
BitStringPayloadDecoder = ber_decoder.BitStringPayloadDecoder
OctetStringPayloadDecoder = ber_decoder.OctetStringPayloadDecoder
RealPayloadDecoder = ber_decoder.RealPayloadDecoder

TAG_MAP = ber_decoder.TAG_MAP.copy()
TAG_MAP.update(
    {
        univ.Boolean.tagSet: BooleanPayloadDecoder(),
        univ.BitString.tagSet: BitStringPayloadDecoder(),
        univ.OctetString.tagSet: OctetStringPayloadDecoder(),
        univ.Real.tagSet: RealPayloadDecoder(),
    }
)

TYPE_MAP = ber_decoder.TYPE_MAP.copy()

# Put in non-ambiguous types for faster codec lookup
for typeDecoder in TAG_MAP.values():
    if typeDecoder.protoComponent is not None:
        typeId = typeDecoder.protoComponent.__class__.typeId
        if typeId is not None and typeId not in TYPE_MAP:
            TYPE_MAP[typeId] = typeDecoder


class SingleItemDecoder(ber_decoder.SingleItemDecoder):
    __doc__ = ber_decoder.SingleItemDecoder.__doc__

    TAG_MAP = TAG_MAP
    TYPE_MAP = TYPE_MAP


class StreamingDecoder(ber_decoder.StreamingDecoder):
    __doc__ = ber_decoder.StreamingDecoder.__doc__

    SINGLE_ITEM_DECODER = SingleItemDecoder


class Decoder(ber_decoder.Decoder):
    __doc__ = ber_decoder.Decoder.__doc__

    STREAMING_DECODER = StreamingDecoder


#: Turns CER octet stream into an ASN.1 object.
#:
#: Takes CER octet-stream and decode it into an ASN.1 object
#: (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative) which
#: may be a scalar or an arbitrary nested structure.
#:
#: Parameters
#: ----------
#: substrate: :py:class:`bytes`
#:     CER octet-stream
#:
#: Keyword Args
#: ------------
#: asn1Spec: any pyasn1 type object e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
#:     A pyasn1 type object to act as a template guiding the ber_decoder. Depending on the ASN.1 structure
#:     being decoded, *asn1Spec* may or may not be required. Most common reason for
#:     it to require is that ASN.1 structure is encoded in *IMPLICIT* tagging mode.
#:
#: Returns
#: -------
#: : :py:class:`tuple`
#:     A tuple of pyasn1 object recovered from CER substrate (:py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#:     and the unprocessed trailing portion of the *substrate* (may be empty)
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error, ~pyasn1.error.SubstrateUnderrunError
#:     On decoding errors
#:
#: Examples
#: --------
#: Decode CER serialisation without ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> s, _ = decode(b'0\x80\x02\x01\x01\x02\x01\x02\x02\x01\x03\x00\x00')
#:    >>> str(s)
#:    SequenceOf:
#:     1 2 3
#:
#: Decode CER serialisation with ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> s, _ = decode(b'0\x80\x02\x01\x01\x02\x01\x02\x02\x01\x03\x00\x00', asn1Spec=seq)
#:    >>> str(s)
#:    SequenceOf:
#:     1 2 3
#:
decode = Decoder()


def __getattr__(attr: str):
    if newAttr := {"tagMap": "TAG_MAP", "typeMap": "TYPE_MAP"}.get(attr):
        warnings.warn(
            f"{attr} is deprecated. Please use {newAttr} instead.", DeprecationWarning
        )
        return globals()[newAttr]
    raise AttributeError(attr)
