#
# This file is part of pyasn1 software.
#
import warnings

from . import cer_decoder
from . import univ

__all__ = ["decode", "StreamingDecoder"]


class BitStringPayloadDecoder(cer_decoder.BitStringPayloadDecoder):
    supportConstructedForm = False


class OctetStringPayloadDecoder(cer_decoder.OctetStringPayloadDecoder):
    supportConstructedForm = False


# TODO: prohibit non-canonical encoding
RealPayloadDecoder = cer_decoder.RealPayloadDecoder

TAG_MAP = cer_decoder.TAG_MAP.copy()
TAG_MAP.update(
    {
        univ.BitString.tagSet: BitStringPayloadDecoder(),
        univ.OctetString.tagSet: OctetStringPayloadDecoder(),
        univ.Real.tagSet: RealPayloadDecoder(),
    }
)

TYPE_MAP = cer_decoder.TYPE_MAP.copy()

# Put in non-ambiguous types for faster codec lookup
for typeDecoder in TAG_MAP.values():
    if typeDecoder.protoComponent is not None:
        typeId = typeDecoder.protoComponent.__class__.typeId
        if typeId is not None and typeId not in TYPE_MAP:
            TYPE_MAP[typeId] = typeDecoder


class SingleItemDecoder(cer_decoder.SingleItemDecoder):
    __doc__ = cer_decoder.SingleItemDecoder.__doc__

    TAG_MAP = TAG_MAP
    TYPE_MAP = TYPE_MAP

    supportIndefLength = False


class StreamingDecoder(cer_decoder.StreamingDecoder):
    __doc__ = cer_decoder.StreamingDecoder.__doc__

    SINGLE_ITEM_DECODER = SingleItemDecoder


class Decoder(cer_decoder.Decoder):
    __doc__ = cer_decoder.Decoder.__doc__

    STREAMING_DECODER = StreamingDecoder


#: Turns DER octet stream into an ASN.1 object.
#:
#: Takes DER octet-stream and decode it into an ASN.1 object
#: (e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative) which
#: may be a scalar or an arbitrary nested structure.
#:
#: Parameters
#: ----------
#: substrate: :py:class:`bytes`
#:     DER octet-stream
#:
#: Keyword Args
#: ------------
#: asn1Spec: any pyasn1 type object e.g. :py:class:`~pyasn1.type.base.PyAsn1Item` derivative
#:     A pyasn1 type object to act as a template guiding the cer_decoder. Depending on the ASN.1 structure
#:     being decoded, *asn1Spec* may or may not be required. Most common reason for
#:     it to require is that ASN.1 structure is encoded in *IMPLICIT* tagging mode.
#:
#: Returns
#: -------
#: : :py:class:`tuple`
#:     A tuple of pyasn1 object recovered from DER substrate (:py:class:`~pyasn1.type.base.PyAsn1Item` derivative)
#:     and the unprocessed trailing portion of the *substrate* (may be empty)
#:
#: Raises
#: ------
#: ~pyasn1.error.PyAsn1Error, ~pyasn1.error.SubstrateUnderrunError
#:     On decoding errors
#:
#: Examples
#: --------
#: Decode DER serialisation without ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> s, _ = decode(b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03')
#:    >>> str(s)
#:    SequenceOf:
#:     1 2 3
#:
#: Decode DER serialisation with ASN.1 schema
#:
#: .. code-block:: pycon
#:
#:    >>> seq = SequenceOf(componentType=Integer())
#:    >>> s, _ = decode(b'0\t\x02\x01\x01\x02\x01\x02\x02\x01\x03', asn1Spec=seq)
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
