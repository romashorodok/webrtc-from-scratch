#
# This file is part of pyasn1 software.
#
import sys
import unittest


from webrtc.dtls.pyasn1.base_test_case import BaseTestCase

from webrtc.dtls.pyasn1 import tag
from webrtc.dtls.pyasn1 import namedtype
from webrtc.dtls.pyasn1 import opentype
from webrtc.dtls.pyasn1 import univ
from webrtc.dtls.pyasn1 import useful
from webrtc.dtls.pyasn1 import cer_encoder
from webrtc.dtls.pyasn1.error import PyAsn1Error


class BooleanEncoderTestCase(BaseTestCase):
    def testTrue(self):
        assert cer_encoder.encode(univ.Boolean(1)) == bytes((1, 1, 255))

    def testFalse(self):
        assert cer_encoder.encode(univ.Boolean(0)) == bytes((1, 1, 0))


class BitStringEncoderTestCase(BaseTestCase):
    def testShortMode(self):
        assert cer_encoder.encode(univ.BitString((1, 0) * 5)) == bytes(
            (3, 3, 6, 170, 128)
        )

    def testLongMode(self):
        assert cer_encoder.encode(univ.BitString((1, 0) * 501)) == bytes(
            (3, 127, 6) + (170,) * 125 + (128,)
        )


class OctetStringEncoderTestCase(BaseTestCase):
    def testShortMode(self):
        assert cer_encoder.encode(univ.OctetString("Quick brown fox")) == bytes(
            (
                4,
                15,
                81,
                117,
                105,
                99,
                107,
                32,
                98,
                114,
                111,
                119,
                110,
                32,
                102,
                111,
                120,
            )
        )

    def testLongMode(self):
        assert cer_encoder.encode(univ.OctetString("Q" * 1001)) == bytes(
            (36, 128, 4, 130, 3, 232) + (81,) * 1000 + (4, 1, 81, 0, 0)
        )


class GeneralizedTimeEncoderTestCase(BaseTestCase):
    #    def testExtraZeroInSeconds(self):
    #        try:
    #            assert cer_encoder.encode(
    #                useful.GeneralizedTime('20150501120112.10Z')
    #            )
    #        except PyAsn1Error:
    #            pass
    #        else:
    #            assert 0, 'Meaningless trailing zero in fraction part tolerated'

    def testLocalTimezone(self):
        try:
            assert cer_encoder.encode(useful.GeneralizedTime("20150501120112.1+0200"))
        except PyAsn1Error:
            pass
        else:
            assert 0, "Local timezone tolerated"

    def testMissingTimezone(self):
        try:
            assert cer_encoder.encode(useful.GeneralizedTime("20150501120112.1"))
        except PyAsn1Error:
            pass
        else:
            assert 0, "Missing timezone tolerated"

    def testDecimalCommaPoint(self):
        try:
            assert cer_encoder.encode(useful.GeneralizedTime("20150501120112,1Z"))
        except PyAsn1Error:
            pass
        else:
            assert 0, "Decimal comma tolerated"

    def testWithSubseconds(self):
        assert cer_encoder.encode(
            useful.GeneralizedTime("20170801120112.59Z")
        ) == bytes(
            (
                24,
                18,
                50,
                48,
                49,
                55,
                48,
                56,
                48,
                49,
                49,
                50,
                48,
                49,
                49,
                50,
                46,
                53,
                57,
                90,
            )
        )

    def testWithSubsecondsWithZeros(self):
        assert cer_encoder.encode(
            useful.GeneralizedTime("20170801120112.099Z")
        ) == bytes(
            (
                24,
                18,
                50,
                48,
                49,
                55,
                48,
                56,
                48,
                49,
                49,
                50,
                48,
                49,
                49,
                50,
                46,
                57,
                57,
                90,
            )
        )

    def testWithSubsecondsMax(self):
        assert cer_encoder.encode(
            useful.GeneralizedTime("20170801120112.999Z")
        ) == bytes(
            (
                24,
                19,
                50,
                48,
                49,
                55,
                48,
                56,
                48,
                49,
                49,
                50,
                48,
                49,
                49,
                50,
                46,
                57,
                57,
                57,
                90,
            )
        )

    def testWithSubsecondsMin(self):
        assert cer_encoder.encode(
            useful.GeneralizedTime("20170801120112.000Z")
        ) == bytes((24, 15, 50, 48, 49, 55, 48, 56, 48, 49, 49, 50, 48, 49, 49, 50, 90))

    def testWithSubsecondsDanglingDot(self):
        assert cer_encoder.encode(useful.GeneralizedTime("20170801120112.Z")) == bytes(
            (24, 15, 50, 48, 49, 55, 48, 56, 48, 49, 49, 50, 48, 49, 49, 50, 90)
        )

    def testWithSeconds(self):
        assert cer_encoder.encode(useful.GeneralizedTime("20170801120112Z")) == bytes(
            (24, 15, 50, 48, 49, 55, 48, 56, 48, 49, 49, 50, 48, 49, 49, 50, 90)
        )

    def testWithMinutes(self):
        assert cer_encoder.encode(useful.GeneralizedTime("201708011201Z")) == bytes(
            (24, 13, 50, 48, 49, 55, 48, 56, 48, 49, 49, 50, 48, 49, 90)
        )


class UTCTimeEncoderTestCase(BaseTestCase):
    def testFractionOfSecond(self):
        try:
            assert cer_encoder.encode(useful.UTCTime("150501120112.10Z"))
        except PyAsn1Error:
            pass
        else:
            assert 0, "Decimal point tolerated"

    def testMissingTimezone(self):
        try:
            assert cer_encoder.encode(useful.UTCTime("150501120112")) == bytes(
                (23, 13, 49, 53, 48, 53, 48, 49, 49, 50, 48, 49, 49, 50, 90)
            )
        except PyAsn1Error:
            pass
        else:
            assert 0, "Missing timezone tolerated"

    def testLocalTimezone(self):
        try:
            assert cer_encoder.encode(useful.UTCTime("150501120112+0200"))
        except PyAsn1Error:
            pass
        else:
            assert 0, "Local timezone tolerated"

    def testWithSeconds(self):
        assert cer_encoder.encode(useful.UTCTime("990801120112Z")) == bytes(
            (23, 13, 57, 57, 48, 56, 48, 49, 49, 50, 48, 49, 49, 50, 90)
        )

    def testWithMinutes(self):
        assert cer_encoder.encode(useful.UTCTime("9908011201Z")) == bytes(
            (23, 11, 57, 57, 48, 56, 48, 49, 49, 50, 48, 49, 90)
        )


class SequenceOfEncoderTestCase(BaseTestCase):
    def testEmpty(self):
        s = univ.SequenceOf()
        s.clear()
        assert cer_encoder.encode(s) == bytes((48, 128, 0, 0))

    def testDefMode1(self):
        s = univ.SequenceOf()
        s.append(univ.OctetString("a"))
        s.append(univ.OctetString("ab"))
        assert cer_encoder.encode(s) == bytes((48, 128, 4, 1, 97, 4, 2, 97, 98, 0, 0))

    def testDefMode2(self):
        s = univ.SequenceOf()
        s.append(univ.OctetString("ab"))
        s.append(univ.OctetString("a"))
        assert cer_encoder.encode(s) == bytes((48, 128, 4, 2, 97, 98, 4, 1, 97, 0, 0))

    def testDefMode3(self):
        s = univ.SequenceOf()
        s.append(univ.OctetString("b"))
        s.append(univ.OctetString("a"))
        assert cer_encoder.encode(s) == bytes((48, 128, 4, 1, 98, 4, 1, 97, 0, 0))

    def testDefMode4(self):
        s = univ.SequenceOf()
        s.append(univ.OctetString("a"))
        s.append(univ.OctetString("b"))
        assert cer_encoder.encode(s) == bytes((48, 128, 4, 1, 97, 4, 1, 98, 0, 0))


class SequenceOfEncoderWithSchemaTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.SequenceOf(componentType=univ.OctetString())

    def testEmpty(self):
        self.s.clear()
        assert cer_encoder.encode(self.s) == bytes((48, 128, 0, 0))

    def testIndefMode1(self):
        self.s.clear()
        self.s.append("a")
        self.s.append("ab")
        assert cer_encoder.encode(self.s) == bytes(
            (48, 128, 4, 1, 97, 4, 2, 97, 98, 0, 0)
        )

    def testIndefMode2(self):
        self.s.clear()
        self.s.append("ab")
        self.s.append("a")
        assert cer_encoder.encode(self.s) == bytes(
            (48, 128, 4, 2, 97, 98, 4, 1, 97, 0, 0)
        )

    def testIndefMode3(self):
        self.s.clear()
        self.s.append("b")
        self.s.append("a")
        assert cer_encoder.encode(self.s) == bytes((48, 128, 4, 1, 98, 4, 1, 97, 0, 0))

    def testIndefMode4(self):
        self.s.clear()
        self.s.append("a")
        self.s.append("b")
        assert cer_encoder.encode(self.s) == bytes((48, 128, 4, 1, 97, 4, 1, 98, 0, 0))


class SetOfEncoderTestCase(BaseTestCase):
    def testEmpty(self):
        s = univ.SetOf()
        s.clear()
        assert cer_encoder.encode(s) == bytes((49, 128, 0, 0))

    def testDefMode1(self):
        s = univ.SetOf()
        s.append(univ.OctetString("a"))
        s.append(univ.OctetString("ab"))
        assert cer_encoder.encode(s) == bytes((49, 128, 4, 1, 97, 4, 2, 97, 98, 0, 0))

    def testDefMode2(self):
        s = univ.SetOf()
        s.append(univ.OctetString("ab"))
        s.append(univ.OctetString("a"))
        assert cer_encoder.encode(s) == bytes((49, 128, 4, 1, 97, 4, 2, 97, 98, 0, 0))

    def testDefMode3(self):
        s = univ.SetOf()
        s.append(univ.OctetString("b"))
        s.append(univ.OctetString("a"))
        assert cer_encoder.encode(s) == bytes((49, 128, 4, 1, 97, 4, 1, 98, 0, 0))

    def testDefMode4(self):
        s = univ.SetOf()
        s.append(univ.OctetString("a"))
        s.append(univ.OctetString("b"))
        assert cer_encoder.encode(s) == bytes((49, 128, 4, 1, 97, 4, 1, 98, 0, 0))


class SetOfEncoderWithSchemaTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.SetOf(componentType=univ.OctetString())

    def testEmpty(self):
        self.s.clear()
        assert cer_encoder.encode(self.s) == bytes((49, 128, 0, 0))

    def testIndefMode1(self):
        self.s.clear()
        self.s.append("a")
        self.s.append("ab")

        assert cer_encoder.encode(self.s) == bytes(
            (49, 128, 4, 1, 97, 4, 2, 97, 98, 0, 0)
        )

    def testIndefMode2(self):
        self.s.clear()
        self.s.append("ab")
        self.s.append("a")

        assert cer_encoder.encode(self.s) == bytes(
            (49, 128, 4, 1, 97, 4, 2, 97, 98, 0, 0)
        )

    def testIndefMode3(self):
        self.s.clear()
        self.s.append("b")
        self.s.append("a")

        assert cer_encoder.encode(self.s) == bytes((49, 128, 4, 1, 97, 4, 1, 98, 0, 0))

    def testIndefMode4(self):
        self.s.clear()
        self.s.append("a")
        self.s.append("b")

        assert cer_encoder.encode(self.s) == bytes((49, 128, 4, 1, 97, 4, 1, 98, 0, 0))


class SetEncoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.Set()
        self.s.setComponentByPosition(0, univ.Null(""))
        self.s.setComponentByPosition(1, univ.OctetString("quick brown"))
        self.s.setComponentByPosition(2, univ.Integer(1))

    def testIndefMode(self):
        assert cer_encoder.encode(self.s) == bytes(
            (
                49,
                128,
                2,
                1,
                1,
                4,
                11,
                113,
                117,
                105,
                99,
                107,
                32,
                98,
                114,
                111,
                119,
                110,
                5,
                0,
                0,
                0,
            )
        )

    def testWithOptionalIndefMode(self):
        assert cer_encoder.encode(self.s) == bytes(
            (
                49,
                128,
                2,
                1,
                1,
                4,
                11,
                113,
                117,
                105,
                99,
                107,
                32,
                98,
                114,
                111,
                119,
                110,
                5,
                0,
                0,
                0,
            )
        )

    def testWithDefaultedIndefMode(self):
        assert cer_encoder.encode(self.s) == bytes(
            (
                49,
                128,
                2,
                1,
                1,
                4,
                11,
                113,
                117,
                105,
                99,
                107,
                32,
                98,
                114,
                111,
                119,
                110,
                5,
                0,
                0,
                0,
            )
        )

    def testWithOptionalAndDefaultedIndefMode(self):
        assert cer_encoder.encode(self.s) == bytes(
            (
                49,
                128,
                2,
                1,
                1,
                4,
                11,
                113,
                117,
                105,
                99,
                107,
                32,
                98,
                114,
                111,
                119,
                110,
                5,
                0,
                0,
                0,
            )
        )


class SetEncoderWithSchemaTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.Set(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("place-holder", univ.Null("")),
                namedtype.OptionalNamedType("first-name", univ.OctetString()),
                namedtype.DefaultedNamedType("age", univ.Integer(33)),
            )
        )

    def __init(self):
        self.s.clear()
        self.s.setComponentByPosition(0)

    def __initWithOptional(self):
        self.s.clear()
        self.s.setComponentByPosition(0)
        self.s.setComponentByPosition(1, "quick brown")

    def __initWithDefaulted(self):
        self.s.clear()
        self.s.setComponentByPosition(0)
        self.s.setComponentByPosition(2, 1)

    def __initWithOptionalAndDefaulted(self):
        self.s.clear()
        self.s.setComponentByPosition(0, univ.Null(""))
        self.s.setComponentByPosition(1, univ.OctetString("quick brown"))
        self.s.setComponentByPosition(2, univ.Integer(1))

    def testIndefMode(self):
        self.__init()
        assert cer_encoder.encode(self.s) == bytes((49, 128, 5, 0, 0, 0))

    def testWithOptionalIndefMode(self):
        self.__initWithOptional()
        assert cer_encoder.encode(self.s) == bytes(
            (
                49,
                128,
                4,
                11,
                113,
                117,
                105,
                99,
                107,
                32,
                98,
                114,
                111,
                119,
                110,
                5,
                0,
                0,
                0,
            )
        )

    def testWithDefaultedIndefMode(self):
        self.__initWithDefaulted()
        assert cer_encoder.encode(self.s) == bytes((49, 128, 2, 1, 1, 5, 0, 0, 0))

    def testWithOptionalAndDefaultedIndefMode(self):
        self.__initWithOptionalAndDefaulted()
        assert cer_encoder.encode(self.s) == bytes(
            (
                49,
                128,
                2,
                1,
                1,
                4,
                11,
                113,
                117,
                105,
                99,
                107,
                32,
                98,
                114,
                111,
                119,
                110,
                5,
                0,
                0,
                0,
            )
        )


class SetEncoderWithChoiceWithSchemaEncoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        c = univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("actual", univ.Boolean(0))
            )
        )
        self.s = univ.Set(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("place-holder", univ.Null("")),
                namedtype.NamedType("status", c),
            )
        )

    def testIndefMode(self):
        self.s.setComponentByPosition(0)
        self.s.setComponentByName("status")
        self.s.getComponentByName("status").setComponentByPosition(0, 1)
        assert cer_encoder.encode(self.s) == bytes((49, 128, 1, 1, 255, 5, 0, 0, 0))


class SetEncoderWithTaggedChoiceEncoderTestCase(BaseTestCase):
    def testWithUntaggedChoice(self):
        c = univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("premium", univ.Boolean())
            )
        )

        s = univ.Set(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("name", univ.OctetString()),
                namedtype.NamedType("customer", c),
            )
        )

        s.setComponentByName("name", "A")
        s.getComponentByName("customer").setComponentByName("premium", True)

        assert cer_encoder.encode(s) == bytes((49, 128, 1, 1, 255, 4, 1, 65, 0, 0))

    def testWithTaggedChoice(self):
        c = univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("premium", univ.Boolean())
            )
        ).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 7))

        s = univ.Set(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("name", univ.OctetString()),
                namedtype.NamedType("customer", c),
            )
        )

        s.setComponentByName("name", "A")
        s.getComponentByName("customer").setComponentByName("premium", True)

        assert cer_encoder.encode(s) == bytes(
            (49, 128, 4, 1, 65, 167, 128, 1, 1, 255, 0, 0, 0, 0)
        )


class SequenceEncoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.Sequence()
        self.s.setComponentByPosition(0, univ.Null(""))
        self.s.setComponentByPosition(1, univ.OctetString("quick brown"))
        self.s.setComponentByPosition(2, univ.Integer(1))

    def testIndefMode(self):
        assert cer_encoder.encode(self.s) == bytes(
            (
                48,
                128,
                5,
                0,
                4,
                11,
                113,
                117,
                105,
                99,
                107,
                32,
                98,
                114,
                111,
                119,
                110,
                2,
                1,
                1,
                0,
                0,
            )
        )

    def testWithOptionalIndefMode(self):
        assert cer_encoder.encode(self.s) == bytes(
            (
                48,
                128,
                5,
                0,
                4,
                11,
                113,
                117,
                105,
                99,
                107,
                32,
                98,
                114,
                111,
                119,
                110,
                2,
                1,
                1,
                0,
                0,
            )
        )

    def testWithDefaultedIndefMode(self):
        assert cer_encoder.encode(self.s) == bytes(
            (
                48,
                128,
                5,
                0,
                4,
                11,
                113,
                117,
                105,
                99,
                107,
                32,
                98,
                114,
                111,
                119,
                110,
                2,
                1,
                1,
                0,
                0,
            )
        )

    def testWithOptionalAndDefaultedIndefMode(self):
        assert cer_encoder.encode(self.s) == bytes(
            (
                48,
                128,
                5,
                0,
                4,
                11,
                113,
                117,
                105,
                99,
                107,
                32,
                98,
                114,
                111,
                119,
                110,
                2,
                1,
                1,
                0,
                0,
            )
        )


class SequenceEncoderWithSchemaTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("place-holder", univ.Null("")),
                namedtype.OptionalNamedType("first-name", univ.OctetString()),
                namedtype.DefaultedNamedType("age", univ.Integer(33)),
            )
        )

    def __init(self):
        self.s.clear()
        self.s.setComponentByPosition(0)

    def __initWithOptional(self):
        self.s.clear()
        self.s.setComponentByPosition(0)
        self.s.setComponentByPosition(1, "quick brown")

    def __initWithDefaulted(self):
        self.s.clear()
        self.s.setComponentByPosition(0)
        self.s.setComponentByPosition(2, 1)

    def __initWithOptionalAndDefaulted(self):
        self.s.clear()
        self.s.setComponentByPosition(0, univ.Null(""))
        self.s.setComponentByPosition(1, univ.OctetString("quick brown"))
        self.s.setComponentByPosition(2, univ.Integer(1))

    def testIndefMode(self):
        self.__init()
        assert cer_encoder.encode(self.s) == bytes((48, 128, 5, 0, 0, 0))

    def testWithOptionalIndefMode(self):
        self.__initWithOptional()
        assert cer_encoder.encode(self.s) == bytes(
            (
                48,
                128,
                5,
                0,
                4,
                11,
                113,
                117,
                105,
                99,
                107,
                32,
                98,
                114,
                111,
                119,
                110,
                0,
                0,
            )
        )

    def testWithDefaultedIndefMode(self):
        self.__initWithDefaulted()
        assert cer_encoder.encode(self.s) == bytes((48, 128, 5, 0, 2, 1, 1, 0, 0))

    def testWithOptionalAndDefaultedIndefMode(self):
        self.__initWithOptionalAndDefaulted()
        assert cer_encoder.encode(self.s) == bytes(
            (
                48,
                128,
                5,
                0,
                4,
                11,
                113,
                117,
                105,
                99,
                107,
                32,
                98,
                114,
                111,
                119,
                110,
                2,
                1,
                1,
                0,
                0,
            )
        )


class SequenceEncoderWithUntaggedOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        openType = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType("blob", univ.Any(), openType=openType),
            )
        )

    def testEncodeOpenTypeChoiceOne(self):
        self.s.clear()

        self.s[0] = 1
        self.s[1] = univ.Integer(12)

        assert cer_encoder.encode(self.s, asn1Spec=self.s) == bytes(
            (48, 128, 2, 1, 1, 49, 50, 0, 0)
        )

    def testEncodeOpenTypeChoiceTwo(self):
        self.s.clear()

        self.s[0] = 2
        self.s[1] = univ.OctetString("quick brown")

        assert cer_encoder.encode(self.s, asn1Spec=self.s) == bytes(
            (48, 128, 2, 1, 2, 113, 117, 105, 99, 107, 32, 98, 114, 111, 119, 110, 0, 0)
        )

    def testEncodeOpenTypeUnknownId(self):
        self.s.clear()

        self.s[0] = 2
        self.s[1] = univ.ObjectIdentifier("1.3.6")

        try:
            cer_encoder.encode(self.s, asn1Spec=self.s)

        except PyAsn1Error:
            assert False, "incompatible open type tolerated"

    def testEncodeOpenTypeIncompatibleType(self):
        self.s.clear()

        self.s[0] = 2
        self.s[1] = univ.ObjectIdentifier("1.3.6")

        try:
            cer_encoder.encode(self.s, asn1Spec=self.s)

        except PyAsn1Error:
            assert False, "incompatible open type tolerated"


class SequenceEncoderWithImplicitlyTaggedOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        openType = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType(
                    "blob",
                    univ.Any().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
                    ),
                    openType=openType,
                ),
            )
        )

    def testEncodeOpenTypeChoiceOne(self):
        self.s.clear()

        self.s[0] = 1
        self.s[1] = univ.Integer(12)

        assert cer_encoder.encode(self.s, asn1Spec=self.s) == bytes(
            (48, 128, 2, 1, 1, 163, 128, 163, 128, 49, 50, 0, 0, 0, 0, 0, 0)
        )


class SequenceEncoderWithExplicitlyTaggedOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        openType = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType(
                    "blob",
                    univ.Any().subtype(
                        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
                    ),
                    openType=openType,
                ),
            )
        )

    def testEncodeOpenTypeChoiceOne(self):
        self.s.clear()

        self.s[0] = 1
        self.s[1] = univ.Integer(12)

        assert cer_encoder.encode(self.s, asn1Spec=self.s) == bytes(
            (48, 128, 2, 1, 1, 163, 128, 163, 128, 49, 50, 0, 0, 0, 0, 0, 0)
        )


class SequenceEncoderWithUntaggedSetOfOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        openType = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType(
                    "blob", univ.SetOf(componentType=univ.Any()), openType=openType
                ),
            )
        )

    def testEncodeOpenTypeChoiceOne(self):
        self.s.clear()

        self.s[0] = 1
        self.s[1].append(univ.Integer(12))

        assert cer_encoder.encode(self.s, asn1Spec=self.s) == bytes(
            (48, 128, 2, 1, 1, 49, 128, 49, 50, 0, 0, 0, 0)
        )

    def testEncodeOpenTypeChoiceTwo(self):
        self.s.clear()

        self.s[0] = 2
        self.s[1].append(univ.OctetString("quick brown"))

        assert cer_encoder.encode(self.s, asn1Spec=self.s) == bytes(
            (
                48,
                128,
                2,
                1,
                2,
                49,
                128,
                113,
                117,
                105,
                99,
                107,
                32,
                98,
                114,
                111,
                119,
                110,
                0,
                0,
                0,
                0,
            )
        )

    def testEncodeOpenTypeUnknownId(self):
        self.s.clear()

        self.s[0] = 2
        self.s[1].append(univ.ObjectIdentifier("1.3.6"))

        try:
            cer_encoder.encode(self.s, asn1Spec=self.s)

        except PyAsn1Error:
            assert False, "incompatible open type tolerated"

    def testEncodeOpenTypeIncompatibleType(self):
        self.s.clear()

        self.s[0] = 2
        self.s[1].append(univ.ObjectIdentifier("1.3.6"))

        try:
            cer_encoder.encode(self.s, asn1Spec=self.s)

        except PyAsn1Error:
            assert False, "incompatible open type tolerated"


class SequenceEncoderWithImplicitlyTaggedSetOfOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        openType = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType(
                    "blob",
                    univ.SetOf(
                        componentType=univ.Any().subtype(
                            implicitTag=tag.Tag(
                                tag.tagClassContext, tag.tagFormatSimple, 3
                            )
                        )
                    ),
                    openType=openType,
                ),
            )
        )

    def testEncodeOpenTypeChoiceOne(self):
        self.s.clear()

        self.s[0] = 1
        self.s[1].append(univ.Integer(12))

        assert cer_encoder.encode(self.s, asn1Spec=self.s) == bytes(
            (
                48,
                128,
                2,
                1,
                1,
                49,
                128,
                163,
                128,
                163,
                128,
                49,
                50,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            )
        )


class SequenceEncoderWithExplicitlyTaggedSetOfOpenTypesTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)

        openType = opentype.OpenType("id", {1: univ.Integer(), 2: univ.OctetString()})
        self.s = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("id", univ.Integer()),
                namedtype.NamedType(
                    "blob",
                    univ.SetOf(
                        componentType=univ.Any().subtype(
                            explicitTag=tag.Tag(
                                tag.tagClassContext, tag.tagFormatSimple, 3
                            )
                        )
                    ),
                    openType=openType,
                ),
            )
        )

    def testEncodeOpenTypeChoiceOne(self):
        self.s.clear()

        self.s[0] = 1
        self.s[1].append(univ.Integer(12))

        assert cer_encoder.encode(self.s, asn1Spec=self.s) == bytes(
            (
                48,
                128,
                2,
                1,
                1,
                49,
                128,
                163,
                128,
                163,
                128,
                49,
                50,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            )
        )


class NestedOptionalSequenceEncoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        inner = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.OptionalNamedType("first-name", univ.OctetString()),
                namedtype.DefaultedNamedType("age", univ.Integer(33)),
            )
        )

        outerWithOptional = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.OptionalNamedType("inner", inner),
            )
        )

        outerWithDefault = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.DefaultedNamedType("inner", inner),
            )
        )

        self.s1 = outerWithOptional
        self.s2 = outerWithDefault

    def __initOptionalWithDefaultAndOptional(self):
        self.s1.clear()
        self.s1[0][0] = "test"
        self.s1[0][1] = 123
        return self.s1

    def __initOptionalWithDefault(self):
        self.s1.clear()
        self.s1[0][1] = 123
        return self.s1

    def __initOptionalWithOptional(self):
        self.s1.clear()
        self.s1[0][0] = "test"
        return self.s1

    def __initOptional(self):
        self.s1.clear()
        return self.s1

    def __initDefaultWithDefaultAndOptional(self):
        self.s2.clear()
        self.s2[0][0] = "test"
        self.s2[0][1] = 123
        return self.s2

    def __initDefaultWithDefault(self):
        self.s2.clear()
        self.s2[0][0] = "test"
        return self.s2

    def __initDefaultWithOptional(self):
        self.s2.clear()
        self.s2[0][1] = 123
        return self.s2

    def testOptionalWithDefaultAndOptional(self):
        s = self.__initOptionalWithDefaultAndOptional()
        assert cer_encoder.encode(s) == bytes(
            (48, 128, 48, 128, 4, 4, 116, 101, 115, 116, 2, 1, 123, 0, 0, 0, 0)
        )

    def testOptionalWithDefault(self):
        s = self.__initOptionalWithDefault()
        assert cer_encoder.encode(s) == bytes((48, 128, 48, 128, 2, 1, 123, 0, 0, 0, 0))

    def testOptionalWithOptional(self):
        s = self.__initOptionalWithOptional()
        assert cer_encoder.encode(s) == bytes(
            (48, 128, 48, 128, 4, 4, 116, 101, 115, 116, 0, 0, 0, 0)
        )

    def testOptional(self):
        s = self.__initOptional()
        assert cer_encoder.encode(s) == bytes((48, 128, 0, 0))

    def testDefaultWithDefaultAndOptional(self):
        s = self.__initDefaultWithDefaultAndOptional()
        assert cer_encoder.encode(s) == bytes(
            (48, 128, 48, 128, 4, 4, 116, 101, 115, 116, 2, 1, 123, 0, 0, 0, 0)
        )

    def testDefaultWithDefault(self):
        s = self.__initDefaultWithDefault()
        assert cer_encoder.encode(s) == bytes(
            (48, 128, 48, 128, 4, 4, 116, 101, 115, 116, 0, 0, 0, 0)
        )

    def testDefaultWithOptional(self):
        s = self.__initDefaultWithOptional()
        assert cer_encoder.encode(s) == bytes((48, 128, 48, 128, 2, 1, 123, 0, 0, 0, 0))


class NestedOptionalChoiceEncoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        layer3 = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.OptionalNamedType("first-name", univ.OctetString()),
                namedtype.DefaultedNamedType("age", univ.Integer(33)),
            )
        )

        layer2 = univ.Choice(
            componentType=namedtype.NamedTypes(
                namedtype.NamedType("inner", layer3),
                namedtype.NamedType("first-name", univ.OctetString()),
            )
        )

        layer1 = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.OptionalNamedType("inner", layer2),
            )
        )

        self.s = layer1

    def __initOptionalWithDefaultAndOptional(self):
        self.s.clear()
        self.s[0][0][0] = "test"
        self.s[0][0][1] = 123
        return self.s

    def __initOptionalWithDefault(self):
        self.s.clear()
        self.s[0][0][1] = 123
        return self.s

    def __initOptionalWithOptional(self):
        self.s.clear()
        self.s[0][0][0] = "test"
        return self.s

    def __initOptional(self):
        self.s.clear()
        return self.s

    def testOptionalWithDefaultAndOptional(self):
        s = self.__initOptionalWithDefaultAndOptional()
        assert cer_encoder.encode(s) == bytes(
            (48, 128, 48, 128, 4, 4, 116, 101, 115, 116, 2, 1, 123, 0, 0, 0, 0)
        )

    def testOptionalWithDefault(self):
        s = self.__initOptionalWithDefault()
        assert cer_encoder.encode(s) == bytes((48, 128, 48, 128, 2, 1, 123, 0, 0, 0, 0))

    def testOptionalWithOptional(self):
        s = self.__initOptionalWithOptional()
        assert cer_encoder.encode(s) == bytes(
            (48, 128, 48, 128, 4, 4, 116, 101, 115, 116, 0, 0, 0, 0)
        )

    def testOptional(self):
        s = self.__initOptional()
        assert cer_encoder.encode(s) == bytes((48, 128, 0, 0))


class NestedOptionalSequenceOfEncoderTestCase(BaseTestCase):
    def setUp(self):
        BaseTestCase.setUp(self)
        layer2 = univ.SequenceOf(componentType=univ.OctetString())

        layer1 = univ.Sequence(
            componentType=namedtype.NamedTypes(
                namedtype.OptionalNamedType("inner", layer2),
            )
        )

        self.s = layer1

    def __initOptionalWithValue(self):
        self.s.clear()
        self.s[0][0] = "test"
        return self.s

    def __initOptional(self):
        self.s.clear()
        return self.s

    def testOptionalWithValue(self):
        s = self.__initOptionalWithValue()
        assert cer_encoder.encode(s) == bytes(
            (48, 128, 48, 128, 4, 4, 116, 101, 115, 116, 0, 0, 0, 0)
        )

    def testOptional(self):
        s = self.__initOptional()
        assert cer_encoder.encode(s) == bytes((48, 128, 0, 0))


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite)