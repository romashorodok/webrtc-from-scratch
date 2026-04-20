# 5.  Default and mandatory-to-implement Transforms

The default transforms also are mandatory-to-implement transforms in
SRTP.  Of course, "mandatory-to-implement" does not imply
"mandatory-to-use".  Table 1 summarizes the pre-defined transforms.
The default values below are valid for the pre-defined transforms.

                         mandatory-to-impl.   optional     default

   encryption            AES-CM, NULL         AES-f8       AES-CM
   message integrity     HMAC-SHA1              -          HMAC-SHA1
   key derivation (PRF)  AES-CM                 -          AES-CM

   Table 1: Mandatory-to-implement, optional and default transforms in
   SRTP and SRTCP.

## 5.1.  Encryption: AES-CM and NULL

AES running in Segmented Integer Counter Mode, as defined in Section
4.1.1, SHALL be the default encryption algorithm.  The default key
lengths SHALL be 128-bit for the session encryption key (n_e).  The
default session salt key-length (n_s) SHALL be 112 bits.

The NULL cipher SHALL also be mandatory-to-implement.

## 5.2.  Message Authentication/Integrity: HMAC-SHA1

HMAC-SHA1, as defined in Section 4.2.1, SHALL be the default message
authentication code.  The default session authentication key-length
(n_a) SHALL be 160 bits, the default authentication tag length
(n_tag) SHALL be 80 bits, and the SRTP_PREFIX_LENGTH SHALL be zero
for HMAC-SHA1.  In addition, for SRTCP, the pre-defined HMAC-SHA1
MUST NOT be applied with a value of n_tag, nor n_a, that are smaller
than these defaults.  For SRTP, smaller values are NOT RECOMMENDED,
but MAY be used after careful consideration of the issues in Section
7.5 and 9.5

## 5.3.  Key Derivation: AES-CM PRF

The AES Counter Mode based key derivation and PRF defined in Sections
4.3.1 to 4.3.3, using a 128-bit master key, SHALL be the default
method for generating session keys.  The default master salt length
SHALL be 112 bits and the default key-derivation rate SHALL be zero.
