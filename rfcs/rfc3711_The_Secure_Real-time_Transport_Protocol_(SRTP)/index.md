# RFC 3711: The Secure Real-time Transport Protocol (SRTP)

Source: `../rfc3711_The_Secure_Real-time_Transport_Protocol_(SRTP).md`

Use this file first. It is the compact map for the section files in this RFC.

## Data
- `file`: section file name
- `sec`: RFC section number
- `intent`: short section purpose
- `use`: one short cue or example
- `ref`: parent RFC source file

## Sections
- `2.1_Features.md` | sec `2.1` | intent `Features` | use `Besides the above mentioned direct goals, SRTP provides for some additional features. They have…` | ref `2_Goals_and_Features.md`
- `3.1_Secure_RTP.md` | sec `3.1` | intent `Secure RTP` | use `The format of an SRTP packet is illustrated in Figure 1.` | ref `3_SRTP_Framework.md`
- `3.2_SRTP_Cryptographic_Contexts.md` | sec `3.2` | intent `SRTP Cryptographic Contexts` | use `Each SRTP stream requires the sender and receiver to maintain cryptographic state information.…` | ref `3_SRTP_Framework.md`
- `3.2.1_Transform_independent_parameters.md` | sec `3.2.1` | intent `Transform-independent parameters` | use `Transform-independent parameters are present in the cryptographic context independently of the…` | ref `3_SRTP_Framework.md`
- `3.2.3_Mapping_SRTP_Packets_to_Cryptographic_Contexts.md` | sec `3.2.3` | intent `Mapping SRTP Packets to Cryptographic…` | use `Recall that an RTP session for each participant is defined [RFC3550] by a pair of destination…` | ref `3_SRTP_Framework.md`
- `3.3_SRTP_Packet_Processing.md` | sec `3.3` | intent `SRTP Packet Processing` | use `The following applies to SRTP. SRTCP is described in Section 3.4.` | ref `3_SRTP_Framework.md`
- `3.3.1_Packet_Index_Determination_and_ROC_s_l_Update.md` | sec `3.3.1` | intent `Packet Index Determination, and ROC, s_l…` | use `SRTP implementations use an "implicit" packet index for sequencing, i.e., not all of the index…` | ref `3_SRTP_Framework.md`
- `3.3.2_Replay_Protection.md` | sec `3.3.2` | intent `Replay Protection` | use `Secure replay protection is only possible when integrity protection is present. It is…` | ref `3_SRTP_Framework.md`
- `3.4_Secure_RTCP.md` | sec `3.4` | intent `Secure RTCP` | use `Secure RTCP follows the definition of Secure RTP. SRTCP adds three mandatory new fields (the…` | ref `3_SRTP_Framework.md`
- `4.1_Encryption.md` | sec `4.1` | intent `Encryption` | use `The following parameters are common to both pre-defined, non-NULL, encryption transforms…` | ref `4_Pre-Defined_Cryptographic_Transforms.md`
- `4.1.1_AES_in_Counter_Mode.md` | sec `4.1.1` | intent `AES in Counter Mode` | use `Conceptually, counter mode [AES-CTR] consists of encrypting successive integers. The actual…` | ref `4_Pre-Defined_Cryptographic_Transforms.md`
- `4.1.2_AES_in_f8_mode.md` | sec `4.1.2` | intent `AES in f8-mode` | use `To encrypt UMTS (Universal Mobile Telecommunications System, as 3G networks) data, a solution…` | ref `4_Pre-Defined_Cryptographic_Transforms.md`
- `4.1.3_NULL_Cipher.md` | sec `4.1.3` | intent `NULL Cipher` | use `The NULL cipher is used when no confidentiality for RTP/RTCP is requested. The keystream can be…` | ref `4_Pre-Defined_Cryptographic_Transforms.md`
- `4.2_Message_Authentication_and_Integrity.md` | sec `4.2` | intent `Message Authentication and Integrity` | use `Throughout this section, M will denote data to be integrity protected. In the case of SRTP, M…` | ref `4_Pre-Defined_Cryptographic_Transforms.md`
- `4.2.1_HMAC_SHA1.md` | sec `4.2.1` | intent `HMAC-SHA1` | use `The pre-defined authentication transform for SRTP is HMAC-SHA1 [RFC2104]. With HMAC-SHA1, the…` | ref `4_Pre-Defined_Cryptographic_Transforms.md`
- `4.3_Key_Derivation.md` | sec `4.3` | intent `Key Derivation` | use `Key Derivation` | ref `4_Pre-Defined_Cryptographic_Transforms.md`
- `4.3.1_Key_Derivation_Algorithm.md` | sec `4.3.1` | intent `Key Derivation Algorithm` | use `Regardless of the encryption or message authentication transform that is employed (it may be an…` | ref `4_Pre-Defined_Cryptographic_Transforms.md`
- `4.3.2_SRTCP_Key_Derivation.md` | sec `4.3.2` | intent `SRTCP Key Derivation` | use `SRTCP SHALL by default use the same master key (and master salt) as SRTP. To do this securely,…` | ref `4_Pre-Defined_Cryptographic_Transforms.md`
- `4.3.3_AES_CM_PRF.md` | sec `4.3.3` | intent `AES-CM PRF` | use `The currently defined PRF, keyed by 128, 192, or 256 bit master key, has input block size m =…` | ref `4_Pre-Defined_Cryptographic_Transforms.md`
- `5.1_Encryption_AES_CM_and_NULL.md` | sec `5.1` | intent `Encryption: AES-CM and NULL` | use `AES running in Segmented Integer Counter Mode, as defined in Section 4.1.1, SHALL be the…` | ref `5_Default_and_mandatory-to-implement_Transforms.md`
- `5.2_Message_Authentication_Integrity_HMAC_SHA1.md` | sec `5.2` | intent `Message Authentication/Integrity: HMAC-…` | use `HMAC-SHA1, as defined in Section 4.2.1, SHALL be the default message authentication code. The…` | ref `5_Default_and_mandatory-to-implement_Transforms.md`
- `5.3_Key_Derivation_AES_CM_PRF.md` | sec `5.3` | intent `Key Derivation: AES-CM PRF` | use `The AES Counter Mode based key derivation and PRF defined in Sections 4.3.1 to 4.3.3, using a…` | ref `5_Default_and_mandatory-to-implement_Transforms.md`
- `7.1_Key_derivation.md` | sec `7.1` | intent `Key derivation` | use `Key derivation reduces the burden on the key establishment. As many as six different keys are…` | ref `6_Adding_SRTP_Transforms.md`
- `7.2_Salting_key.md` | sec `7.2` | intent `Salting key` | use `The master salt guarantees security against off-line key-collision attacks on the key…` | ref `6_Adding_SRTP_Transforms.md`
- `7.3_Message_Integrity_from_Universal_Hashing.md` | sec `7.3` | intent `Message Integrity from Universal Hashing` | use `The particular definition of the keystream given in Section 4.1 (the keystream prefix) is to…` | ref `6_Adding_SRTP_Transforms.md`
- `7.4_Data_Origin_Authentication_Considerations.md` | sec `7.4` | intent `Data Origin Authentication Considerations` | use `Note that in pair-wise communications, integrity and data origin authentication are provided…` | ref `6_Adding_SRTP_Transforms.md`
- `7.5_Short_and_Zero_length_Message_Authentication.md` | sec `7.5` | intent `Short and Zero-length Message…` | use `As shown in Figure 1, the authentication tag is RECOMMENDED in SRTP. A full 80-bit…` | ref `6_Adding_SRTP_Transforms.md`
- `8.1_Re_keying.md` | sec `8.1` | intent `Re-keying` | use `The recommended way for a particular key management system to provide re-key within SRTP is by…` | ref `6_Adding_SRTP_Transforms.md`
- `8.2_Key_Management_parameters.md` | sec `8.2` | intent `Key Management parameters` | use `The table below lists all SRTP parameters that key management can supply. For reference, it…` | ref `6_Adding_SRTP_Transforms.md`
- `9.1_SSRC_collision_and_two_time_pad.md` | sec `9.1` | intent `SSRC collision and two-time pad` | use `Any fixed keystream output, generated from the same key and index MUST only be used to encrypt…` | ref `6_Adding_SRTP_Transforms.md`
- `9.2_Key_Usage.md` | sec `9.2` | intent `Key Usage` | use `The effective key size is determined (upper bounded) by the size of the master key and, for…` | ref `6_Adding_SRTP_Transforms.md`
- `9.3_Confidentiality_of_the_RTP_Payload.md` | sec `9.3` | intent `Confidentiality of the RTP Payload` | use `SRTP's pre-defined ciphers are "seekable" stream ciphers, i.e., ciphers able to efficiently…` | ref `6_Adding_SRTP_Transforms.md`
- `9.4_Confidentiality_of_the_RTP_Header.md` | sec `9.4` | intent `Confidentiality of the RTP Header` | use `In SRTP, RTP headers are sent in the clear to allow for header compression. This means that…` | ref `6_Adding_SRTP_Transforms.md`
- `9.5_Integrity_of_the_RTP_payload_and_header.md` | sec `9.5` | intent `Integrity of the RTP payload and header` | use `SRTP messages are subject to attacks on their integrity and source identification, and these…` | ref `6_Adding_SRTP_Transforms.md`
- `11.1_Unicast.md` | sec `11.1` | intent `Unicast` | use `A typical example would be a voice call or video-on-demand application.` | ref `6_Adding_SRTP_Transforms.md`
- `11.2_Multicast_one_sender.md` | sec `11.2` | intent `Multicast (one sender)` | use `Just as with (unprotected) RTP, a scalability issue arises in big groups due to the possibly…` | ref `6_Adding_SRTP_Transforms.md`
- `11.3_Re_keying_and_access_control.md` | sec `11.3` | intent `Re-keying and access control` | use `Re-keying may occur due to access control (e.g., when a member is removed during a multicast…` | ref `6_Adding_SRTP_Transforms.md`
- `11.4_Summary_of_basic_scenarios.md` | sec `11.4` | intent `Summary of basic scenarios` | use `The description of these scenarios highlights some recommendations on the use of SRTP, mainly…` | ref `6_Adding_SRTP_Transforms.md`
- `B.1_AES_f8_Test_Vectors.md` | sec `B.1` | intent `AES-f8 Test Vectors` | use `SRTP PREFIX LENGTH : 0` | ref `6_Adding_SRTP_Transforms.md`
- `B.2_AES_CM_Test_Vectors.md` | sec `B.2` | intent `AES-CM Test Vectors` | use `Keystream segment length: 1044512 octets (65282 AES blocks) Session Key:…` | ref `6_Adding_SRTP_Transforms.md`
- `B.3_Key_Derivation_Test_Vectors.md` | sec `B.3` | intent `Key Derivation Test Vectors` | use `This section provides test data for the default key derivation function, which uses AES-128 in…` | ref `6_Adding_SRTP_Transforms.md`
