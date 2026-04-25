# RFC 5764: Datagram Transport Layer Security (DTLS) Extension to Establish Keys for the Secure Real-time Transport Protocol (SRTP)

Source: `../rfc5764_Datagram_Transport_Layer_Security_(DTLS)_Extension_to_Establish_Keys_for_the_Secure_Real-time_Transport_Protocol_(SRTP).md`

Use this file first. It is the compact map for the section files in this RFC.

## Data
- `file`: section file name
- `sec`: RFC section number
- `intent`: short section purpose
- `use`: one short cue or example
- `ref`: parent RFC source file

## Sections
- `4.1_The_use_srtp_Extension.md` | sec `4.1` | intent `The use_srtp Extension` | use `In order to negotiate the use of SRTP data protection, clients include an extension of type…` | ref `4_DTLS_Extensions_for_SRTP_Key_Establishment.md`
- `4.1.1_use_srtp_Extension_Definition.md` | sec `4.1.1` | intent `use_srtp Extension Definition` | use `The client MUST fill the extension_data field of the "use_srtp" extension with an UseSRTPData…` | ref `4_DTLS_Extensions_for_SRTP_Key_Establishment.md`
- `4.1.2_SRTP_Protection_Profiles.md` | sec `4.1.2` | intent `SRTP Protection Profiles` | use `A DTLS-SRTP SRTP Protection Profile defines the parameters and options that are in effect for…` | ref `4_DTLS_Extensions_for_SRTP_Key_Establishment.md`
- `4.1.3_srtp_mki_value.md` | sec `4.1.3` | intent `srtp_mki value` | use `The srtp_mki value MAY be used to indicate the capability and desire to use the SRTP Master Key…` | ref `4_DTLS_Extensions_for_SRTP_Key_Establishment.md`
- `4.2_Key_Derivation.md` | sec `4.2` | intent `Key Derivation` | use `When SRTP mode is in effect, different keys are used for ordinary DTLS record protection and…` | ref `4_DTLS_Extensions_for_SRTP_Key_Establishment.md`
- `4.3_Key_Scope.md` | sec `4.3` | intent `Key Scope` | use `Because of the possibility of packet reordering, DTLS-SRTP implementations SHOULD store…` | ref `4_DTLS_Extensions_for_SRTP_Key_Establishment.md`
- `4.4_Key_Usage_Limitations.md` | sec `4.4` | intent `Key Usage Limitations` | use `The maximum_lifetime parameter in the SRTP protection profile indicates the maximum number of…` | ref `4_DTLS_Extensions_for_SRTP_Key_Establishment.md`
- `5.1_Data_Protection.md` | sec `5.1` | intent `Data Protection` | use `Once the DTLS handshake has completed, the peers can send RTP or RTCP over the newly created…` | ref `5_Use_of_RTP_and_RTCP_over_a_DTLS-SRTP_Channel.md`
- `5.1.1_Transmission.md` | sec `5.1.1` | intent `Transmission` | use `DTLS and TLS define a number of record content types. In ordinary TLS/DTLS, all data is…` | ref `5_Use_of_RTP_and_RTCP_over_a_DTLS-SRTP_Channel.md`
- `5.1.2_Reception.md` | sec `5.1.2` | intent `Reception` | use `When DTLS-SRTP is used to protect an RTP session, the RTP receiver needs to demultiplex packets…` | ref `5_Use_of_RTP_and_RTCP_over_a_DTLS-SRTP_Channel.md`
- `5.2_Rehandshake_and_Rekey.md` | sec `5.2` | intent `Rehandshake and Rekey` | use `Rekeying in DTLS is accomplished by performing a new handshake over the existing DTLS channel.…` | ref `5_Use_of_RTP_and_RTCP_over_a_DTLS-SRTP_Channel.md`
- `6_Multi_Party_RTP_Sessions.md` | sec `6` | intent `Multi-Party RTP Sessions` | use `Since DTLS is a point-to-point protocol, DTLS-SRTP is intended only to protect unicast RTP…` | ref `5_Use_of_RTP_and_RTCP_over_a_DTLS-SRTP_Channel.md`
- `7.1_Security_of_Negotiation.md` | sec `7.1` | intent `Security of Negotiation` | use `One concern here is that attackers might be able to implement a bid- down attack forcing the…` | ref `7_Security_Considerations.md`
- `7.2_Framing_Confusion.md` | sec `7.2` | intent `Framing Confusion` | use `Because two different framing formats are used, there is concern that an attacker could…` | ref `7_Security_Considerations.md`
- `7.3_Sequence_Number_Interactions.md` | sec `7.3` | intent `Sequence Number Interactions` | use `As described in Section 5.1.1, the SRTP and DTLS sequence number spaces are distinct. This…` | ref `7_Security_Considerations.md`
- `7.3.1_Alerts.md` | sec `7.3.1` | intent `Alerts` | use `Because DTLS handshake and change_cipher_spec messages share the same sequence number space as…` | ref `7_Security_Considerations.md`
- `7.3.2_Renegotiation.md` | sec `7.3.2` | intent `Renegotiation` | use `Because the rehandshake transition algorithm specified in Section 5.2 requires trying multiple…` | ref `7_Security_Considerations.md`
- `7.4_Decryption_Cost.md` | sec `7.4` | intent `Decryption Cost` | use `An attacker can impose computational costs on the receiver by sending superficially valid SRTP…` | ref `7_Security_Considerations.md`
- `8_Session_Description_for_RTP_SAVP_over_DTLS.md` | sec `8` | intent `Session Description for RTP/SAVP over DTLS` | use `This specification defines new tokens to describe the protocol used in SDP media descriptions…` | ref `7_Security_Considerations.md`
