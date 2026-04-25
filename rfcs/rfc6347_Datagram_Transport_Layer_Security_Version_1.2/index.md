# RFC 6347: Datagram Transport Layer Security Version 1.2

Source: `../rfc6347_Datagram_Transport_Layer_Security_Version_1.2.md`

Use this file first. It is the compact map for the section files in this RFC.

## Data
- `file`: section file name
- `sec`: RFC section number
- `intent`: short section purpose
- `use`: one short cue or example
- `ref`: parent RFC source file

## Sections
- `3.1_Loss_Insensitive_Messaging.md` | sec `3.1` | intent `Loss-Insensitive Messaging` | use `In TLS's traffic encryption layer (called the TLS Record Layer), records are not independent.…` | ref `3_Overview_of_DTLS.md`
- `3.2_Providing_Reliability_for_Handshake.md` | sec `3.2` | intent `Providing Reliability for Handshake` | use `The TLS handshake is a lockstep cryptographic handshake. Messages must be transmitted and…` | ref `3_Overview_of_DTLS.md`
- `3.2.1_Packet_Loss.md` | sec `3.2.1` | intent `Packet Loss` | use `DTLS uses a simple retransmission timer to handle packet loss. The following figure…` | ref `3_Overview_of_DTLS.md`
- `3.2.2_Reordering.md` | sec `3.2.2` | intent `Reordering` | use `In DTLS, each handshake message is assigned a specific sequence number within that handshake.…` | ref `3_Overview_of_DTLS.md`
- `3.2.3_Message_Size.md` | sec `3.2.3` | intent `Message Size` | use `TLS and DTLS handshake messages can be quite large (in theory up to 2^24-1 bytes, in practice…` | ref `3_Overview_of_DTLS.md`
- `3.3_Replay_Detection.md` | sec `3.3` | intent `Replay Detection` | use `DTLS optionally supports record replay detection. The technique used is the same as in IPsec…` | ref `3_Overview_of_DTLS.md`
- `4_Differences_from_TLS.md` | sec `4` | intent `Differences from TLS` | use `As mentioned in Section 3, DTLS is intentionally very similar to TLS. Therefore, instead of…` | ref `3_Overview_of_DTLS.md`
- `4.1_Record_Layer.md` | sec `4.1` | intent `Record Layer` | use `The DTLS record layer is extremely similar to that of TLS 1.2. The only change is the inclusion…` | ref `4_Differences_from_TLS.md`
- `4.1.1_Transport_Layer_Mapping.md` | sec `4.1.1` | intent `Transport Layer Mapping` | use `Each DTLS record MUST fit within a single datagram. In order to avoid IP fragmentation, clients…` | ref `4_Differences_from_TLS.md`
- `4.1.2_Record_Payload_Protection.md` | sec `4.1.2` | intent `Record Payload Protection` | use `Like TLS, DTLS transmits data as a series of protected records. The rest of this section…` | ref `4_Differences_from_TLS.md`
- `4.2_The_DTLS_Handshake_Protocol.md` | sec `4.2` | intent `The DTLS Handshake Protocol` | use `DTLS uses all of the same handshake messages and flows as TLS, with three principal changes:` | ref `4_Differences_from_TLS.md`
- `4.2.1_Denial_of_Service_Countermeasures.md` | sec `4.2.1` | intent `Denial-of-Service Countermeasures` | use `Datagram security protocols are extremely susceptible to a variety of DoS attacks. Two attacks…` | ref `4_Differences_from_TLS.md`
- `4.2.2_Handshake_Message_Format.md` | sec `4.2.2` | intent `Handshake Message Format` | use `In order to support message loss, reordering, and message fragmentation, DTLS modifies the TLS…` | ref `4_Differences_from_TLS.md`
- `4.2.3_Handshake_Message_Fragmentation_and_Reassembly.md` | sec `4.2.3` | intent `Handshake Message Fragmentation and…` | use `As noted in Section 4.1.1, each DTLS message MUST fit within a single transport layer datagram.…` | ref `4_Differences_from_TLS.md`
- `4.2.4_Timeout_and_Retransmission.md` | sec `4.2.4` | intent `Timeout and Retransmission` | use `DTLS messages are grouped into a series of message flights, according to the diagrams below.…` | ref `4_Differences_from_TLS.md`
- `4.2.5_ChangeCipherSpec.md` | sec `4.2.5` | intent `ChangeCipherSpec` | use `As with TLS, the ChangeCipherSpec message is not technically a handshake message but MUST be…` | ref `4_Differences_from_TLS.md`
- `4.2.6_CertificateVerify_and_Finished_Messages.md` | sec `4.2.6` | intent `CertificateVerify and Finished Messages` | use `CertificateVerify and Finished messages have the same format as in TLS. Hash calculations…` | ref `4_Differences_from_TLS.md`
- `4.2.7_Alert_Messages.md` | sec `4.2.7` | intent `Alert Messages` | use `Note that Alert messages are not retransmitted at all, even when they occur in the context of a…` | ref `4_Differences_from_TLS.md`
- `4.2.8_Establishing_New_Associations_with_Existing_Parameters.md` | sec `4.2.8` | intent `Establishing New Associations with…` | use `If a DTLS client-server pair is configured in such a way that repeated connections happen on…` | ref `4_Differences_from_TLS.md`
- `4.3_Summary_of_New_Syntax.md` | sec `4.3` | intent `Summary of New Syntax` | use `This section includes specifications for the data structures that have changed between TLS 1.2…` | ref `4_Differences_from_TLS.md`
- `4.3.1_Record_Layer.md` | sec `4.3.1` | intent `Record Layer` | use `struct { ContentType type; ProtocolVersion version; uint16 epoch; // New field uint48…` | ref `4_Differences_from_TLS.md`
