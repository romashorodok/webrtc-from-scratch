# RFC 9143: Negotiating Media Multiplexing Using the Session Description Protocol SDP

Source: original source file is not present in this worktree.

Use this file first. It is the compact map for the section files in this RFC.

## Data
- `file`: section file name
- `sec`: RFC section number
- `intent`: short section purpose
- `use`: one short cue or example
- `ref`: parent RFC source file

## Sections
- `8_Protocol_Identification.md` | sec `8` | intent `Protocol Identification` | use `Each bundled "m=" section MUST use the same transport-layer protocol.` | ref `rfc9143_Negotiating_Media_Multiplexing_Using_the_Session_Description_Protocol_SDP.md`
- `8.1_STUN_DTLS_and_SRTP.md` | sec `8.1` | intent `STUN, DTLS, and SRTP` | use `Defines how received data is identified among STUN, DTLS, and SRTP over UDP.` | ref `rfc9143_Negotiating_Media_Multiplexing_Using_the_Session_Description_Protocol_SDP.md`
- `9_RTP_Considerations.md` | sec `9` | intent `RTP Considerations` | use `All RTP-based media in a BUNDLE group belong to one RTP session.` | ref `rfc9143_Negotiating_Media_Multiplexing_Using_the_Session_Description_Protocol_SDP.md`
- `9.1_Single_RTP_Session.md` | sec `9.1` | intent `Single RTP Session` | use `A single BUNDLE group shares one RTP session and one SSRC space.` | ref `rfc9143_Negotiating_Media_Multiplexing_Using_the_Session_Description_Protocol_SDP.md`
- `9.1.1_Payload_Type_(PT)_Value_Reuse.md` | sec `9.1.1` | intent `Payload Type (PT) Value Reuse` | use `A payload type can be reused only when codec configuration is identical.` | ref `rfc9143_Negotiating_Media_Multiplexing_Using_the_Session_Description_Protocol_SDP.md`
- `9.2_Associating_RTP_RTCP_Streams_with_the_Correct_SDP_Media_Description.md` | sec `9.2` | intent `Associating RTP/RTCP Streams with the Correct SDP Media Description` | use `MID, SSRC, and payload type tables are used to route received RTP and RTCP packets.` | ref `rfc9143_Negotiating_Media_Multiplexing_Using_the_Session_Description_Protocol_SDP.md`
- `9.3_RTP_RTCP_Multiplexing.md` | sec `9.3` | intent `RTP/RTCP Multiplexing` | use `BUNDLE requires RTP/RTCP multiplexing and rtcp-mux-only support.` | ref `rfc9143_Negotiating_Media_Multiplexing_Using_the_Session_Description_Protocol_SDP.md`
- `9.3.1_SDP_Offer_Answer_Procedures.md` | sec `9.3.1` | intent `SDP Offer/Answer Procedures` | use `Offer/answer rules negotiate rtcp-mux and rtcp-mux-only for bundled RTP media.` | ref `rfc9143_Negotiating_Media_Multiplexing_Using_the_Session_Description_Protocol_SDP.md`
- `10_ICE_Considerations.md` | sec `10` | intent `ICE Considerations` | use `ICE procedures apply to the BUNDLE transport with some exceptions.` | ref `rfc9143_Negotiating_Media_Multiplexing_Using_the_Session_Description_Protocol_SDP.md`
- `Appendix_A_Design_Considerations.md` | sec `A` | intent `Design Considerations` | use `Discusses the tradeoffs behind the BUNDLE port assignment design.` | ref `rfc9143_Negotiating_Media_Multiplexing_Using_the_Session_Description_Protocol_SDP.md`
