# RFC 5761: Multiplexing RTP Data and Control Packets on a Single Port

Source: `../rfc5761_Multiplexing_RTP_Data_and_Control_Packets_on_a_Single_Port.md`

Use this file first. It is the compact map for the section files in this RFC.

## Data
- `file`: section file name
- `sec`: RFC section number
- `intent`: short section purpose
- `use`: one short cue or example
- `ref`: parent RFC source file

## Sections
- `5.1_Unicast_Sessions.md` | sec `5.1` | intent `Unicast Sessions` | use `It is acceptable to multiplex RTP and RTCP packets on a single UDP port to ease NAT traversal…` | ref `rfc5761_Multiplexing_RTP_Data_and_Control_Packets_on_a_Single_Port.md`
- `5.1.1_SDP_Signalling.md` | sec `5.1.1` | intent `SDP Signalling` | use `When the Session Description Protocol (SDP) [8] is used to negotiate RTP sessions following the…` | ref `rfc5761_Multiplexing_RTP_Data_and_Control_Packets_on_a_Single_Port.md`
- `5.1.2_Interactions_with_SIP_Forking.md` | sec `5.1.2` | intent `Interactions with SIP Forking` | use `When using SIP with a forking proxy, it is possible that an INVITE request may result in…` | ref `rfc5761_Multiplexing_RTP_Data_and_Control_Packets_on_a_Single_Port.md`
- `5.1.3_Interactions_with_ICE.md` | sec `5.1.3` | intent `Interactions with ICE` | use `It is common to use the Interactive Connectivity Establishment (ICE) [19] methodology to…` | ref `rfc5761_Multiplexing_RTP_Data_and_Control_Packets_on_a_Single_Port.md`
- `5.1.4_Interactions_with_Header_Compression.md` | sec `5.1.4` | intent `Interactions with Header Compression` | use `Multiplexing RTP and RTCP packets onto a single port may negatively impact header compression…` | ref `rfc5761_Multiplexing_RTP_Data_and_Control_Packets_on_a_Single_Port.md`
- `5.2_Any_Source_Multicast_Sessions.md` | sec `5.2` | intent `Any Source Multicast Sessions` | use `The problem of NAT traversal is less severe for Any Source Multicast (ASM) RTP sessions than…` | ref `rfc5761_Multiplexing_RTP_Data_and_Control_Packets_on_a_Single_Port.md`
- `5.3_Source_Specific_Multicast_Sessions.md` | sec `5.3` | intent `Source-Specific Multicast Sessions` | use `RTP sessions running over Source-Specific Multicast (SSM) send RTCP packets from the source to…` | ref `rfc5761_Multiplexing_RTP_Data_and_Control_Packets_on_a_Single_Port.md`
