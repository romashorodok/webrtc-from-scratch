# RFC 3550: RTP A Transport Protocol for Real-Time Applications

Source: `../rfc3550_RTP_A_Transport_Protocol_for_Real-Time_Applications.md`

Use this file first. It is the compact map for the section files in this RFC.

## Data
- `file`: section file name
- `sec`: RFC section number
- `intent`: short section purpose
- `use`: one short cue or example
- `ref`: parent RFC source file

## Sections
- `2.1_Simple_Multicast_Audio_Conference.md` | sec `2.1` | intent `Simple Multicast Audio Conference` | use `A working group of the IETF meets to discuss the latest protocol document, using the IP…` | ref `2_RTP_Use_Scenarios.md`
- `2.2_Audio_and_Video_Conference.md` | sec `2.2` | intent `Audio and Video Conference` | use `If both audio and video media are used in a conference, they are transmitted as separate RTP…` | ref `2_RTP_Use_Scenarios.md`
- `2.3_Mixers_and_Translators.md` | sec `2.3` | intent `Mixers and Translators` | use `So far, we have assumed that all sites want to receive media data in the same format. However,…` | ref `2_RTP_Use_Scenarios.md`
- `2.4_Layered_Encodings.md` | sec `2.4` | intent `Layered Encodings` | use `Multimedia applications should be able to adjust the transmission rate to match the capacity of…` | ref `2_RTP_Use_Scenarios.md`
- `5.1_RTP_Fixed_Header_Fields.md` | sec `5.1` | intent `RTP Fixed Header Fields` | use `The RTP header has the following format:` | ref `5_RTP_Data_Transfer_Protocol.md`
- `5.2_Multiplexing_RTP_Sessions.md` | sec `5.2` | intent `Multiplexing RTP Sessions` | use `For efficient protocol processing, the number of multiplexing points should be minimized, as…` | ref `5_RTP_Data_Transfer_Protocol.md`
- `5.3_Profile_Specific_Modifications_to_the_RTP_Header.md` | sec `5.3` | intent `Profile-Specific Modifications to the RTP…` | use `The existing RTP data packet header is believed to be complete for the set of functions…` | ref `5_RTP_Data_Transfer_Protocol.md`
- `5.3.1_RTP_Header_Extension.md` | sec `5.3.1` | intent `RTP Header Extension` | use `An extension mechanism is provided to allow individual implementations to experiment with new…` | ref `5_RTP_Data_Transfer_Protocol.md`
- `6.1_RTCP_Packet_Format.md` | sec `6.1` | intent `RTCP Packet Format` | use `This specification defines several RTCP packet types to carry a variety of control information:` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.2_RTCP_Transmission_Interval.md` | sec `6.2` | intent `RTCP Transmission Interval` | use `RTP is designed to allow an application to scale automatically over session sizes ranging from…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.2.1_Maintaining_the_Number_of_Session_Members.md` | sec `6.2.1` | intent `Maintaining the Number of Session Members` | use `Calculation of the RTCP packet interval depends upon an estimate of the number of sites…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.3_RTCP_Packet_Send_and_Receive_Rules.md` | sec `6.3` | intent `RTCP Packet Send and Receive Rules` | use `The rules for how to send, and what to do when receiving an RTCP packet are outlined here. An…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.3.1_Computing_the_RTCP_Transmission_Interval.md` | sec `6.3.1` | intent `Computing the RTCP Transmission Interval` | use `To maintain scalability, the average interval between packets from a session participant should…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.3.2_Initialization.md` | sec `6.3.2` | intent `Initialization` | use `Upon joining the session, the participant initializes tp to 0, tc to 0, senders to 0, pmembers…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.3.3_Receiving_an_RTP_or_Non_BYE_RTCP_Packet.md` | sec `6.3.3` | intent `Receiving an RTP or Non-BYE RTCP Packet` | use `When an RTP or RTCP packet is received from a participant whose SSRC is not in the member…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.3.4_Receiving_an_RTCP_BYE_Packet.md` | sec `6.3.4` | intent `Receiving an RTCP BYE Packet` | use `Except as described in Section 6.3.7 for the case when an RTCP BYE is to be transmitted, if the…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.3.5_Timing_Out_an_SSRC.md` | sec `6.3.5` | intent `Timing Out an SSRC` | use `At occasional intervals, the participant MUST check to see if any of the other participants…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.3.6_Expiration_of_Transmission_Timer.md` | sec `6.3.6` | intent `Expiration of Transmission Timer` | use `When the packet transmission timer expires, the participant performs the following operations:` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.3.7_Transmitting_a_BYE_Packet.md` | sec `6.3.7` | intent `Transmitting a BYE Packet` | use `When a participant wishes to leave a session, a BYE packet is transmitted to inform the other…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.3.8_Updating_we_sent.md` | sec `6.3.8` | intent `Updating we_sent` | use `The variable we_sent contains true if the participant has sent an RTP packet recently, false…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.3.9_Allocation_of_Source_Description_Bandwidth.md` | sec `6.3.9` | intent `Allocation of Source Description Bandwidth` | use `This specification defines several source description (SDES) items in addition to the mandatory…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.4_Sender_and_Receiver_Reports.md` | sec `6.4` | intent `Sender and Receiver Reports` | use `RTP receivers provide reception quality feedback using RTCP report packets which may take one…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.4.1_SR_Sender_Report_RTCP_Packet.md` | sec `6.4.1` | intent `SR: Sender Report RTCP Packet` | use `0 1 2 3 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.4.2_RR_Receiver_Report_RTCP_Packet.md` | sec `6.4.2` | intent `RR: Receiver Report RTCP Packet` | use `0 1 2 3 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.4.3_Extending_the_Sender_and_Receiver_Reports.md` | sec `6.4.3` | intent `Extending the Sender and Receiver Reports` | use `A profile SHOULD define profile-specific extensions to the sender report and receiver report if…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.4.4_Analyzing_Sender_and_Receiver_Reports.md` | sec `6.4.4` | intent `Analyzing Sender and Receiver Reports` | use `It is expected that reception quality feedback will be useful not only for the sender but also…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.5_SDES_Source_Description_RTCP_Packet.md` | sec `6.5` | intent `SDES: Source Description RTCP Packet` | use `0 1 2 3 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.5.1_CNAME_Canonical_End_Point_Identifier_SDES_Item.md` | sec `6.5.1` | intent `CNAME: Canonical End-Point Identifier…` | use `0 1 2 3 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.5.2_NAME_User_Name_SDES_Item.md` | sec `6.5.2` | intent `NAME: User Name SDES Item` | use `0 1 2 3 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.5.3_EMAIL_Electronic_Mail_Address_SDES_Item.md` | sec `6.5.3` | intent `EMAIL: Electronic Mail Address SDES Item` | use `0 1 2 3 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.5.4_PHONE_Phone_Number_SDES_Item.md` | sec `6.5.4` | intent `PHONE: Phone Number SDES Item` | use `0 1 2 3 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.5.5_LOC_Geographic_User_Location_SDES_Item.md` | sec `6.5.5` | intent `LOC: Geographic User Location SDES Item` | use `0 1 2 3 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.5.6_TOOL_Application_or_Tool_Name_SDES_Item.md` | sec `6.5.6` | intent `TOOL: Application or Tool Name SDES Item` | use `0 1 2 3 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.5.7_NOTE_Notice_Status_SDES_Item.md` | sec `6.5.7` | intent `NOTE: Notice/Status SDES Item` | use `0 1 2 3 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.5.8_PRIV_Private_Extensions_SDES_Item.md` | sec `6.5.8` | intent `PRIV: Private Extensions SDES Item` | use `0 1 2 3 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.6_BYE_Goodbye_RTCP_Packet.md` | sec `6.6` | intent `BYE: Goodbye RTCP Packet` | use `0 1 2 3 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `6.7_APP_Application_Defined_RTCP_Packet.md` | sec `6.7` | intent `APP: Application-Defined RTCP Packet` | use `0 1 2 3 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1…` | ref `6_RTP_Control_Protocol__RTCP.md`
- `7.1_General_Description.md` | sec `7.1` | intent `General Description` | use `An RTP translator/mixer connects two or more transport-level "clouds". Typically, each cloud is…` | ref `7_RTP_Translators_and_Mixers.md`
- `7.2_RTCP_Processing_in_Translators.md` | sec `7.2` | intent `RTCP Processing in Translators` | use `In addition to forwarding data packets, perhaps modified, translators and mixers MUST also…` | ref `7_RTP_Translators_and_Mixers.md`
- `7.3_RTCP_Processing_in_Mixers.md` | sec `7.3` | intent `RTCP Processing in Mixers` | use `Since a mixer generates a new data stream of its own, it does not pass through SR or RR packets…` | ref `7_RTP_Translators_and_Mixers.md`
- `7.4_Cascaded_Mixers.md` | sec `7.4` | intent `Cascaded Mixers` | use `An RTP session may involve a collection of mixers and translators as shown in Fig. 3. If two…` | ref `7_RTP_Translators_and_Mixers.md`
- `8.1_Probability_of_Collision.md` | sec `8.1` | intent `Probability of Collision` | use `Since the identifiers are chosen randomly, it is possible that two or more sources will choose…` | ref `8_SSRC_Identifier_Allocation_and_Use.md`
- `8.2_Collision_Resolution_and_Loop_Detection.md` | sec `8.2` | intent `Collision Resolution and Loop Detection` | use `Although the probability of SSRC identifier collision is low, all RTP implementations MUST be…` | ref `8_SSRC_Identifier_Allocation_and_Use.md`
- `8.3_Use_with_Layered_Encodings.md` | sec `8.3` | intent `Use with Layered Encodings` | use `For layered encodings transmitted on separate RTP sessions (see Section 2.4), a single SSRC…` | ref `8_SSRC_Identifier_Allocation_and_Use.md`
- `9.1_Confidentiality.md` | sec `9.1` | intent `Confidentiality` | use `Confidentiality means that only the intended receiver(s) can decode the received packets; for…` | ref `9_Security.md`
- `9.2_Authentication_and_Message_Integrity.md` | sec `9.2` | intent `Authentication and Message Integrity` | use `Authentication and message integrity services are not defined at the RTP level since these…` | ref `9_Security.md`
- `12.1_RTCP_Packet_Types.md` | sec `12.1` | intent `RTCP Packet Types` | use `abbrev. name value SR sender report 200 RR receiver report 201 SDES source description 202 BYE…` | ref `12_Summary_of_Protocol_Constants.md`
- `12.2_SDES_Types.md` | sec `12.2` | intent `SDES Types` | use `abbrev. name value END end of SDES list 0 CNAME canonical name 1 NAME user name 2 EMAIL user's…` | ref `12_Summary_of_Protocol_Constants.md`
- `A.1_RTP_Data_Header_Validity_Checks.md` | sec `A.1` | intent `RTP Data Header Validity Checks` | use `An RTP receiver should check the validity of the RTP header on incoming packets since they…` | ref `Appendix_A_Algorithms.md`
- `A.2_RTCP_Header_Validity_Checks.md` | sec `A.2` | intent `RTCP Header Validity Checks` | use `The following checks should be applied to RTCP packets.` | ref `Appendix_A_Algorithms.md`
- `A.3_Determining_Number_of_Packets_Expected_and_Lost.md` | sec `A.3` | intent `Determining Number of Packets Expected…` | use `In order to compute packet loss rates, the number of RTP packets expected and actually received…` | ref `Appendix_A_Algorithms.md`
- `A.4_Generating_RTCP_SDES_Packets.md` | sec `A.4` | intent `Generating RTCP SDES Packets` | use `This function builds one SDES chunk into buffer b composed of argc items supplied in arrays…` | ref `Appendix_A_Algorithms.md`
- `A.5_Parsing_RTCP_SDES_Packets.md` | sec `A.5` | intent `Parsing RTCP SDES Packets` | use `This function parses an SDES packet, calling functions find_member() to find a pointer to the…` | ref `Appendix_A_Algorithms.md`
- `A.6_Generating_a_Random_32_bit_Identifier.md` | sec `A.6` | intent `Generating a Random 32-bit Identifier` | use `The following subroutine generates a random 32-bit identifier using the MD5 routines published…` | ref `Appendix_A_Algorithms.md`
- `A.7_Computing_the_RTCP_Transmission_Interval.md` | sec `A.7` | intent `Computing the RTCP Transmission Interval` | use `The following functions implement the RTCP transmission and reception rules described in…` | ref `Appendix_A_Algorithms.md`
- `A.8_Estimating_the_Interarrival_Jitter.md` | sec `A.8` | intent `Estimating the Interarrival Jitter` | use `The code fragments below implement the algorithm given in Section 6.4.1 for calculating an…` | ref `Appendix_A_Algorithms.md`
