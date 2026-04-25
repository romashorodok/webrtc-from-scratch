# RFC 8489: Session Traversal Utilities for NAT STUN

Source: `../rfc8489_Session_Traversal_Utilities_for_NAT_STUN_.md`

Use this file first. It is the compact map for the section files in this RFC.

## Data
- `file`: section file name
- `sec`: RFC section number
- `intent`: short section purpose
- `use`: one short cue or example
- `ref`: parent RFC source file

## Sections
- `6.1_Forming_a_Request_or_an_Indication.md` | sec `6.1` | intent `Forming a Request or an Indication` | use `When formulating a request or indication message, the agent MUST follow the rules in Section 5…` | ref `6_Base_Protocol_Procedures.md`
- `6.2_Sending_the_Request_or_Indication.md` | sec `6.2` | intent `Sending the Request or Indication` | use `The agent then sends the request or indication. This document specifies how to send STUN…` | ref `6_Base_Protocol_Procedures.md`
- `6.2.1_Sending_over_UDP_or_DTLS_over_UDP.md` | sec `6.2.1` | intent `Sending over UDP or DTLS-over-UDP` | use `When running STUN over UDP or STUN over DTLS-over-UDP [RFC7350], it is possible that the STUN…` | ref `6_Base_Protocol_Procedures.md`
- `6.2.2_Sending_over_TCP_or_TLS_over_TCP.md` | sec `6.2.2` | intent `Sending over TCP or TLS-over-TCP` | use `For TCP and TLS-over-TCP [RFC8446], the client opens a TCP connection to the server.` | ref `6_Base_Protocol_Procedures.md`
- `6.2.3_Sending_over_TLS_over_TCP_or_DTLS_over_UDP.md` | sec `6.2.3` | intent `Sending over TLS-over-TCP or DTLS-over-UDP` | use `When STUN is run by itself over TLS-over-TCP or DTLS-over-UDP, the…` | ref `6_Base_Protocol_Procedures.md`
- `6.3_Receiving_a_STUN_Message.md` | sec `6.3` | intent `Receiving a STUN Message` | use `This section specifies the processing of a STUN message. The processing specified here is for…` | ref `6_Base_Protocol_Procedures.md`
- `6.3.1_Processing_a_Request.md` | sec `6.3.1` | intent `Processing a Request` | use `If the request contains one or more unknown comprehension-required attributes, the server…` | ref `6_Base_Protocol_Procedures.md`
- `6.3.2_Processing_an_Indication.md` | sec `6.3.2` | intent `Processing an Indication` | use `If the indication contains unknown comprehension-required attributes, the indication is…` | ref `6_Base_Protocol_Procedures.md`
- `6.3.3_Processing_a_Success_Response.md` | sec `6.3.3` | intent `Processing a Success Response` | use `If the success response contains unknown comprehension-required attributes, the response is…` | ref `6_Base_Protocol_Procedures.md`
- `6.3.4_Processing_an_Error_Response.md` | sec `6.3.4` | intent `Processing an Error Response` | use `If the error response contains unknown comprehension-required attributes, or if the error…` | ref `6_Base_Protocol_Procedures.md`
- `8.1_STUN_URI_Scheme_Semantics.md` | sec `8.1` | intent `STUN URI Scheme Semantics` | use `If the <host> part of a "stun" URI contains an IP address, then this IP address is used…` | ref `8_DNS_Discovery_of_a_Server.md`
- `9.1_Short_Term_Credential_Mechanism.md` | sec `9.1` | intent `Short-Term Credential Mechanism` | use `The short-term credential mechanism assumes that, prior to the STUN transaction, the client and…` | ref `9_Authentication_and_Message-Integrity_Mechanisms.md`
- `9.1.1_HMAC_Key.md` | sec `9.1.1` | intent `HMAC Key` | use `For short-term credentials, the Hash-Based Message Authentication Code (HMAC) key is defined as…` | ref `9_Authentication_and_Message-Integrity_Mechanisms.md`
- `9.1.2_Forming_a_Request_or_Indication.md` | sec `9.1.2` | intent `Forming a Request or Indication` | use `For a request or indication message, the agent MUST include the USERNAME, MESSAGE-INTEGRITY-…` | ref `9_Authentication_and_Message-Integrity_Mechanisms.md`
- `9.1.3_Receiving_a_Request_or_Indication.md` | sec `9.1.3` | intent `Receiving a Request or Indication` | use `After the agent has done the basic processing of a message, the agent performs the checks…` | ref `9_Authentication_and_Message-Integrity_Mechanisms.md`
- `9.1.4_Receiving_a_Response.md` | sec `9.1.4` | intent `Receiving a Response` | use `The client looks for the MESSAGE-INTEGRITY or the MESSAGE-INTEGRITY- SHA256 attribute in the…` | ref `9_Authentication_and_Message-Integrity_Mechanisms.md`
- `9.1.5_Sending_Subsequent_Requests.md` | sec `9.1.5` | intent `Sending Subsequent Requests` | use `A client sending subsequent requests to the same server MUST send only the MESSAGE-INTEGRITY-…` | ref `9_Authentication_and_Message-Integrity_Mechanisms.md`
- `9.2_Long_Term_Credential_Mechanism.md` | sec `9.2` | intent `Long-Term Credential Mechanism` | use `The long-term credential mechanism relies on a long-term credential, in the form of a username…` | ref `9_Authentication_and_Message-Integrity_Mechanisms.md`
- `9.2.1_Bid_Down_Attack_Prevention.md` | sec `9.2.1` | intent `Bid-Down Attack Prevention` | use `This document introduces two new security features that provide the ability to choose the…` | ref `9_Authentication_and_Message-Integrity_Mechanisms.md`
- `9.2.2_HMAC_Key.md` | sec `9.2.2` | intent `HMAC Key` | use `For long-term credentials that do not use a different algorithm, as specified by the PASSWORD-…` | ref `9_Authentication_and_Message-Integrity_Mechanisms.md`
- `9.2.3_Forming_a_Request.md` | sec `9.2.3` | intent `Forming a Request` | use `The first request from the client to the server (as identified by hostname if the DNS…` | ref `9_Authentication_and_Message-Integrity_Mechanisms.md`
- `9.2.4_Receiving_a_Request.md` | sec `9.2.4` | intent `Receiving a Request` | use `After the server has done the basic processing of a request, it performs the checks listed…` | ref `9_Authentication_and_Message-Integrity_Mechanisms.md`
- `9.2.5_Receiving_a_Response.md` | sec `9.2.5` | intent `Receiving a Response` | use `If the response is an error response with an error code of 401 (Unauthenticated) or 438 (Stale…` | ref `9_Authentication_and_Message-Integrity_Mechanisms.md`
- `14.1_MAPPED_ADDRESS.md` | sec `14.1` | intent `MAPPED-ADDRESS` | use `The MAPPED-ADDRESS attribute indicates a reflexive transport address of the client. It consists…` | ref `14_STUN_Attributes.md`
- `14.2_XOR_MAPPED_ADDRESS.md` | sec `14.2` | intent `XOR-MAPPED-ADDRESS` | use `The XOR-MAPPED-ADDRESS attribute is identical to the MAPPED-ADDRESS attribute, except that the…` | ref `14_STUN_Attributes.md`
- `14.3_USERNAME.md` | sec `14.3` | intent `USERNAME` | use `The USERNAME attribute is used for message integrity. It identifies the username and password…` | ref `14_STUN_Attributes.md`
- `14.4_USERHASH.md` | sec `14.4` | intent `USERHASH` | use `The USERHASH attribute is used as a replacement for the USERNAME attribute when username…` | ref `14_STUN_Attributes.md`
- `14.5_MESSAGE_INTEGRITY.md` | sec `14.5` | intent `MESSAGE-INTEGRITY` | use `The MESSAGE-INTEGRITY attribute contains an HMAC-SHA1 [RFC2104] of the STUN message. The…` | ref `14_STUN_Attributes.md`
- `14.6_MESSAGE_INTEGRITY_SHA256.md` | sec `14.6` | intent `MESSAGE-INTEGRITY-SHA256` | use `The MESSAGE-INTEGRITY-SHA256 attribute contains an HMAC-SHA256 [RFC2104] of the STUN message.…` | ref `14_STUN_Attributes.md`
- `14.7_FINGERPRINT.md` | sec `14.7` | intent `FINGERPRINT` | use `The FINGERPRINT attribute MAY be present in all STUN messages.` | ref `14_STUN_Attributes.md`
- `14.8_ERROR_CODE.md` | sec `14.8` | intent `ERROR-CODE` | use `The ERROR-CODE attribute is used in error response messages. It contains a numeric error code…` | ref `14_STUN_Attributes.md`
- `14.9_REALM.md` | sec `14.9` | intent `REALM` | use `The REALM attribute may be present in requests and responses. It contains text that meets the…` | ref `14_STUN_Attributes.md`
- `14.10_NONCE.md` | sec `14.10` | intent `NONCE` | use `The NONCE attribute may be present in requests and responses. It contains a sequence of qdtext…` | ref `14_STUN_Attributes.md`
- `14.11_PASSWORD_ALGORITHMS.md` | sec `14.11` | intent `PASSWORD-ALGORITHMS` | use `The PASSWORD-ALGORITHMS attribute may be present in requests and responses. It contains the…` | ref `14_STUN_Attributes.md`
- `14.12_PASSWORD_ALGORITHM.md` | sec `14.12` | intent `PASSWORD-ALGORITHM` | use `The PASSWORD-ALGORITHM attribute is present only in requests. It contains the algorithm that…` | ref `14_STUN_Attributes.md`
- `14.13_UNKNOWN_ATTRIBUTES.md` | sec `14.13` | intent `UNKNOWN-ATTRIBUTES` | use `The UNKNOWN-ATTRIBUTES attribute is present only in an error response when the response code in…` | ref `14_STUN_Attributes.md`
- `14.14_SOFTWARE.md` | sec `14.14` | intent `SOFTWARE` | use `The SOFTWARE attribute contains a textual description of the software being used by the agent…` | ref `14_STUN_Attributes.md`
- `14.15_ALTERNATE_SERVER.md` | sec `14.15` | intent `ALTERNATE-SERVER` | use `The alternate server represents an alternate transport address identifying a different STUN…` | ref `14_STUN_Attributes.md`
- `14.16_ALTERNATE_DOMAIN.md` | sec `14.16` | intent `ALTERNATE-DOMAIN` | use `The alternate domain represents the domain name that is used to verify the IP address in the…` | ref `14_STUN_Attributes.md`
- `16.1_Attacks_against_the_Protocol.md` | sec `16.1` | intent `Attacks against the Protocol` | use `Attacks against the Protocol` | ref `16_Security_Considerations.md`
- `16.1.1_Outside_Attacks.md` | sec `16.1.1` | intent `Outside Attacks` | use `An attacker can try to modify STUN messages in transit, in order to cause a failure in STUN…` | ref `16_Security_Considerations.md`
- `16.1.2_Inside_Attacks.md` | sec `16.1.2` | intent `Inside Attacks` | use `A rogue client may try to launch a DoS attack against a server by sending it a large number of…` | ref `16_Security_Considerations.md`
- `16.1.3_Bid_Down_Attacks.md` | sec `16.1.3` | intent `Bid-Down Attacks` | use `This document adds the possibility of selecting different algorithms to protect the…` | ref `16_Security_Considerations.md`
- `16.2_Attacks_Affecting_the_Usage.md` | sec `16.2` | intent `Attacks Affecting the Usage` | use `This section lists attacks that might be launched against a usage of STUN. Each STUN Usage must…` | ref `16_Security_Considerations.md`
- `16.2.1_Attack_I_Distributed_DoS_DDoS_against_a_Target.md` | sec `16.2.1` | intent `Attack I: Distributed DoS (DDoS) against…` | use `In this attack, the attacker provides one or more clients with the same faked reflexive address…` | ref `16_Security_Considerations.md`
- `16.2.2_Attack_II_Silencing_a_Client.md` | sec `16.2.2` | intent `Attack II: Silencing a Client` | use `In this attack, the attacker provides a STUN client with a faked reflexive address. The…` | ref `16_Security_Considerations.md`
- `16.2.3_Attack_III_Assuming_the_Identity_of_a_Client.md` | sec `16.2.3` | intent `Attack III: Assuming the Identity of a…` | use `This attack is similar to attack II. However, the faked reflexive address points to the…` | ref `16_Security_Considerations.md`
- `16.2.4_Attack_IV_Eavesdropping.md` | sec `16.2.4` | intent `Attack IV: Eavesdropping` | use `In this attack, the attacker forces the client to use a reflexive address that routes to…` | ref `16_Security_Considerations.md`
- `16.3_Hash_Agility_Plan.md` | sec `16.3` | intent `Hash Agility Plan` | use `This specification uses HMAC-SHA256 for computation of the message integrity, sometimes in…` | ref `16_Security_Considerations.md`
- `18.1_STUN_Security_Features_Registry.md` | sec `18.1` | intent `STUN Security Features Registry` | use `A STUN Security Feature set defines 24 bits as flags.` | ref `18_IANA_Considerations.md`
- `18.2_STUN_Methods_Registry.md` | sec `18.2` | intent `STUN Methods Registry` | use `A STUN method is a hex number in the range 0x000-0x0FF. The encoding of a STUN method into a…` | ref `18_IANA_Considerations.md`
- `18.3_STUN_Attributes_Registry.md` | sec `18.3` | intent `STUN Attributes Registry` | use `A STUN attribute type is a hex number in the range 0x0000-0xFFFF. STUN attribute types in the…` | ref `18_IANA_Considerations.md`
- `18.3.1_Updated_Attributes.md` | sec `18.3.1` | intent `Updated Attributes` | use `IANA has updated the names for attributes 0x0002, 0x0004, 0x0005, 0x0007, and 0x000B as well as…` | ref `18_IANA_Considerations.md`
- `18.3.2_New_Attributes.md` | sec `18.3.2` | intent `New Attributes` | use `IANA has added the following attribute to the "STUN Attributes" registry:` | ref `18_IANA_Considerations.md`
- `18.4_STUN_Error_Codes_Registry.md` | sec `18.4` | intent `STUN Error Codes Registry` | use `A STUN error code is a number in the range 0-699. STUN error codes are accompanied by a textual…` | ref `18_IANA_Considerations.md`
- `18.5_STUN_Password_Algorithms_Registry.md` | sec `18.5` | intent `STUN Password Algorithms Registry` | use `IANA has created a new registry titled "STUN Password Algorithms".` | ref `18_IANA_Considerations.md`
- `18.5.1_Password_Algorithms.md` | sec `18.5.1` | intent `Password Algorithms` | use `#### 18.5.1.1. MD5` | ref `18_IANA_Considerations.md`
- `18.6_STUN_UDP_and_TCP_Port_Numbers.md` | sec `18.6` | intent `STUN UDP and TCP Port Numbers` | use `IANA has updated the reference from RFC 5389 to RFC 8489 for the following ports in the…` | ref `18_IANA_Considerations.md`
- `B.1_Sample_Request_with_Long_Term_Authentication_with_MESSAGE_INTEGRITY_SHA256_and_USERHASH.md` | sec `B.1` | intent `Sample Request with Long-Term…` | use `This request uses the following parameters:` | ref `Appendix_B_Test_Vectors.md`
