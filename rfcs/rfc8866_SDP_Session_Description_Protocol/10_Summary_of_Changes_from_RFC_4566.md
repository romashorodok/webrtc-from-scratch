# 10. Summary of Changes from RFC 4566
Generally clarified and refined terminology. Aligned terms used in text with the ABNF. The terms <attribute>, <att-field>, and "att-field" are now <attribute-name>. The terms <value> and <att-value> are now <attribute-value>. The term "media" is now <media>.
Identified now-obsolete items: "a=cat:" (Section 6.1), "a=keywds:" (Section 6.2), and "k=" (Section 5.12).
Updated normative and informative references, and added references to additional relevant related RFCs.
Reformatted the SDP Attributes section (Section 6) for readability. The syntax of attribute values is now given in ABNF.
Made mandatory the sending of RTCP with inactive media streams (Section 6.7.4).
Removed the section "Private Sessions". That section dated back to a time when the primary use of SDP was with SAP (Session Announcement Protocol), which has fallen out of use. Now the vast majority of uses of SDP is for establishment of private sessions. The considerations for that are covered in Section 7.
Expanded and clarified the specification of the "a=lang:" (Section 6.12) and "a=sdplang:" (Section 6.11) attributes.
Removed some references to SAP because it is no longer in widespread use.
Changed the way <fmt> values for UDP transport are registered (Section 8.2.3).
Changed the mechanism and documentation required for registering new attributes (Section 8.2.4.1).
Tightened up IANA registration procedures for extensions. Removed phone number and long-form name (Section 8.2).
Expanded the IANA <nettype> registry to identify valid <addrtype> subfields (Section 8.2.6).
Reorganized the several IANA "att-field" registries into a single <attribute-name> registry (Section 8.2.4).
Revised ABNF syntax (Section 9) for clarity and for alignment with text. Backward compatibility is maintained with a few exceptions. Of particular note:

Revised the syntax of time descriptions ("t=", "r=", "z=") to remove ambiguities. Clarified that "z=" only modifies the immediately preceding "r=" lines. Made "z=" without a preceding "r=" a syntax error (Section 5.11). (This is incompatible with certain aberrant usage.)
Updated the "IP6-address" and "IP6-multicast" rules, consistent with the syntax in [RFC3986], mirroring a bug fix made to [RFC3261] by [RFC5954]. Removed rules that were unused as a result of this change.
The "att-field" rule has been renamed "attribute-name" because elsewhere "*-field" always refers to a complete line. However, the rulename "att-field" remains defined as a synonym for backward compatibility with references from other RFCs.
The "att-value" rule has been renamed "attribute-value".
Revised normative statements that were redundant with ABNF syntax, making the text non-normative.
Revised IPv4 unicast and multicast addresses in the example SDP descriptions per [RFC5735] and [RFC5771].
Changed some examples to use IPv6 addresses, and added additional examples using IPv6.
Incorporated case-insensitivity rules from [RFC4855].
Revised sections that incorrectly referenced NTP (Section 5.2, Section 5.9, Section 5.10, and Section 5.11).
Clarified the explanation of the impact and use of the "a=charset:" attribute (Section 6.10).
Revised the description of the "a=type:" attribute to remove implication that it sometimes changes the default media direction to something other than "a=sendrecv" (Section 6.9).
