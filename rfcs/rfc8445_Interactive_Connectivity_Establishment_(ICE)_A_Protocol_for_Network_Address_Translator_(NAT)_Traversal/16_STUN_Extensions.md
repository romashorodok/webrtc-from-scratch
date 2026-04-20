# 16.  STUN Extensions

## 16.1.  Attributes

This specification defines four STUN attributes: PRIORITY,
USE-CANDIDATE, ICE-CONTROLLED, and ICE-CONTROLLING.

The PRIORITY attribute indicates the priority that is to be
associated with a peer-reflexive candidate, if one will be discovered
by this check.  It is a 32-bit unsigned integer and has an attribute
value of 0x0024.

The USE-CANDIDATE attribute indicates that the candidate pair
resulting from this check will be used for transmission of data.  The
attribute has no content (the Length field of the attribute is zero);
it serves as a flag.  It has an attribute value of 0x0025.

The ICE-CONTROLLED attribute is present in a Binding request.  The
attribute indicates that the client believes it is currently in the
controlled role.  The content of the attribute is a 64-bit unsigned
integer in network byte order, which contains a random number.  The
number is used for solving role conflicts, when it is referred to as
the "tiebreaker value".  An ICE agent MUST use the same number for
all Binding requests, for all streams, within an ICE session, unless
it has received a 487 response, in which case it MUST change the
number (Section 7.2.5.1).  The agent MAY change the number when an
ICE restart occurs.

The ICE-CONTROLLING attribute is present in a Binding request.  The
attribute indicates that the client believes it is currently in the
controlling role.  The content of the attribute is a 64-bit unsigned
integer in network byte order, which contains a random number.  As
for the ICE-CONTROLLED attribute, the number is used for solving role
conflicts.  An agent MUST use the same number for all Binding
requests, for all streams, within an ICE session, unless it has
received a 487 response, in which case it MUST change the number
(Section 7.2.5.1).  The agent MAY change the number when an ICE
restart occurs.

## 16.2.  New Error-Response Codes

This specification defines a single error-response code:

487 (Role Conflict):  The Binding request contained either the ICE-
    CONTROLLING or ICE-CONTROLLED attribute, indicating an ICE role
    that conflicted with the server.  The remote server compared the
    tiebreaker values of the client and the server and determined that
    the client needs to switch roles.