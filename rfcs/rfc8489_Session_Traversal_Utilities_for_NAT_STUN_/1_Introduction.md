# 1.  Introduction

The protocol defined in this specification, Session Traversal
Utilities for NAT (STUN), provides a tool for dealing with Network
Address Translators (NATs).  It provides a means for an endpoint to
determine the IP address and port allocated by a NAT that corresponds
to its private IP address and port.  It also provides a way for an
endpoint to keep a NAT binding alive.  With some extensions, the
protocol can be used to do connectivity checks between two endpoints
[RFC8445] or to relay packets between two endpoints [RFC5766].

In keeping with its tool nature, this specification defines an
extensible packet format, defines operation over several transport
protocols, and provides for two forms of authentication.

STUN is intended to be used in the context of one or more NAT
traversal solutions.  These solutions are known as "STUN Usages".
Each usage describes how STUN is utilized to achieve the NAT
traversal solution.  Typically, a usage indicates when STUN messages
get sent, which optional attributes to include, what server is used,
and what authentication mechanism is to be used.  Interactive
Connectivity Establishment (ICE) [RFC8445] is one usage of STUN.  SIP
Outbound [RFC5626] is another usage of STUN.  In some cases, a usage
will require extensions to STUN.  A STUN extension can be in the form
of new methods, attributes, or error response codes.  More
information on STUN Usages can be found in Section 13.
