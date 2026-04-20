# 2.  Overview of Operation

   This section is descriptive only.

                           /-----\
                         // STUN  \\
                        |   Server  |
                         \\       //
                           \-----/




                      +--------------+             Public Internet
      ................|     NAT 2    |.......................
                      +--------------+



                      +--------------+             Private Network 2
      ................|     NAT 1    |.......................
                      +--------------+




                           /-----\
                         // STUN  \\
                        |   Client  |
                         \\       //               Private Network 1
                           \-----/

                 Figure 1: One Possible STUN Configuration

One possible STUN configuration is shown in Figure 1.  In this
configuration, there are two entities (called STUN agents) that
implement the STUN protocol.  The lower agent in the figure is the
client, which is connected to private network 1.  This network
connects to private network 2 through NAT 1.  Private network 2
connects to the public Internet through NAT 2.  The upper agent in
the figure is the server, which resides on the public Internet.

STUN is a client-server protocol.  It supports two types of
transactions.  One is a request/response transaction in which a
client sends a request to a server, and the server returns a
response.  The second is an indication transaction in which either
agent -- client or server -- sends an indication that generates no
response.  Both types of transactions include a transaction ID, which

is a randomly selected 96-bit number.  For request/response
transactions, this transaction ID allows the client to associate the
response with the request that generated it; for indications, the
transaction ID serves as a debugging aid.

All STUN messages start with a fixed header that includes a method, a
class, and the transaction ID.  The method indicates which of the
various requests or indications this is; this specification defines
just one method, Binding, but other methods are expected to be
defined in other documents.  The class indicates whether this is a
request, a success response, an error response, or an indication.
Following the fixed header comes zero or more attributes, which are
Type-Length-Value extensions that convey additional information for
the specific message.

This document defines a single method called "Binding".  The Binding
method can be used either in request/response transactions or in
indication transactions.  When used in request/response transactions,
the Binding method can be used to determine the particular binding a
NAT has allocated to a STUN client.  When used in either request/
response or in indication transactions, the Binding method can also
be used to keep these bindings alive.

In the Binding request/response transaction, a Binding request is
sent from a STUN client to a STUN server.  When the Binding request
arrives at the STUN server, it may have passed through one or more
NATs between the STUN client and the STUN server (in Figure 1, there
are two such NATs).  As the Binding request message passes through a
NAT, the NAT will modify the source transport address (that is, the
source IP address and the source port) of the packet.  As a result,
the source transport address of the request received by the server
will be the public IP address and port created by the NAT closest to
the server.  This is called a "reflexive transport address".  The
STUN server copies that source transport address into an XOR-MAPPED-
ADDRESS attribute in the STUN Binding response and sends the Binding
response back to the STUN client.  As this packet passes back through
a NAT, the NAT will modify the destination transport address in the
IP header, but the transport address in the XOR-MAPPED-ADDRESS
attribute within the body of the STUN response will remain untouched.
In this way, the client can learn its reflexive transport address
allocated by the outermost NAT with respect to the STUN server.

In some usages, STUN must be multiplexed with other protocols (e.g.,
[RFC8445] and [RFC5626]).  In these usages, there must be a way to
inspect a packet and determine if it is a STUN packet or not.  STUN
provides three fields in the STUN header with fixed values that can


be used for this purpose.  If this is not sufficient, then STUN
packets can also contain a FINGERPRINT value, which can further be
used to distinguish the packets.

STUN defines a set of optional procedures that a usage can decide to
use, called "mechanisms".  These mechanisms include DNS discovery, a
redirection technique to an alternate server, a fingerprint attribute
for demultiplexing, and two authentication and message-integrity
exchanges.  The authentication mechanisms revolve around the use of a
username, password, and message-integrity value.  Two authentication
mechanisms, the long-term credential mechanism and the short-term
credential mechanism, are defined in this specification.  Each usage
specifies the mechanisms allowed with that usage.

In the long-term credential mechanism, the client and server share a
pre-provisioned username and password and perform a digest challenge/
response exchange inspired by the one defined for HTTP [RFC7616] but
differing in details.  In the short-term credential mechanism, the
client and the server exchange a username and password through some
out-of-band method prior to the STUN exchange.  For example, in the
ICE usage [RFC8445], the two endpoints use out-of-band signaling to
exchange a username and password.  These are used to integrity
protect and authenticate the request and response.  There is no
challenge or nonce used.
