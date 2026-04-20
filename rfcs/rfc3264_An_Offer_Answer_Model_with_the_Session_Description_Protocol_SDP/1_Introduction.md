#  1 Introduction

The Session Description Protocol (SDP) [1] was originally conceived
as a way to describe multicast sessions carried on the Mbone.  The
Session Announcement Protocol (SAP) [6] was devised as a multicast
mechanism to carry SDP messages.  Although the SDP specification
allows for unicast operation, it is not complete.  Unlike multicast,
where there is a global view of the session that is used by all
participants, unicast sessions involve two participants, and a
complete view of the session requires information from both
participants, and agreement on parameters between them.

As an example, a multicast session requires conveying a single
multicast address for a particular media stream.  However, for a
unicast session, two addresses are needed - one for each participant.
As another example, a multicast session requires an indication of
which codecs will be used in the session.  However, for unicast, the
set of codecs needs to be determined by finding an overlap in the set
supported by each participant.

As a result, even though SDP has the expressiveness to describe
unicast sessions, it is missing the semantics and operational details
of how it is actually done.  In this document, we remedy that by
defining a simple offer/answer model based on SDP.  In this model,
one participant in the session generates an SDP message that
constitutes the offer - the set of media streams and codecs the
offerer wishes to use, along with the IP addresses and ports the
offerer would like to use to receive the media.  The offer is
conveyed to the other participant, called the answerer.  The answerer
generates an answer, which is an SDP message that responds to the
offer provided by the offerer.  The answer has a matching media
stream for each stream in the offer, indicating whether the stream is
accepted or not, along with the codecs that will be used and the IP
addresses and ports that the answerer wants to use to receive media.

It is also possible for a multicast session to work similar to a
unicast one; its parameters are negotiated between a pair of users as
in the unicast case, but both sides send packets to the same
multicast address, rather than unicast ones.  This document also
discusses the application of the offer/answer model to multicast
streams.

We also define guidelines for how the offer/answer model is used to
update a session after an initial offer/answer exchange.

The means by which the offers and answers are conveyed are outside
the scope of this document.  The offer/answer model defined here is
the mandatory baseline mechanism used by the Session Initiation
Protocol (SIP) [7].