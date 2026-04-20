# 4.  Definitions

   STUN Agent:  A STUN agent is an entity that implements the STUN
      protocol.  The entity can be either a STUN client or a STUN
      server.

   STUN Client:  A STUN client is an entity that sends STUN requests and
      receives STUN responses and STUN indications.  A STUN client can
      also send indications.  In this specification, the terms "STUN
      client" and "client" are synonymous.

   STUN Server:  A STUN server is an entity that receives STUN requests
      and STUN indications and that sends STUN responses.  A STUN server
      can also send indications.  In this specification, the terms "STUN
      server" and "server" are synonymous.

   Transport Address:  The combination of an IP address and port number
      (such as a UDP or TCP port number).

   Reflexive Transport Address:  A transport address learned by a client
      that identifies that client as seen by another host on an IP
      network, typically a STUN server.  When there is an intervening
      NAT between the client and the other host, the reflexive transport
      address represents the mapped address allocated to the client on
      the public side of the NAT.  Reflexive transport addresses are
      learned from the mapped address attribute (MAPPED-ADDRESS or XOR-
      MAPPED-ADDRESS) in STUN responses.

   Mapped Address:  Same meaning as reflexive address.  This term is
      retained only for historic reasons and due to the naming of the
      MAPPED-ADDRESS and XOR-MAPPED-ADDRESS attributes.

   Long-Term Credential:  A username and associated password that
      represent a shared secret between client and server.  Long-term
      credentials are generally granted to the client when a subscriber
      enrolls in a service and persist until the subscriber leaves the
      service or explicitly changes the credential.

   Long-Term Password:  The password from a long-term credential.

   Short-Term Credential:  A temporary username and associated password
      that represent a shared secret between client and server.  Short-
      term credentials are obtained through some kind of protocol
      mechanism between the client and server, preceding the STUN
      exchange.  A short-term credential has an explicit temporal scope,
      which may be based on a specific amount of time (such as 5
      minutes) or on an event (such as termination of a Session
      Initiation Protocol (SIP) [RFC3261] dialog).  The specific scope
      of a short-term credential is defined by the application usage.

   Short-Term Password:  The password component of a short-term
      credential.

   STUN Indication:  A STUN message that does not receive a response.

   Attribute:  The STUN term for a Type-Length-Value (TLV) object that
      can be added to a STUN message.  Attributes are divided into two
      types: comprehension-required and comprehension-optional.  STUN
      agents can safely ignore comprehension-optional attributes they
      don't understand but cannot successfully process a message if it
      contains comprehension-required attributes that are not
      understood.

   RTO:  Retransmission TimeOut, which defines the initial period of
      time between transmission of a request and the first retransmit of
      that request.
