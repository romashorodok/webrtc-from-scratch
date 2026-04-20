19.  Changes since RFC 5389

   This specification obsoletes [RFC5389].  This specification differs
   from RFC 5389 in the following ways:

   o  Added support for DTLS-over-UDP [RFC6347].

   o  Made clear that the RTO is considered stale if there are no
      transactions with the server.

   o  Aligned the RTO calculation with [RFC6298].

   o  Updated the ciphersuites for TLS.

   o  Added support for STUN URI [RFC7064].

   o  Added support for SHA256 message integrity.

   o  Updated the Preparation, Enforcement, and Comparison of
      Internationalized Strings (PRECIS) support to [RFC8265].

   o  Added protocol and registry to choose the password encryption
      algorithm.

   o  Added support for anonymous username.

   o  Added protocol and registry for preventing bid-down attacks.

   o  Specified that sharing a NONCE is no longer permitted.

   o  Added the possibility of using a domain name in the alternate
      server mechanism.