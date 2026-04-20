# 5.  Security Considerations

This document describes a variant of TLS 1.2; therefore, most of the
security considerations are the same as those of TLS 1.2 [TLS12],
described in Appendices D, E, and F.

The primary additional security consideration raised by DTLS is that
of denial of service.  DTLS includes a cookie exchange designed to
protect against denial of service.  However, implementations that do
not use this cookie exchange are still vulnerable to DoS.  In
particular, DTLS servers that do not use the cookie exchange may be
used as attack amplifiers even if they themselves are not
experiencing DoS.  Therefore, DTLS servers SHOULD use the cookie
exchange unless there is good reason to believe that amplification is
not a threat in their environment.  Clients MUST be prepared to do a
cookie exchange with every handshake.

Unlike TLS implementations, DTLS implementations SHOULD NOT respond
to invalid records by terminating the connection.  See Section
4.1.2.7 for details on this.
