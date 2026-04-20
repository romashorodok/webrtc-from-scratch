# 11 Security Considerations

There are numerous attacks possible if an attacker can modify offers
or answers in transit.  Generally, these include diversion of media
streams (enabling eavesdropping), disabling of calls, and injection
of unwanted media streams.  If a passive listener can construct fake
offers, and inject those into an exchange, similar attacks are
possible.  Even if an attacker can simply observe offers and answers,
they can inject media streams into an existing conversation.

Offer/answer relies on transport within an application signaling
protocol, such as SIP.  It also relies on that protocol for security
capabilities.  Because of the attacks described above, that protocol
MUST provide a means for end-to-end authentication and integrity
protection of offers and answers.  It SHOULD offer encryption of
bodies to prevent eavesdropping.  However, media injection attacks
can alternatively be resolved through authenticated media exchange,
and therefore the encryption requirement is a SHOULD instead of a
MUST.

Replay attacks are also problematic.  An attacker can replay an old
offer, perhaps one that had put media on hold, and thus disable media
streams in a conversation.  Therefore, the application protocol MUST
provide a secure way to sequence offers and answers, and to detect
and reject old offers or answers.

SIP [7] meets all of these requirements.