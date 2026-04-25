## 6.  Multi-Party RTP Sessions

Since DTLS is a point-to-point protocol, DTLS-SRTP is intended only
to protect unicast RTP sessions.  This does not preclude its use with
RTP mixers.  For example, a conference bridge may use DTLS-SRTP to
secure the communication to and from each of the participants in a
conference.  However, because each flow between an endpoint and a
mixer has its own key, the mixer has to decrypt and then reencrypt
the traffic for each recipient.

A future specification may describe methods for sharing a single key
between multiple DTLS-SRTP associations thus allowing conferencing
systems to avoid the decrypt/reencrypt stage.  However, any system in
which the media is modified (e.g., for level balancing or
transcoding) will generally need to be performed on the plaintext and
will certainly break the authentication tag, and therefore will
require a decrypt/reencrypt stage.