## B.6.  Why Are Keepalives Needed?

Once data begins flowing on a candidate pair, it is still necessary
to keep the bindings alive at intermediate NATs for the duration of
the session.  Normally, the data stream packets themselves (e.g.,
RTP) meet this objective.  However, several cases merit further
discussion.  Firstly, in some RTP usages, such as SIP, the data
streams can be "put on hold".  This is accomplished by using the SDP
"sendonly" or "inactive" attributes, as defined in RFC 3264
[RFC3264].  RFC 3264 directs implementations to cease transmission of
data in these cases.  However, doing so may cause NAT bindings to
time out, and data won't be able to come off hold.

Secondly, some RTP payload formats, such as the payload format for
text conversation [RFC4103], may send packets so infrequently that
the interval exceeds the NAT binding timeouts.

Thirdly, if silence suppression is in use, long periods of silence
may cause data transmission to cease sufficiently long for NAT
bindings to time out.

For these reasons, the data packets themselves cannot be relied upon.
ICE defines a simple periodic keepalive utilizing STUN Binding
Indications.  This makes its bandwidth requirements highly
predictable and thus amenable to QoS reservations.

