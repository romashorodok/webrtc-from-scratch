# 17.  Operational Considerations

This section discusses issues relevant to operators operating
networks where ICE will be used by endpoints.

## 17.1.  NAT and Firewall Types

ICE was designed to work with existing NAT and firewall equipment.
Consequently, it is not necessary to replace or reconfigure existing
firewall and NAT equipment in order to facilitate deployment of ICE.
Indeed, ICE was developed to be deployed in environments where the
Voice over IP (VoIP) operator has no control over the IP network
infrastructure, including firewalls and NATs.

That said, ICE works best in environments where the NAT devices are
"behave" compliant, meeting the recommendations defined in [RFC4787]
and [RFC5382].  In networks with behave-compliant NAT, ICE will work
without the need for a TURN server, thus improving voice quality,
decreasing call setup times, and reducing the bandwidth demands on
the network operator.

## 17.2.  Bandwidth Requirements

Deployment of ICE can have several interactions with available
network capacity that operators need to take into consideration.

### 17.2.1.  STUN and TURN Server-Capacity Planning

First and foremost, ICE makes use of TURN and STUN servers, which
would typically be located in data centers.  The STUN servers require
relatively little bandwidth.  For each component of each data stream,
there will be one or more STUN transactions from each client to the
STUN server.  In a basic voice-only IPv4 VoIP deployment, there will
be four transactions per call (one for RTP and one for RTCP, for both
the caller and callee).  Each transaction is a single request and a
single response, the former being 20 bytes long, and the latter, 28.



Consequently, if a system has N users, and each makes four calls in a
busy hour, this would require N*1.7bps.  For one million users, this
is 1.7 Mbps, a very small number (relatively speaking).

TURN traffic is more substantial.  The TURN server will see traffic
volume equal to the STUN volume (indeed, if TURN servers are
deployed, there is no need for a separate STUN server), in addition
to the traffic for the actual data.  The amount of calls requiring
TURN for data relay is highly dependent on network topologies, and
can and will vary over time.  In a network with 100% behave-compliant
NATs, it is exactly zero.

The planning considerations above become more significant in
multimedia scenarios (e.g., audio and video conferences) and when the
numbers of participants in a session grow.

### 17.2.2.  Gathering and Connectivity Checks

The process of gathering candidates and performing connectivity
checks can be bandwidth intensive.  ICE has been designed to pace
both of these processes.  The gathering and connectivity-check phases
are meant to generate traffic at roughly the same bandwidth as the
data traffic itself will consume once the ICE process concludes.
This was done to ensure that if a network is designed to support
communication traffic of a certain type (voice, video, or just text),
it will have sufficient capacity to support the ICE checks for that
data.  Once ICE has concluded, the subsequent ICE keepalives will
later cause a marginal increase in the total bandwidth utilization;
however, this will typically be an extremely small increase.

Congestion due to the gathering and check phases has proven to be a
problem in deployments that did not utilize pacing.  Typically,
access links became congested as the endpoints flooded the network
with checks as fast as they could send them.  Consequently, network
operators need to ensure that their ICE implementations support the
pacing feature.  Though this pacing does increase call setup times,
it makes ICE network friendly and easier to deploy.

### 17.2.3.  Keepalives

STUN keepalives (in the form of STUN Binding Indications) are sent in
the middle of a data session.  However, they are sent only in the
absence of actual data traffic.  In deployments with continuous media
and without utilizing Voice Activity Detection (VAD), or deployments
where VAD is utilized together with short interval (max 1 second)
comfort noise, the keepalives are never used and there is no increase
in bandwidth usage.  When VAD is being used without comfort noise,
keepalives will be sent during silence periods.  This involves a
single packet every 15-20 seconds, far less than the packet every
20-30 ms that is sent when there is voice.  Therefore, keepalives do
not have any real impact on capacity planning.

## 17.3.  ICE and ICE-Lite

Deployments utilizing a mix of ICE and ICE-lite interoperate with
each other.  They have been explicitly designed to do so.

However, ICE-lite can only be deployed in limited use cases.  Those
cases, and the caveats involved in doing so, are documented in
Appendix A.

## 17.4.  Troubleshooting and Performance Management

ICE utilizes end-to-end connectivity checks and places much of the
processing in the endpoints.  This introduces a challenge to the
network operator -- how can they troubleshoot ICE deployments?  How
can they know how ICE is performing?

ICE has built-in features to help deal with these problems.
Signaling servers, typically deployed in data centers of the network
operator, will see the contents of the candidate exchanges that
convey the ICE parameters.  These parameters include the type of each
candidate (host, server reflexive, or relayed), along with their
related addresses.  Once ICE processing has completed, an updated
candidate exchange takes place, signaling the selected address (and
its type).  This updated signaling is performed exactly for the
purposes of educating network equipment (such as a diagnostic tool
attached to a signaling) about the results of ICE processing.

As a consequence, through the logs generated by a signaling server, a
network operator can observe what types of candidates are being used
for each call and what addresses were selected by ICE.  This is the
primary information that helps evaluate how ICE is performing.

## 17.5.  Endpoint Configuration

ICE relies on several pieces of data being configured into the
endpoints.  This configuration data includes timers, credentials for
TURN servers, and hostnames for STUN and TURN servers.  ICE itself
does not provide a mechanism for this configuration.  Instead, it is
assumed that this information is attached to whatever mechanism is
used to configure all of the other parameters in the endpoint.  For
SIP phones, standard solutions such as the configuration framework
[RFC6080] have been defined.

