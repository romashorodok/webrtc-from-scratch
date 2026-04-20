14. Security Considerations

   RTP suffers from the same security liabilities as the underlying
   protocols.  For example, an impostor can fake source or destination
   network addresses, or change the header or payload.  Within RTCP, the
   CNAME and NAME information may be used to impersonate another
   participant.  In addition, RTP may be sent via IP multicast, which
   provides no direct means for a sender to know all the receivers of
   the data sent and therefore no measure of privacy.  Rightly or not,
   users may be more sensitive to privacy concerns with audio and video
   communication than they have been with more traditional forms of
   network communication [33].  Therefore, the use of security
   mechanisms with RTP is important.  These mechanisms are discussed in
   Section 9.

   RTP-level translators or mixers may be used to allow RTP traffic to
   reach hosts behind firewalls.  Appropriate firewall security
   principles and practices, which are beyond the scope of this
   document, should be followed in the design and installation of these
   devices and in the admission of RTP applications for use behind the
   firewall.

15. IANA Considerations

   Additional RTCP packet types and SDES item types may be registered
   through the Internet Assigned Numbers Authority (IANA).  Since these
   number spaces are small, allowing unconstrained registration of new
   values would not be prudent.  To facilitate review of requests and to
   promote shared use of new types among multiple applications, requests
   for registration of new values must be documented in an RFC or other
   permanent and readily available reference such as the product of
   another cooperative standards body (e.g., ITU-T).  Other requests may
   also be accepted, under the advice of a "designated expert."


   (Contact the IANA for the contact information of the current expert.)

   RTP profile specifications SHOULD register with IANA a name for the
   profile in the form "RTP/xxx", where xxx is a short abbreviation of
   the profile title.  These names are for use by higher-level control
   protocols, such as the Session Description Protocol (SDP), RFC 2327
   [15], to refer to transport methods.
