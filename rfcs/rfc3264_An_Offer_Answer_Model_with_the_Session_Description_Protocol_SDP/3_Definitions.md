# 3 Definitions

The following terms are used throughout this document:

    Agent: An agent is the protocol implementation involved in the
        offer/answer exchange.  There are two agents involved in an
        offer/answer exchange.

    Answer: An SDP message sent by an answerer in response to an offer
        received from an offerer.

    Answerer: An agent which receives a session description from
        another agent describing aspects of desired media
        communication, and then responds to that with its own session
        description.

    Media Stream: From RTSP [8], a media stream is a single media
        instance, e.g., an audio stream or a video stream as well as a
        single whiteboard or shared application group.  In SDP, a media
        stream is described by an "m=" line and its associated
        attributes.

    Offer: An SDP message sent by an offerer.

    Offerer: An agent which generates a session description in order
        to create or modify a session.