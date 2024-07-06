from typing import Any
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import asyncio, json

from ice.candidate_base import get_candidate_type_from_str, parse_candidate_str
import peer_connection

app = FastAPI()

origins = [
    "*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


pc = peer_connection.PeerConnection()

lock = asyncio.Lock()


async def peer():
    yield pc


@app.get("/offer")
async def offer(pc: peer_connection.PeerConnection = Depends(peer)):
    async with lock:
        print(pc)
        pc.add_transceiver_from_kind(
            peer_connection.RTPCodecKind.Video,
            peer_connection.RTPTransceiverDirection.Sendrecv,
        )
        desc = await pc.create_offer()
        if not desc:
            return "unable create offer"
        return {"type": "offer", "sdp": desc.marshal()}


@app.get("/candidates")
async def candidates(pc: peer_connection.PeerConnection = Depends(peer)):
    async with lock:
        print(pc)
        await pc.gatherer.gather()
        candidates = await pc.gatherer.agent.get_local_candidates()
        c = candidates[0]
        return c.unwrap.to_ice_str()


@app.post("/ice")
async def ice(req: Request, pc: peer_connection.PeerConnection = Depends(peer)):
    async with lock:
        body = await req.body()
        body_dict: dict[str, Any] = json.loads(body)
        candidate = body_dict.get("candidate")
        if not candidate:
            return
        pc.gatherer.agent.add_remote_candidate(candidate)
        await pc.gatherer.gather()
        pc.gatherer.agent.accept()

        await pc._dtls_transport.start()


@app.post("/answer")
async def answer(req: Request, pc: peer_connection.PeerConnection = Depends(peer)):
    async with lock:
        body = await req.body()
        body_dict = json.loads(body)
        sdp = body_dict["sdp"]
        desc = peer_connection.SessionDescription.parse(sdp)
        media = desc.media_descriptions[0]

        pc._dtls_transport._media_fingerprints.extend(media.fingerprints)

        candidate_str = media.candidates
        ufrag, pwd = media.ice_ufrag, media.ice_pwd
        if not ufrag or not pwd:
            return

        pc.gatherer.agent.set_remote_credentials(ufrag, pwd)

        pc.gatherer.agent.accept()
        await pc.gatherer.gather()

        await pc._dtls_transport.start()

        print(candidate_str, ufrag, pwd)
