"""Bounded observable machine definitions and compiled task-owner mappings."""

from types import MappingProxyType

from .state_machine import MachineSpec


def _spec(machine_type, initial, transitions, terminal=(), test_actions=()):
    return MachineSpec(
        machine_type, initial, transitions, frozenset(terminal), frozenset(test_actions)
    )


MACHINE_SPECS = MappingProxyType({
    "runtime": _spec("runtime", "new", {
        "new": {"starting", "closed"},
        "starting": {"active", "failed"},
        "active": {"quiescing", "failed"},
        "quiescing": {"draining", "failed"},
        "failed": {"draining"},
        "draining": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner", "inject_failure"}),
    "peer": _spec("peer", "new", {
        "new": {"starting", "closing"},
        "starting": {"negotiating", "failed", "closing"},
        "negotiating": {"negotiating", "connecting", "failed", "closing"},
        "connecting": {"connected", "failed", "closing"},
        "connected": {"negotiating", "failed", "closing"},
        "failed": {"closing"},
        "closing": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner", "inject_failure"}),
    "signaling": _spec("signaling", "stable", {
        "stable": {"have-local-offer", "have-remote-offer", "failed", "closed"},
        "have-local-offer": {"stable", "failed", "closed"},
        "have-remote-offer": {"stable", "failed", "closed"},
        "failed": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner", "inject_failure"}),
    "ice-gatherer": _spec("ice-gatherer", "new", {
        "new": {"gathering", "closed"},
        "gathering": {"complete", "failed", "closed"},
        "complete": {"closed"}, "failed": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner", "inject_failure"}),
    "ice-agent": _spec("ice-agent", "new", {
        "new": {"waiting-remote", "closed"},
        "waiting-remote": {"checking", "failed", "closed"},
        "checking": {"connected", "failed", "closed"},
        "connected": {"completed", "disconnected", "failed", "closed"},
        "completed": {"disconnected", "failed", "closed"},
        "disconnected": {"checking", "failed", "closed"},
        "failed": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner", "inject_failure"}),
    "candidate-pair": _spec("candidate-pair", "frozen", {
        "frozen": {"waiting", "failed", "closed"},
        "waiting": {"in-progress", "failed", "closed"},
        "in-progress": {"succeeded", "failed", "closed"},
        "succeeded": {"nominated", "failed", "closed"},
        "nominated": {"failed", "closed"}, "failed": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner"}),
    "candidate-pair-controller": _spec("candidate-pair-controller", "new", {
        "new": {"starting", "stopping"}, "starting": {"checking", "failed", "stopping"},
        "checking": {"nominated", "failed", "stopping"},
        "nominated": {"forwarding", "failed", "stopping"},
        "forwarding": {"failed", "stopping"}, "failed": {"stopping"},
        "stopping": {"stopped"}, "stopped": set(),
    }, {"stopped"}, {"cancel_owner", "inject_failure"}),
    "udp-mux": _spec("udp-mux", "new", {
        "new": {"binding", "draining"}, "binding": {"active", "failed", "draining"},
        "active": {"draining", "failed"}, "failed": {"draining", "closed"},
        "draining": {"closed", "failed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner"}),
    "udp-binding": _spec("udp-binding", "new", {
        "new": {"bound", "draining"}, "bound": {"active", "failed", "draining"},
        "active": {"draining", "failed"}, "failed": {"draining"},
        "draining": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner"}),
    "dtls-transport": _spec("dtls-transport", "new", {
        "new": {"binding", "connecting", "closed"},
        "binding": {"connecting", "failed", "closing"},
        "connecting": {"connected", "failed", "closing"},
        "connected": {"failed", "closing"},
        "failed": {"closing"}, "closing": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner", "inject_failure"}),
    "dtls-handshake-phase": _spec("dtls-handshake-phase", "preparing", {
        "preparing": {"sending", "errored"},
        "sending": {"sending", "waiting", "finished", "errored"},
        "waiting": {"preparing", "waiting", "finished", "errored"},
        "errored": {"preparing"}, "finished": set(),
    }, {"finished"}, {"cancel_owner", "inject_failure"}),
    "srtp-session": _spec("srtp-session", "new", {
        "new": {"initializing", "failed", "closed"},
        "initializing": {"ready", "failed"},
        "ready": {"draining", "failed"}, "failed": {"draining"},
        "draining": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner", "inject_failure"}),
    "srtp-stream": _spec("srtp-stream", "new", {
        "new": {"active", "failed", "closed"}, "active": {"draining", "failed"},
        "failed": {"draining"}, "draining": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner"}),
    "transport": _spec("transport", "new", {
        "new": {"selecting", "draining"}, "selecting": {"ready", "failed", "draining"},
        "ready": {"draining", "failed"},
        "failed": {"draining"}, "draining": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner"}),
    "worker-lane": _spec("worker-lane", "idle", {
        "idle": {"queued", "closing"},
        "queued": {"running", "idle", "closing"},
        "running": {"idle", "failed", "closing"},
        "failed": {"idle", "closing"},
        "closing": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner", "inject_failure"}),
    "transceiver": _spec("transceiver", "inactive", {
        "inactive": {"negotiating", "stopping", "failed"},
        "negotiating": {"active", "inactive", "failed", "stopping"},
        "active": {"active", "negotiating", "inactive", "stopping", "failed"},
        "stopping": {"stopped"}, "failed": {"stopping", "stopped"}, "stopped": set(),
    }, {"stopped"}, {"cancel_owner"}),
    "rtp-sender": _spec("rtp-sender", "new", {
        "new": {"bound", "stopping"},
        "bound": {"active", "stopping", "failed"},
        "active": {"paused", "stopping", "failed"},
        "paused": {"active", "stopping", "failed"},
        "failed": {"stopping"}, "stopping": {"stopped"}, "stopped": set(),
    }, {"stopped"}, {"cancel_owner"}),
    "rtp-receiver": _spec("rtp-receiver", "new", {
        "new": {"bound", "stopping"},
        "bound": {"active", "stopping", "failed"},
        "active": {"paused", "stopping", "failed"},
        "paused": {"active", "stopping", "failed"},
        "failed": {"stopping"}, "stopping": {"stopped"}, "stopped": set(),
    }, {"stopped"}, {"cancel_owner"}),
    "media-track": _spec("media-track", "new", {
        "new": {"live", "ended"}, "live": {"muted", "ended", "failed"},
        "muted": {"live", "ended", "failed"}, "failed": {"ended"}, "ended": set(),
    }, {"ended"}, {"cancel_owner"}),
    "media-send": _spec("media-send", "new", {
        "new": {"active", "closed"}, "active": {"draining", "failed"},
        "failed": {"draining"}, "draining": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner", "inject_failure"}),
    "media": _spec("media", "inactive", {
        "inactive": {"active", "ended"}, "active": {"muted", "inactive", "ended", "failed"},
        "muted": {"active", "inactive", "ended"}, "failed": {"ended"}, "ended": set(),
    }, {"ended"}, {"cancel_owner"}),
    "attachment-registry": _spec("attachment-registry", "open", {
        "open": {"starting", "closing", "failed"},
        "starting": {"active", "closing", "failed"},
        "active": {"closing", "failed"},
        "failed": {"closing"}, "closing": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner"}),
    "attachment": _spec("attachment", "detached", {
        "detached": {"attached"}, "attached": {"starting", "stopping"},
        "starting": {"active", "failed", "stopping"},
        "active": {"stopping", "failed"}, "failed": {"stopping"},
        "stopping": {"stopped"}, "stopped": set(),
    }, {"stopped"}, {"cancel_owner"}),
    "log-drain": _spec("log-drain", "stopped", {
        "stopped": {"starting"}, "starting": {"idle", "failed", "stopping"},
        "idle": {"draining", "stopping", "failed"},
        "draining": {"idle", "stopping", "failed"},
        "failed": {"stopping"}, "stopping": {"stopped"},
    }, {"stopped"}, {"cancel_owner"}),
    "queue": _spec("queue", "open", {
        "open": {"closing", "failed"}, "failed": {"closing"},
        "closing": {"drained"}, "drained": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner"}),
    "observability": _spec("observability", "stopped", {
        "stopped": {"starting"}, "starting": {"active", "degraded", "draining"},
        "active": {"degraded", "draining"},
        "degraded": {"active", "draining"},
        "draining": {"stopped"},
    }, {"stopped"}, {"cancel_owner"}),
})
