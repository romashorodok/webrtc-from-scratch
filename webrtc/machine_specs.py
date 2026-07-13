"""Bounded observable machine definitions and compiled task-owner mappings."""

from types import MappingProxyType

from .state_machine import MachineSpec


def _spec(machine_type, initial, transitions, terminal=(), test_actions=()):
    return MachineSpec(
        machine_type, initial, transitions, frozenset(terminal), frozenset(test_actions)
    )


MACHINE_SPECS = MappingProxyType({
    "peer": _spec("peer", "new", {
        "new": {"starting", "closed"}, "starting": {"connected", "failed", "closing"},
        "connected": {"closing", "failed"}, "failed": {"closing", "closed"},
        "closing": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner", "inject_failure"}),
    "ice": _spec("ice", "new", {
        "new": {"checking", "closed"}, "checking": {"connected", "failed", "closed"},
        "connected": {"completed", "disconnected", "failed", "closed"},
        "completed": {"disconnected", "failed", "closed"},
        "disconnected": {"checking", "failed", "closed"}, "failed": {"closed"},
        "closed": set(),
    }, {"closed"}, {"cancel_owner", "inject_failure"}),
    "dtls": _spec("dtls", "new", {
        "new": {"connecting", "closed"},
        "connecting": {"connected", "failed", "closed"},
        "connected": {"failed", "closed"}, "failed": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner", "inject_failure"}),
    "transport": _spec("transport", "new", {
        "new": {"starting", "closed"}, "starting": {"ready", "failed", "closed"},
        "ready": {"draining", "failed", "closed"},
        "draining": {"closed", "failed"}, "failed": {"closed"}, "closed": set(),
    }, {"closed"}, {"cancel_owner"}),
    "worker": _spec("worker", "idle", {
        "idle": {"queued", "closed"}, "queued": {"running", "idle", "closed"},
        "running": {"idle", "failed", "closed"}, "failed": {"idle", "closed"},
        "closed": set(),
    }, {"closed"}, {"cancel_owner", "inject_failure"}),
    "transceiver": _spec("transceiver", "inactive", {
        "inactive": {"active", "stopping", "stopped"},
        "active": {"inactive", "stopping", "failed"},
        "stopping": {"stopped"}, "failed": {"stopping", "stopped"}, "stopped": set(),
    }, {"stopped"}, {"cancel_owner"}),
    "media": _spec("media", "inactive", {
        "inactive": {"active", "ended"}, "active": {"muted", "inactive", "ended", "failed"},
        "muted": {"active", "inactive", "ended"}, "failed": {"ended"}, "ended": set(),
    }, {"ended"}, {"cancel_owner"}),
})

# `@task(state=...)` accepts only these stable machine identities.  Helper
# tasks without a mapping remain registry-owned and invisible to this plane.
TASK_STATE_MACHINE_MAP = MappingProxyType({name: spec for name, spec in MACHINE_SPECS.items()})

