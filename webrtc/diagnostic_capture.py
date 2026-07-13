from __future__ import annotations

import time
import math
from collections import Counter
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class CaptureAuthorization:
    capture_id: int
    selector_kind: str
    selector_value: int | str
    expires_ns: int
    call_budget: int
    calls_started: int


@dataclass(slots=True)
class _CaptureRule:
    capture_id: int
    selector_kind: str
    selector_value: int | str
    match_value: int | str
    expires_ns: int
    remaining_calls: int
    initial_calls: int


@dataclass(slots=True)
class CaptureRecord:
    record_id: int
    capture_id: int
    selector_kind: str
    selector_value: int | str
    operation_id: int
    operation: str
    owner_entity_id: str
    started_ns: int
    finished_ns: int = 0
    duration_ns: int = 0
    outcome: str = "running"
    failure_class: str | None = None
    revision: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "capture_id": self.capture_id,
            "selector_kind": self.selector_kind,
            "selector_value": self.selector_value,
            "operation_id": self.operation_id,
            "operation": self.operation,
            "owner_entity_id": self.owner_entity_id,
            "started_ns": self.started_ns,
            "finished_ns": self.finished_ns or None,
            "duration_ms": self.duration_ns / 1_000_000,
            "outcome": self.outcome,
            "failure_class": self.failure_class,
            "revision": self.revision,
            "diagnostic_capture": True,
        }


class DiagnosticCaptureManager:
    """Runtime-local, server-authorized and strictly bounded exact capture."""

    SELECTORS = frozenset({"operation", "entity", "control", "facet"})

    def __init__(
        self, *, diagnostics: Counter[str], max_active: int = 8,
        max_duration_seconds: float = 60.0, max_call_budget: int = 1_000,
        max_records: int = 1_024,
    ) -> None:
        self.diagnostics = diagnostics
        self.max_active = max(1, max_active)
        self.max_duration_ns = max(1, int(max_duration_seconds * 1_000_000_000))
        self.max_call_budget = max(1, max_call_budget)
        self.max_records = max(1, max_records)
        self._next_capture_id = 1
        self._next_record_id = 1
        self._rules: dict[int, _CaptureRule] = {}
        self._records: dict[int, CaptureRecord] = {}
        self._dirty: set[int] = set()
        self._removed: set[int] = set()
        self._dirty_callback = None
        self.closed = False

    def set_dirty_callback(self, callback) -> None:
        self._dirty_callback = callback

    @property
    def has_active_rules(self) -> bool:
        """Allocation-free observation fast path; expiry is handled on a match attempt."""
        return bool(self._rules) and not self.closed

    def authorize(
        self, selector_kind: str, selector_value: int | str, *,
        duration_seconds: float, call_budget: int,
        match_value: int | str | None = None,
    ) -> CaptureAuthorization:
        if self.closed:
            raise RuntimeError("runtime capture manager is closed")
        if selector_kind not in self.SELECTORS:
            raise ValueError("unsupported capture selector")
        if (
            not isinstance(selector_value, (int, str))
            or isinstance(selector_value, bool)
            or (isinstance(selector_value, str) and (not selector_value or len(selector_value) > 128))
        ):
            raise ValueError("capture selector value must be a bounded string or integer")
        if not isinstance(call_budget, int) or isinstance(call_budget, bool) or call_budget <= 0:
            raise ValueError("call_budget must be a positive integer")
        if (
            not isinstance(duration_seconds, (int, float))
            or isinstance(duration_seconds, bool)
            or not math.isfinite(duration_seconds)
            or duration_seconds <= 0
        ):
            raise ValueError("duration_seconds must be positive")
        self.expire()
        if len(self._rules) >= self.max_active:
            self.diagnostics["capture_authorization_rejections"] += 1
            raise RuntimeError("active capture limit reached")
        calls = min(call_budget, self.max_call_budget)
        duration_ns = min(int(duration_seconds * 1_000_000_000), self.max_duration_ns)
        capture_id = self._next_capture_id
        self._next_capture_id += 1
        rule = _CaptureRule(
            capture_id, selector_kind, selector_value,
            selector_value if match_value is None else match_value,
            time.monotonic_ns() + duration_ns, calls, calls,
        )
        self._rules[capture_id] = rule
        self.diagnostics["captures_authorized"] += 1
        return self._authorization(rule)

    def begin(
        self, policy: Any, owner_entity_id: str, scope_id: str | None,
        entity_alias: str | None = None,
    ) -> CaptureRecord | None:
        if self.closed:
            return None
        now = time.monotonic_ns()
        self.expire(now)
        for rule in tuple(self._rules.values()):
            if not self._matches(
                rule, policy.operation_id, owner_entity_id, scope_id, entity_alias
            ):
                continue
            rule.remaining_calls -= 1
            record = CaptureRecord(
                self._next_record_id, rule.capture_id, rule.selector_kind,
                rule.selector_value, policy.operation_id, policy.operation[:256],
                owner_entity_id[:128], now,
            )
            self._next_record_id += 1
            if not self._admit_record(record):
                return None
            if rule.remaining_calls == 0:
                self._rules.pop(rule.capture_id, None)
                self.diagnostics["captures_call_budget_exhausted"] += 1
            self.diagnostics["captured_calls"] += 1
            return record
        return None

    def finish(self, record: CaptureRecord, outcome: str, exception: BaseException | None = None) -> None:
        if record.record_id not in self._records:
            return
        finished = time.monotonic_ns()
        record.finished_ns = finished
        record.duration_ns = max(0, finished - record.started_ns)
        record.outcome = outcome
        record.failure_class = type(exception).__name__[:128] if exception is not None else None
        record.revision += 1
        self._dirty.add(record.record_id)
        self._changed()

    def expire(self, now_ns: int | None = None) -> int:
        now_ns = time.monotonic_ns() if now_ns is None else now_ns
        expired = [key for key, rule in self._rules.items() if rule.expires_ns <= now_ns]
        for capture_id in expired:
            self._rules.pop(capture_id, None)
        if expired:
            self.diagnostics["captures_expired"] += len(expired)
        return len(expired)

    def cancel(self, capture_id: int) -> bool:
        removed = self._rules.pop(capture_id, None) is not None
        if removed:
            self.diagnostics["captures_cancelled"] += 1
        return removed

    def active(self) -> tuple[CaptureAuthorization, ...]:
        self.expire()
        return tuple(self._authorization(rule) for rule in self._rules.values())

    def snapshots(self) -> tuple[CaptureRecord, ...]:
        return tuple(self._records.values())

    def drain_dirty(self) -> tuple[CaptureRecord, ...]:
        ids = tuple(self._dirty)
        self._dirty.clear()
        return tuple(self._records[key] for key in ids if key in self._records)

    def drain_removed(self) -> tuple[int, ...]:
        ids = tuple(sorted(self._removed))
        self._removed.clear()
        return ids

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self._rules:
            self.diagnostics["captures_teardown_cancelled"] += len(self._rules)
        self._rules.clear()

    def _matches(self, rule, operation_id, owner_entity_id, scope_id, entity_alias) -> bool:
        if rule.selector_kind == "operation":
            return rule.match_value == operation_id
        return rule.match_value in {owner_entity_id, scope_id, entity_alias}

    def _admit_record(self, record: CaptureRecord) -> bool:
        if len(self._records) >= self.max_records:
            terminal = next((key for key, item in self._records.items() if item.outcome != "running"), None)
            if terminal is None:
                self.diagnostics["capture_record_limit_rejections"] += 1
                return False
            self._records.pop(terminal, None)
            self._dirty.discard(terminal)
            self._removed.add(terminal)
            self.diagnostics["capture_records_evicted"] += 1
        self._records[record.record_id] = record
        self._dirty.add(record.record_id)
        self._changed()
        return True

    def _changed(self) -> None:
        if self._dirty_callback is not None:
            self._dirty_callback()

    @staticmethod
    def _authorization(rule: _CaptureRule) -> CaptureAuthorization:
        return CaptureAuthorization(
            rule.capture_id, rule.selector_kind, rule.selector_value,
            rule.expires_ns, rule.initial_calls, rule.initial_calls - rule.remaining_calls,
        )
