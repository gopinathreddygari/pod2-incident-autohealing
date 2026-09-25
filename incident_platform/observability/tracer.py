"""OpenTelemetry-shaped tracing with no SDK dependency.

Spans carry the same identifiers OTel does (trace_id, span_id, parent_id),
nest automatically through a ContextVar, and record status + attributes.
Swapping in the real ``opentelemetry-sdk`` means replacing ``start_span``
with ``tracer.start_as_current_span`` -- call sites don't change.
"""

from __future__ import annotations

import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Iterator


@dataclass
class Span:
    name: str
    trace_id: str
    span_id: str
    parent_id: str | None
    start_ns: int                      # wall clock (epoch ns), for display / export
    end_ns: int | None = None
    status: str = "OK"
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)
    # Monotonic high-resolution clock for ordering and durations: the wall clock
    # ticks only every ~15 ms on Windows, which would make most spans "0 ms".
    mono_start_ns: int = field(default_factory=time.perf_counter_ns)
    mono_end_ns: int | None = None

    @property
    def duration_ms(self) -> float:
        if self.mono_end_ns is None:
            return 0.0
        return (self.mono_end_ns - self.mono_start_ns) / 1e6

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def add_event(self, name: str, **attributes: Any) -> None:
        self.events.append({"name": name, "ts_ns": time.time_ns(), **attributes})

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_id": self.parent_id,
            "duration_ms": round(self.duration_ms, 3),
            "status": self.status,
            "attributes": dict(self.attributes),
            "events": list(self.events),
        }


class Tracer:
    def __init__(self, service_name: str = "incident-platform"):
        self.service_name = service_name
        self.spans: list[Span] = []          # finished spans
        self.active: dict[str, Span] = {}    # started, not yet finished (for live views)
        self._current: ContextVar[Span | None] = ContextVar(
            f"current_span_{id(self)}", default=None
        )

    @contextmanager
    def start_span(self, name: str, attributes: dict[str, Any] | None = None) -> Iterator[Span]:
        parent = self._current.get()
        span = Span(
            name=name,
            trace_id=parent.trace_id if parent else uuid.uuid4().hex,
            span_id=uuid.uuid4().hex[:16],
            parent_id=parent.span_id if parent else None,
            start_ns=time.time_ns(),
            attributes={"service.name": self.service_name, **(attributes or {})},
        )
        token = self._current.set(span)
        self.active[span.span_id] = span
        try:
            yield span
        except BaseException as exc:
            span.status = "ERROR"
            span.set_attribute("error.type", type(exc).__name__)
            span.set_attribute("error.message", str(exc))
            raise
        finally:
            span.mono_end_ns = time.perf_counter_ns()
            span.end_ns = time.time_ns()
            self._current.reset(token)
            self.spans.append(span)
            self.active.pop(span.span_id, None)

    def current_span(self) -> Span | None:
        return self._current.get()

    def current_trace_id(self) -> str | None:
        span = self._current.get()
        return span.trace_id if span else None

    def spans_for_trace(self, trace_id: str) -> list[Span]:
        return [s for s in self.spans if s.trace_id == trace_id]
