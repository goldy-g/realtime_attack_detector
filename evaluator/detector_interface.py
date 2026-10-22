"""The submission contract.

Your detector subclasses `Detector`. The harness constructs it once, then plays
a series of *waves* through it. A wave is one Windows machine's endpoint
telemetry (DARPA OpTC eCAR events, anonymized):

1. `start_wave(machine, callbacks)` -- a new machine; forget per-machine state and retain this wave's callback handle.
2. **Warm-up**: the 60 minutes before the live window, replayed back to back
   with no pacing, one `on_event()` per event. Use it to learn what normal
   looks like on this machine. Total warm-up compute is capped (120 s per
   wave); events not delivered by then are dropped. No attack starts in the
   warm-up.
3. `on_live()` -- warm-up done; the real-time clock is already running.
4. **Live**: two to about eleven minutes, replayed in REAL TIME. An event stamped
    `ts` is delivered at `wall0 + (ts - live_start)`. Return promptly from
    `on_event()`; queue expensive model work instead of blocking event delivery.
    The live part stops at `live_end + 30 s`; events not yet delivered are dropped.

When your detector concludes an attack is underway, call `callbacks.alert(event_id)`
with an already-delivered event ID. The harness timestamps the callback itself; the
event ID does not backdate the alert. The callback returns an `alert_id` for its
explanation. Call `callbacks.explain(alert_id, text, event_ids)` with the plain-language
reasoning and a structured list of relevant event IDs. Explanation may be immediate
or asynchronous and does not change detection credit.

After the final event-feed call returns, callbacks remain open for at least ten
seconds to receive alerts. After that, the wave closes as soon as every received
alert has an explanation (also when no alerts were received). Missing explanations
extend the wait, up to five minutes after the feed ends. With explanations disabled,
only the ten-second alert wait applies. Closing sets `callbacks.cancelled`; later
callbacks are ignored, even if a worker is still processing events. A missing
explanation at the hard deadline does not erase a valid detection.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from threading import Event
from typing import Callable


@dataclass(frozen=True)
class WaveCallbacks:
    """Thread-safe callbacks scoped to one wave. Capture this object in worker tasks."""

    alert: Callable[[str], str | None]
    """Report the event ID the alert concerns; returns alert_id, or None after closure."""

    explain: Callable[[str, str, list[str]], bool]
    """Attach plain-language text and structured relevant event IDs; False means rejected."""

    cancelled: Event
    """Set when the wave closes (possibly early after ten seconds) or is abandoned."""


class Detector(ABC):
    """Base class for a submission.

    `__init__` is where you load anything you need, including the labelled
    training machine-days in data/train/. It is timed separately as build time
    and is NOT part of any wave's latency -- keep it reasonable (minutes, not
    hours). Everything runs on CPU.
    """

    def __init__(self, train_dir: str) -> None:
        """Args:
        train_dir: path to data/train/ -- machines.jsonl, <machine>.events.jsonl.stream
            and <machine>.labels.json.stream (malicious event ids, chains, event -> chain).
        """
        self.train_dir = train_dir
        self.callbacks: WaveCallbacks | None = None

    def start_wave(self, machine: str, callbacks: WaveCallbacks) -> None:
        """A new wave begins. Reset per-wave state and retain its callback handle."""
        self.callbacks = callbacks

    def on_live(self) -> None:
        """Warm-up done; the real-time part starts now. The live clock is already
        running while this executes, so keep it short."""

    @abstractmethod
    def on_event(self, event: dict) -> None:
        """Called once per event, in order. Enqueue expensive work and return promptly.

        `event` is an eCAR record: id, timestamp (ISO 8601 with offset), hostname,
        object, action, actorID, objectID, pid, ppid, tid, principal, properties.
        Report results through `self.callbacks.alert(event_id)` and
        `self.callbacks.explain(alert_id, text, event_ids)`. Use the captured
        wave callback handle in async work; `cancelled` signals its deadline.
        """
        raise NotImplementedError
