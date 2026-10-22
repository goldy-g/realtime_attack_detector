"""Baseline detector (run v0): receives every event and never alerts.

It measures the evaluation harness on its own -- delivery, lag and timing --
before any detection logic exists.
"""

from __future__ import annotations

try:  # evaluate.py puts evaluator/ on sys.path
    from detector_interface import Detector
except ImportError:  # imported from the repository root, e.g. by tools/
    from evaluator.detector_interface import Detector


class MyDetector(Detector):
    """Accepts every event and raises no alerts."""

    def on_event(self, event: dict) -> None:
        pass
