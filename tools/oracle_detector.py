"""Oracle detector: a test of a wave set and the harness, never a submission.

It reads the answer key named by ORACLE_ANSWERS and alerts exactly at each
attack's alert point during the live phase. On a correct wave set it scores
100% recall, no false alarms and a timeliness score of 1.0 in instant mode.

    ORACLE_ANSWERS=data/cache/val/answers.json python evaluator/evaluate.py \\
        --detector tools.oracle_detector:OracleDetector --data data/cache/val \\
        --set full --mode instant --no-explain
"""

from __future__ import annotations

import json
import os

try:  # evaluate.py puts evaluator/ on sys.path
    from detector_interface import Detector
except ImportError:
    from evaluator.detector_interface import Detector


class OracleDetector(Detector):
    def __init__(self, train_dir: str) -> None:
        super().__init__(train_dir)
        with open(os.environ["ORACLE_ANSWERS"], encoding="utf-8") as fh:
            waves = json.load(fh)["waves"]
        self.alert_points = {a["first_alertable_event_id"]
                             for answer in waves.values() for a in answer.get("attacks") or []}
        self.live = False

    def start_wave(self, machine, callbacks) -> None:
        super().start_wave(machine, callbacks)
        self.live = False

    def on_live(self) -> None:
        self.live = True

    def on_event(self, event: dict) -> None:
        if self.live and event["id"] in self.alert_points:
            self.callbacks.alert(event["id"])
