"""Write a scoreable copy of the eval answer key.

metrics.score_wave() rejects any answer without an `event_attack` field, but the
four benign eval waves (w04-w07) omit it, as data/README.md documents. Scoring any
set that contains one -- the default `fast` set included -- stops with
"answers must use the current event_attack label schema" after the whole run.

This adds the missing empty field to a copy. The provided answers.json and the
evaluator stay untouched; pass the copy with --answers:

    python tools/fix_eval_answers.py
    python evaluator/evaluate.py --detector ... --answers data/cache/eval_answers.json
"""

from __future__ import annotations

import argparse
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", default=os.path.join(ROOT, "data", "eval", "answers.json"))
    ap.add_argument("--out", default=os.path.join(ROOT, "data", "cache", "eval_answers.json"))
    args = ap.parse_args()

    with open(args.src, encoding="utf-8") as fh:
        doc = json.load(fh)
    fixed = [wave_id for wave_id, answer in doc["waves"].items() if "event_attack" not in answer]
    for wave_id in fixed:
        doc["waves"][wave_id]["event_attack"] = {}

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    print("added an empty event_attack to {} wave(s): {} -> {}".format(
        len(fixed), ", ".join(fixed) or "none", os.path.relpath(args.out, ROOT)))


if __name__ == "__main__":
    main()
