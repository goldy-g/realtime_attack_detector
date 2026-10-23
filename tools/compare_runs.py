"""Compare two recorded runs attack by attack: which change helped, where, and by how much.

Reads results/<label>/scorecard.json of each run (the evaluator's own scoring) and
prints the headline numbers side by side, then one row per attack: detection
delay, the malicious event it was caught at, and its timeliness score. Waves
present in only one run are listed but not compared.

    python tools/compare_runs.py v1.2-dev-attacks v1.3-dev-attacks
    python tools/compare_runs.py v1.2-dev-attacks v1.3-dev-attacks --md results/compare.md
"""

from __future__ import annotations

import argparse
import json
import os
import statistics

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEADLINE = [("recall", "Recall", 3), ("timeliness_score", "Timeliness", 3), ("delay_s_p50", "Delay p50 (s)", 2),
            ("delay_s_max", "Delay max (s)", 2), ("false_alarms", "False alarms", 0),
            ("evidence_precision", "Evidence precision", 3)]


def load(label: str) -> dict:
    with open(os.path.join(ROOT, "results", label, "scorecard.json"), encoding="utf-8") as fh:
        return json.load(fh)


def attacks(card: dict) -> dict:
    out = {}
    for wave, w in card["waves"].items():
        for aid, a in (w.get("attacks") or {}).items():
            out[(wave, aid)] = a
    return out


def fmt(v, digits: int) -> str:
    if v is None:
        return "–"
    return str(int(v)) if digits == 0 else "{:.{}f}".format(v, digits)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("before")
    ap.add_argument("after")
    ap.add_argument("--md", help="also write the comparison as Markdown to this path")
    args = ap.parse_args()
    a, b = load(args.before), load(args.after)
    lines = ["# {} → {}".format(args.before, args.after), "",
             "| | {} | {} |".format(args.before, args.after), "|---|---|---|"]
    for key, name, digits in HEADLINE:
        lines.append("| {} | {} | {} |".format(name, fmt(a["summary"].get(key), digits), fmt(b["summary"].get(key), digits)))
    aa, bb = attacks(a), attacks(b)
    both = sorted(set(aa) & set(bb))
    lines += ["", "| Wave | Attack | Delay (s) before → after | Caught at event before → after | Timeliness before → after | Change |",
              "|---|---|---|---|---|---|"]
    gains = []
    for key in both:
        x, y = aa[key], bb[key]
        d = (y.get("event_score") or 0) - (x.get("event_score") or 0)
        gains.append(d)
        lines.append("| {} | {} | {} → {} | {} → {} of {} | {} → {} | {:+.3f} |".format(
            key[0], key[1], fmt(x.get("delay_s"), 2), fmt(y.get("delay_s"), 2), x.get("caught_at_event") or "–",
            y.get("caught_at_event") or "–", y.get("n_malicious_events"), fmt(x.get("event_score"), 3),
            fmt(y.get("event_score"), 3), d))
    if gains:
        lines += ["", "Timeliness change per attack: mean {:+.3f}, median {:+.3f}; better on {}, worse on {}, same on {} of {}.".format(
            statistics.fmean(gains), statistics.median(gains), sum(g > 0.0005 for g in gains),
            sum(g < -0.0005 for g in gains), sum(abs(g) <= 0.0005 for g in gains), len(gains))]
    only = sorted(set(aa) ^ set(bb))
    if only:
        lines += ["", "In one run only: " + ", ".join("{} {}".format(*k) for k in only)]
    text = "\n".join(lines) + "\n"
    print(text)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(text)


if __name__ == "__main__":
    main()
