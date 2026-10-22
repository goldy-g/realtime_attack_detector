"""Cut the labelled training days into eval-format waves for local validation.

Every wave mirrors data/eval: an hour of warm-up, then a short live window.
The output has the same layout -- waves.json, <wave>/warmup.stream and
live.stream (gzip JSONL, events copied byte for byte) and answers.json in the
eval answer schema -- so evaluate.py runs it unchanged with --data.

  attack waves  One per training attack. The live window opens 10-45 s before
                the attack's first event, lead-up included, so the warm-up holds
                no attack activity (as in the eval waves). It lasts 120-180 s,
                and at least until 30 s after the alert point.
  benign waves  One 2-3 minute window per benign day, inside working hours
                when the day allows it.

Machines are split into dev (~70%) and holdout (~30%) by a hash of the name, so
holdout machines stay unseen while tuning. Sets: dev, holdout, full (all waves)
and fast (two dev attack waves and two dev benign waves). Window placement is
seeded, so a rebuild gives the same waves.

    python tools/build_val_set.py
    python evaluator/evaluate.py --detector submission.my_detector:MyDetector \\
        --data data/cache/val --set dev --mode instant
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import os
import random
import re
import shutil
import sys
from concurrent.futures import ProcessPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "evaluator"))
from metrics import parse_dt, parse_ts  # noqa: E402  -- the scorer's own timestamp parsing

WARMUP_S = 3600.0
TS = re.compile(r'"timestamp":\s*"([^"]+)"')
HOLDOUT_SHARE = 3                       # in tenths


def split_of(machine: str) -> str:
    return "holdout" if int(hashlib.sha1(machine.encode()).hexdigest(), 16) % 10 < HOLDOUT_SHARE else "dev"


def iso(t: float, tz: dt.tzinfo) -> str:
    return dt.datetime.fromtimestamp(t, tz).isoformat(timespec="milliseconds")


def first_attack_ts(attack: dict) -> float:
    """Earliest event of the attack: the alert point or the start of its lead-up."""
    times = [parse_ts(attack["alert_from"])]
    for activity in attack.get("lead_up") or []:
        times.append(parse_ts(activity["ts"]))
        times += [parse_ts(g["first_ts"]) for g in activity.get("events") or [] if g.get("first_ts")]
    return min(times)


def plan_windows(row: dict, labels: dict, seed: str) -> list[dict]:
    machine, short = row["machine"], row["machine"].removeprefix("host-")
    day_lo, day_hi = parse_ts(row["first_ts"]), parse_ts(row["last_ts"])
    windows = []
    attacks = labels.get("attacks") or []
    for n, attack in enumerate(attacks, 1):
        rng = random.Random("{}:{}:{}".format(seed, machine, attack["attack_id"]))
        alert = parse_ts(attack["alert_from"])
        start = first_attack_ts(attack)
        live_start = start - rng.uniform(10, 45)
        windows.append({
            "wave_id": "atk-" + short + ("-{}".format(n) if len(attacks) > 1 else ""),
            "kind": "attack", "source_attack": attack["attack_id"],
            "live_start": live_start, "live_end": max(live_start + rng.uniform(120, 180), alert + 30),
            "lead_up_s": alert - start,
        })
    if not attacks:
        rng = random.Random("{}:{}:benign".format(seed, machine))
        length = rng.uniform(120, 180)
        date = parse_dt(row["first_ts"])
        lo = max(day_lo + WARMUP_S + 60, date.replace(hour=9, minute=0, second=0, microsecond=0).timestamp())
        hi = min(day_hi - length, date.replace(hour=17, minute=0, second=0, microsecond=0).timestamp())
        if lo >= hi:                    # short day: anywhere after the first hour
            lo, hi = day_lo + WARMUP_S + 60, day_hi - length
        start = rng.uniform(lo, hi)
        windows.append({"wave_id": "ben-" + short, "kind": "benign", "source_attack": None,
                        "live_start": start, "live_end": start + length, "lead_up_s": None})
    return windows


def build_day(task: tuple[dict, str, str, str]) -> list[dict]:
    """Stream one machine-day once, cut its waves, write their streams, return metadata + answers."""
    row, train_dir, out_dir, seed = task
    machine = row["machine"]
    with gzip.open(os.path.join(train_dir, machine + ".labels.json.stream"), "rt", encoding="utf-8") as fh:
        labels = json.load(fh)
    windows = plan_windows(row, labels, seed)
    for w in windows:
        w["warm"], w["live"] = [], []
    last = max(w["live_end"] for w in windows)
    with gzip.open(os.path.join(train_dir, row["file"]), "rt", encoding="utf-8") as fh:
        for raw in fh:
            t = parse_ts(TS.search(raw).group(1))
            if t > last + 1:
                break                   # events are in time order
            for w in windows:
                if w["live_start"] - WARMUP_S <= t < w["live_start"]:
                    w["warm"].append(raw)
                elif w["live_start"] <= t <= w["live_end"]:
                    w["live"].append(raw)

    tz = parse_dt(row["first_ts"]).tzinfo
    malicious = set(labels.get("malicious_event_ids") or [])
    context = set(labels.get("context_event_ids") or [])
    event_attack = labels.get("event_attack") or {}
    event_chain = labels["event_chain"]
    out = []
    for w in windows:
        warm_ids = [json.loads(raw)["id"] for raw in w["warm"]]
        live_ids = [json.loads(raw)["id"] for raw in w["live"]]
        in_warm = [i for i in warm_ids if i in malicious or i in context]
        if in_warm:                     # an earlier attack is still running: not a clean warm-up
            out.append({"wave_id": w["wave_id"], "skipped": "{} attack events in warm-up".format(len(in_warm))})
            continue
        attack_ids = {event_attack[i] for i in live_ids if i in malicious and i in event_attack}
        attacks = [a for a in labels.get("attacks") or [] if a["attack_id"] in attack_ids]
        mal = [i for i in live_ids if i in malicious]
        ctx = [i for i in live_ids if i in context]
        chains_seen = {event_chain.get(i) for i in warm_ids + live_ids}
        answer = {
            "attack": bool(attacks),
            "attack_onset_ts": min((a["alert_from"] for a in attacks), key=parse_ts) if attacks else None,
            "attacks": attacks,
            "malicious_event_ids": mal,
            "context_event_ids": ctx,
            "event_attack": {i: event_attack[i] for i in mal + ctx if i in event_attack},
            "malicious_chains": [{"chain_id": c["chain_id"], "onset_event_id": c["onset_event_id"],
                                  "onset_ts": c["onset_ts"]}
                                 for c in labels.get("chains") or []
                                 if c.get("malicious") and c["chain_id"] in chains_seen],
            "event_chain": {i: event_chain.get(i) for i in warm_ids + live_ids},
            "excused_chains": labels.get("excused_chains") or [],
            "excused_actors": labels.get("excused_actors") or [],
        }
        wave_dir = os.path.join(out_dir, w["wave_id"])
        os.makedirs(wave_dir, exist_ok=True)
        for name, lines in (("warmup.stream", w["warm"]), ("live.stream", w["live"])):
            with gzip.open(os.path.join(wave_dir, name), "wt", encoding="utf-8") as fh:
                fh.writelines(line if line.endswith("\n") else line + "\n" for line in lines)
        out.append({
            "wave": {"wave_id": w["wave_id"], "machine": machine,
                     "live_start": iso(w["live_start"], tz), "live_end": iso(w["live_end"], tz),
                     "warmup_events": len(w["warm"]), "live_events": len(w["live"]),
                     "kind": w["kind"], "source_attack": w["source_attack"]},
            "answer": answer, "lead_up_s": w["lead_up_s"],
            "names": [a["name"] for a in attacks],
        })
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--train", default=os.path.join(ROOT, "data", "train"))
    ap.add_argument("--out", default=os.path.join(ROOT, "data", "cache", "val"))
    ap.add_argument("--seed", default="val-v1")
    ap.add_argument("--workers", type=int, default=min(8, os.cpu_count() or 1))
    args = ap.parse_args()

    out_dir = os.path.abspath(args.out)
    if not out_dir.startswith(os.path.join(ROOT, "data", "cache")):
        sys.exit("refusing to write outside data/cache: " + out_dir)
    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir)
    with open(os.path.join(args.train, "machines.jsonl"), encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]

    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        results = [r for day in pool.map(build_day, [(row, args.train, out_dir, args.seed) for row in rows])
                   for r in day]

    built = [r for r in results if "wave" in r]
    for r in results:
        if "skipped" in r:
            print("skipped {}: {}".format(r["wave_id"], r["skipped"]))
    for r in built:
        r["wave"]["sets"] = [split_of(r["wave"]["machine"]), "full"]
    built.sort(key=lambda r: (r["wave"]["sets"][0], r["wave"]["kind"], r["wave"]["wave_id"]))
    for kind in ("attack", "benign"):
        for r in [r for r in built if r["wave"]["sets"][0] == "dev" and r["wave"]["kind"] == kind][:2]:
            r["wave"]["sets"].append("fast")

    with open(os.path.join(out_dir, "waves.json"), "w", encoding="utf-8") as fh:
        json.dump({"waves": [r["wave"] for r in built]}, fh, indent=1)
    with open(os.path.join(out_dir, "answers.json"), "w", encoding="utf-8") as fh:
        json.dump({"waves": {r["wave"]["wave_id"]: r["answer"] for r in built}}, fh)

    print("\n{:<9} {:>7} {:>7} {:>11} {:>11}".format("set", "attack", "benign", "warm-up ev", "live ev"))
    for split in ("dev", "holdout"):
        rs = [r for r in built if r["wave"]["sets"][0] == split]
        print("{:<9} {:>7} {:>7} {:>11,} {:>11,}".format(
            split, sum(r["wave"]["kind"] == "attack" for r in rs), sum(r["wave"]["kind"] == "benign" for r in rs),
            sum(r["wave"]["warmup_events"] for r in rs), sum(r["wave"]["live_events"] for r in rs)))
    print("\nattack waves (lead-up = first attack event -> alert point):")
    for r in [r for r in built if r["wave"]["kind"] == "attack"]:
        w = r["wave"]
        live_s = parse_ts(w["live_end"]) - parse_ts(w["live_start"])
        print("  {:<8} {:<12} live {:5.0f} s  lead-up {:5.0f} s  {:>5} live ev  {}".format(
            w["sets"][0], w["wave_id"], live_s, r["lead_up_s"], w["live_events"], "; ".join(r["names"])[:70]))
    print("\n{} waves -> {}".format(len(built), os.path.relpath(out_dir, ROOT)))


if __name__ == "__main__":
    main()
