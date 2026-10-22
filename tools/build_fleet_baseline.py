"""Build submission/fleet_baseline.json: benign process and connection pairs of every training machine.

For each of the 62 training days it records which parent -> child process pairs
and which process -> destination-port outbound pairs occur in benign activity
(malicious and context events, per the labels, are left out). The detector uses
it only to order its queue: a pair seen on many machines is less suspicious.

    python tools/build_fleet_baseline.py [--train data/train]

Rebuild it whenever the training data changes. Takes about a minute.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from submission.baseline import flow_key, proc_key  # noqa: E402  -- the detector's own keys

OUT = os.path.join(ROOT, "submission", "fleet_baseline.json")


def day_pairs(args: tuple[str, str]) -> tuple[str, list, list]:
    train, machine = args
    with gzip.open(os.path.join(train, machine + ".labels.json.stream"), "rt", encoding="utf-8") as fh:
        labels = json.load(fh)
    bad = set(labels.get("malicious_event_ids") or []) | set(labels.get("context_event_ids") or [])
    pairs, flows = set(), set()
    with gzip.open(os.path.join(train, machine + ".events.jsonl.stream"), "rt", encoding="utf-8") as fh:
        for line in fh:
            if '"object":"PROCESS"' in line and '"action":"CREATE"' in line:
                ev = json.loads(line)
                if ev["id"] not in bad:
                    pairs.add("|".join(proc_key(ev)))
            elif '"object":"FLOW"' in line:
                ev = json.loads(line)
                key = flow_key(ev)
                if key and ev["id"] not in bad:
                    flows.add("|".join(key))
    return machine, sorted(pairs), sorted(flows)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--train", default=os.path.join(ROOT, "data", "train"))
    args = ap.parse_args()
    with open(os.path.join(args.train, "machines.jsonl"), encoding="utf-8") as fh:
        machines = [json.loads(line)["machine"] for line in fh]
    with ProcessPoolExecutor(max_workers=min(12, os.cpu_count() or 4)) as pool:
        days = list(pool.map(day_pairs, [(args.train, m) for m in machines]))
    index = {m: i for i, m in enumerate(machines)}
    pairs: dict[str, list[int]] = {}
    flows: dict[str, list[int]] = {}
    for machine, ps, fs in days:
        for k in ps:
            pairs.setdefault(k, []).append(index[machine])
        for k in fs:
            flows.setdefault(k, []).append(index[machine])
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump({"machines": machines, "pairs": pairs, "flows": flows}, fh, separators=(",", ":"), sort_keys=True)
    print("{}: {} machines, {} process pairs, {} connection pairs, {:.0f} KB".format(
        os.path.relpath(OUT, ROOT), len(machines), len(pairs), len(flows), os.path.getsize(OUT) / 1024))


if __name__ == "__main__":
    main()
