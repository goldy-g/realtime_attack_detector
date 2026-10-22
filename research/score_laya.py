"""2.10 (architecture alternative) Laya, an encoder decision model, zero-shot on the quick case set.

Laya (convaiinnovations/laya, ModernBERT-large + decision head, 421M parameters)
answers typed questions in one pass. It cannot write explanations, and a
classifier may not count as "the SLM", so the question here is narrow: could it
rank cases for the SLM? It runs in its own environment because it needs PyTorch:

    data/cache/research/laya-venv/bin/python research/score_laya.py [cpu|mps]

Writes data/cache/research/scores/Laya.quick.jsonl and research/out/score_laya.md.
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import time

from common import ROOT, save_text
from score_models import auc, case_set

SCORES = os.path.join(ROOT, "data", "cache", "research", "scores")
QUESTIONS = {
    "is_attack": {"type": "noul",
                  "instructions": "Is this Windows event evidence of a cyberattack (an intruder or malware running code, "
                                  "persisting, escalating privileges, moving laterally or contacting a command-and-control "
                                  "server) rather than normal user, administrator, software or system activity?"},
    "kind": {"type": "choice", "instructions": "What best describes this Windows event?",
             "criteria": {"attack": "an intruder or malware executing, persisting, escalating, moving laterally or calling home",
                          "normal": "users, administrators, installers, updaters, system services, scheduled maintenance, test automation"}},
}


def main() -> None:
    device = sys.argv[1] if len(sys.argv) > 1 else "cpu"
    os.environ.setdefault("USE_TF", "0")
    import laya  # noqa: PLC0415 -- only installed in the Laya environment
    t = time.perf_counter()
    agent = laya.load("convaiinnovations/laya", device=device) if "device" in laya.load.__code__.co_varnames else laya.load("convaiinnovations/laya")
    load_s = time.perf_counter() - t
    cases = case_set("quick")
    rows, walls = [], []
    for c in cases:
        t = time.perf_counter()
        res = agent.predict(c["text"], QUESTIONS)
        walls.append(time.perf_counter() - t)
        ans = res["answers"]
        kind = ans["kind"]
        p_choice = (kind.get("probabilities") or kind.get("probs") or {}).get("attack")
        rows.append({k: c[k] for k in ("case_id", "split", "source", "wave", "label", "attack_id", "is_alert_point", "ts")}
                    | {"p_noul": ans["is_attack"].get("noul"), "choice": kind.get("choice"), "p_choice": p_choice})
    os.makedirs(SCORES, exist_ok=True)
    with open(os.path.join(SCORES, "Laya.quick.jsonl"), "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    mal = [r for r in rows if r["label"] == "malicious"]
    ben = [r for r in rows if r["label"] == "benign"]
    lines = ["# Laya zero-shot on the quick case set (2.10)", "",
             "Device {}, load {:.1f} s, {:.0f} ms per case (median, two questions in one pass).".format(
                 device, load_s, 1000 * statistics.median(walls)), "",
             "| Question | AUC malicious vs benign | Malicious ≥ 0.5 | Benign ≥ 0.5 |", "|---|---|---|---|"]
    for key, label in (("p_noul", "yes/no: is this an attack?"), ("p_choice", "choice: attack or normal")):
        pos = [r[key] for r in mal if r[key] is not None]
        neg = [r[key] for r in ben if r[key] is not None]
        lines.append("| {} | {} | {}/{} | {}/{} |".format(label, round(auc(pos, neg) or 0, 3), sum(p >= 0.5 for p in pos),
                                                          len(pos), sum(p >= 0.5 for p in neg), len(neg)))
    save_text("score_laya.md", "\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
