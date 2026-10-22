"""Replay waves through the detector's own state and triage, offline: coverage, volume and case size.

Checks the production code against what research measured (research/FINDINGS.md 2.5,
2.6) before any real-time run: does triage still turn every alert point into a case,
how many cases does a normal machine produce, and how long is a case now. With
--score it also asks the model for a verdict on every case (the detector's own
prompt and grammar) and reports what the detector would flag.

    python tools/replay_cases.py                       # validation (dev + holdout) and eval waves
    python tools/replay_cases.py --score --split dev   # plus model verdicts on the dev cases

Writes data/cache/detector/cases.jsonl (and verdicts.jsonl with --score).
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import statistics
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "evaluator"))
from submission import cases, config, prompts  # noqa: E402
from submission.baseline import Fleet, Triage  # noqa: E402
from submission.state import MachineState  # noqa: E402

VAL = os.path.join(ROOT, "data", "cache", "val")
EVAL = os.path.join(ROOT, "data", "eval")
EVAL_ANSWERS = os.path.join(ROOT, "data", "cache", "eval_answers.json")
OUT = os.path.join(ROOT, "data", "cache", "detector")


def stream(path: str):
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            yield json.loads(line)


def wave_cases(data_dir: str, wave: dict, answer: dict, split: str, fleet: Fleet) -> tuple[list[dict], dict]:
    state, triage = MachineState(wave["machine"]), Triage(wave["machine"], fleet)
    for ev in stream(os.path.join(data_dir, wave["wave_id"], "warmup.stream")):
        triage.observe(ev, state.add(ev))
    triage.live = True
    mal, ctx = set(answer["malicious_event_ids"]), set(answer.get("context_event_ids") or [])
    alert_points = {a["first_alertable_event_id"]: a["attack_id"] for a in answer.get("attacks") or []}
    attack_of = answer.get("event_attack") or {}
    out, first_minute, last = [], None, None
    for ev in stream(os.path.join(data_dir, wave["wave_id"], "live.stream")):
        t = state.add(ev)
        first_minute = first_minute or t
        last = t
        cand = triage.observe(ev, t)
        if cand is None:
            continue
        eid = ev["id"]
        out.append({"wave": wave["wave_id"], "machine": wave["machine"], "split": split, "event_id": eid,
                    "kind": cand.kind, "pair": cand.pair, "fleet": cand.fleet,
                    "label": "malicious" if eid in mal else "context" if eid in ctx else "benign",
                    "attack_id": attack_of.get(eid), "alert_point": eid in alert_points,
                    "text": cases.render(state, cand)})
    minutes = max((last or 0) - (first_minute or 0), 1) / 60
    attacks = {a["attack_id"]: any(c["event_id"] == a["first_alertable_event_id"] for c in out)
               for a in answer.get("attacks") or []}
    return out, {"wave": wave["wave_id"], "split": split, "attack": bool(answer.get("attack")),
                 "per_min": len(out) / minutes, "alert_point_kept": attacks}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--score", action="store_true", help="ask the model for a verdict on every case")
    ap.add_argument("--split", default="dev", help="which split to score: dev, holdout or eval")
    args = ap.parse_args()
    fleet = Fleet(config.FLEET_FILE)
    all_cases, waves = [], []
    for data_dir, answers_path in ((VAL, os.path.join(VAL, "answers.json")), (EVAL, EVAL_ANSWERS)):
        with open(os.path.join(data_dir, "waves.json"), encoding="utf-8") as fh:
            wl = json.load(fh)["waves"]
        with open(answers_path, encoding="utf-8") as fh:
            ans = json.load(fh)["waves"]
        for w in wl:
            split = "eval" if data_dir == EVAL else ("dev" if "dev" in w["sets"] else "holdout")
            cs, info = wave_cases(data_dir, w, ans[w["wave_id"]], split, fleet)
            all_cases += cs
            waves.append(info)
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "cases.jsonl"), "w", encoding="utf-8") as fh:
        for c in all_cases:
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")

    print("Triage coverage and volume (production code)")
    for split in ("dev", "holdout", "eval"):
        ws = [w for w in waves if w["split"] == split]
        kept = [v for w in ws for v in w["alert_point_kept"].values()]
        benign = sorted(w["per_min"] for w in ws if not w["attack"])
        attack = sorted(w["per_min"] for w in ws if w["attack"])
        print("  {:8} waves {:2}  alert points kept {}/{}  cases/min benign median {:.2f} max {:.2f}  attack median {:.2f}".format(
            split, len(ws), sum(kept), len(kept), statistics.median(benign) if benign else 0, max(benign or [0]),
            statistics.median(attack) if attack else 0))
    chars = sorted(len(c["text"]) for c in all_cases)
    print("Case length, characters: median {} p95 {} max {}  (~{} / {} / {} tokens at 3.5 chars per token)".format(
        chars[len(chars) // 2], chars[int(0.95 * len(chars))], chars[-1],
        chars[len(chars) // 2] * 2 // 7, chars[int(0.95 * len(chars))] * 2 // 7, chars[-1] * 2 // 7))
    missed = [(w["wave"], a) for w in waves for a, ok in w["alert_point_kept"].items() if not ok]
    print("Alert points that are not cases:", missed or "none")
    if args.score:
        score(all_cases, args.split)


def score(all_cases: list[dict], split: str) -> None:
    from submission.engine import parse_verdict
    from submission.llm import VERDICT_SLOT, LlamaServer
    sel = [c for c in all_cases if c["split"] == split]
    server = LlamaServer(config.find_server(), config.find_model(config.MODEL_FILE))
    server.start()
    t0, rows = time.perf_counter(), []
    try:
        for c in sel:
            out = server.chat(prompts.verdict_messages(c["text"]), 16, VERDICT_SLOT, prompts.VERDICT_GRAMMAR)
            verdict, conf = parse_verdict(out["text"])
            rows.append({**{k: c[k] for k in ("wave", "event_id", "label", "attack_id", "alert_point", "fleet", "kind")},
                         "verdict": verdict, "confidence": conf, "s": round(out["wall_s"], 3), "prompt_n": out["prompt_n"]})
    finally:
        server.stop()
    with open(os.path.join(OUT, "verdicts-{}.jsonl".format(split)), "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    flag = lambda r: r["verdict"] == "attack" and r["confidence"] >= config.ALERT_MIN_CONFIDENCE  # noqa: E731
    attacks = {}
    for r in rows:
        if r["label"] == "malicious":
            attacks.setdefault((r["wave"], r["attack_id"]), []).append(r)
    first = sum(1 for rs in attacks.values() if flag(rs[0]))
    anyc = sum(1 for rs in attacks.values() if any(flag(r) for r in rs))
    benign = [r for r in rows if r["label"] == "benign"]
    secs = sorted(r["s"] for r in rows)
    toks = sorted(r["prompt_n"] or 0 for r in rows)
    print("Model verdicts on {} {} cases in {:.0f}s".format(len(rows), split, time.perf_counter() - t0))
    print("  attacks flagged at their first case {}/{}, at any case {}/{}".format(first, len(attacks), anyc, len(attacks)))
    print("  benign cases flagged {}/{}  waves with a benign flag: {}".format(
        sum(1 for r in benign if flag(r)), len(benign), len({r["wave"] for r in benign if flag(r)})))
    print("  seconds per verdict median {:.2f} p95 {:.2f}; new prompt tokens median {} p95 {}".format(
        secs[len(secs) // 2], secs[int(0.95 * len(secs))], toks[len(toks) // 2], toks[int(0.95 * len(toks))]))


if __name__ == "__main__":
    main()
