"""2.10 Accuracy on labelled cases: every model, the same neutral prompt, the same cases.

Accuracy does not depend on the hardware, so models run on the Mac GPU here to
save time; speed is measured separately on the CPU (bench_speed.py).

  quick  every candidate: all malicious and context cases of dev + holdout, every
         benign case from the waves, and a fixed sample of benign window cases.
         Verdict and confidence only.
  full   the leaders: every dev + holdout case, with the one-sentence reason.

Eval-wave cases are never scored here: they stay unseen for the final check.

    .venv/bin/python research/score_models.py quick [model ...]

Per-case results: data/cache/research/scores/<model>.<round>.jsonl.
Summary: research/out/score_models_<round>.md and .json.
"""

from __future__ import annotations

import json
import os
import random
import statistics
import sys
import time
from collections import defaultdict

from candidates import CANDIDATES, UNSUPPORTED, ready
from common import OUT, ROOT, save_json, save_text
from llm import MODELS, Server
import prompt_v0
import prompt_v1
from prompt_v0 import GRAMMAR_FULL, GRAMMAR_QUICK

PROMPTS = {"quick": prompt_v0, "full": prompt_v0, "quickv1": prompt_v1}    # round -> prompt module

CASES = os.path.join(ROOT, "data", "cache", "research", "cases.jsonl")
SCORES = os.path.join(ROOT, "data", "cache", "research", "scores")
WINDOW_BENIGN_SAMPLE = 90


def case_set(round_name: str) -> list[dict]:
    cases = [json.loads(line) for line in open(CASES, encoding="utf-8")]
    cases = [c for c in cases if c["split"] in ("dev", "holdout")]
    if round_name == "full":
        return cases                                # every dev and holdout case
    keep = [c for c in cases if c["label"] != "benign" or c["source"] == "wave"]
    window_benign = sorted((c for c in cases if c["label"] == "benign" and c["source"] == "window"), key=lambda c: c["case_id"])
    keep += random.Random("quick-set").sample(window_benign, min(WINDOW_BENIGN_SAMPLE, len(window_benign)))
    return sorted(keep, key=lambda c: (c["wave"], c["ts"]))


def attack_score(c: dict, r: dict) -> float:
    """Confidence that the case is an attack, 0-100, from the verdict and its confidence."""
    p = r.get("parsed") or {}
    conf = p.get("confidence", 50)
    return conf if p.get("verdict") == "attack" else 100 - conf


def auc(pos: list[float], neg: list[float]) -> float | None:
    if not pos or not neg:
        return None
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def attack_types() -> dict:
    """attack_id -> 'WMI' or 'other', from the attack catalogue (2.2)."""
    rows = json.load(open(os.path.join(OUT, "attack_catalogue.json"), encoding="utf-8"))
    return {r["attack_id"]: ("WMI" if (r["alert_point"] or {}).get("parent") == "wmiprvse.exe" else "other") for r in rows}


def summarize(name: str, rows: list[dict]) -> dict:
    flagged = lambda r: (r.get("parsed") or {}).get("verdict") == "attack"  # noqa: E731
    out = {"model": name, "n": len(rows), "invalid": sum(1 for r in rows if not r.get("parsed"))}
    for split in ("dev", "holdout", "all"):
        rs = [r for r in rows if split == "all" or r["split"] == split]
        mal = [r for r in rs if r["label"] == "malicious"]
        ben = [r for r in rs if r["label"] == "benign"]
        by_attack = defaultdict(list)
        for r in mal:
            by_attack[(r["wave"], r["attack_id"])].append(r)
        first_hit = [sorted(v, key=lambda r: r["ts"])[0] for v in by_attack.values()]
        out[split] = {
            "attacks": len(by_attack),
            "attack_first_case_flagged": sum(flagged(r) for r in first_hit),
            "attack_any_case_flagged": sum(any(flagged(r) for r in v) for v in by_attack.values()),
            "malicious_cases": len(mal), "malicious_flagged": sum(flagged(r) for r in mal),
            "benign_cases": len(ben), "benign_flagged": sum(flagged(r) for r in ben),
            "benign_wave_cases_flagged": sum(flagged(r) for r in ben if r["source"] == "wave"),
            "auc": round(auc([attack_score(r, r) for r in mal], [attack_score(r, r) for r in ben]) or 0, 3),
        }
    types = attack_types()
    by_attack = defaultdict(list)
    for r in rows:
        if r["label"] == "malicious":
            by_attack[(r["wave"], r["attack_id"])].append(r)
    for kind in ("WMI", "other"):
        groups = [v for (w, aid), v in by_attack.items() if types.get(aid) == kind]
        out["type_" + kind] = {"attacks": len(groups), "any_case_flagged": sum(any(flagged(r) for r in v) for v in groups),
                               "first_case_flagged": sum(flagged(sorted(v, key=lambda r: r["ts"])[0]) for v in groups)}
    walls = [r["wall_s"] for r in rows if r.get("wall_s")]
    out["gpu_s_per_case_median"] = round(statistics.median(walls), 3) if walls else None
    out["prompt_tokens_median"] = statistics.median([r["prompt_tokens"] for r in rows if r.get("prompt_tokens")] or [0])
    return out


def run_model(name: str, gguf: str, cases: list[dict], round_name: str) -> list[dict]:
    path = os.path.join(SCORES, "{}.{}.jsonl".format(name.replace(" ", "_"), round_name))
    done = {}
    if os.path.exists(path):
        done = {json.loads(line)["case_id"]: json.loads(line) for line in open(path, encoding="utf-8")}
    todo = [c for c in cases if c["case_id"] not in done]
    if todo:
        srv = Server(gguf, cpu=False)
        try:
            srv.wait()
            grammar, max_tokens = (GRAMMAR_FULL, 110) if round_name == "full" else (GRAMMAR_QUICK, 24)
            messages = PROMPTS[round_name].messages
            t0 = time.perf_counter()
            with open(path, "a", encoding="utf-8") as fh:
                for i, c in enumerate(todo, 1):
                    try:
                        r = srv.chat(messages(c["text"]), max_tokens=max_tokens, grammar=grammar)
                    except Exception as exc:  # noqa: BLE001 -- an invalid verdict, not a crash
                        r = {"text": "ERROR " + str(exc), "parsed": None, "wall_s": None, "prompt_tokens": None}
                    row = {k: c[k] for k in ("case_id", "split", "source", "wave", "label", "attack_id", "is_alert_point", "ts", "kind")}
                    row.update({k: r.get(k) for k in ("text", "parsed", "wall_s", "prompt_tokens")})
                    fh.write(json.dumps(row) + "\n")
                    done[c["case_id"]] = row
                    if i % 50 == 0:
                        print("  {} {}/{} cases, {:.0f} s".format(name, i, len(todo), time.perf_counter() - t0), flush=True)
        finally:
            srv.stop()
    return [done[c["case_id"]] for c in cases if c["case_id"] in done]


def report(round_name: str, summaries: list[dict]) -> None:
    save_json("score_models_{}.json".format(round_name), summaries)
    lines = ["# Accuracy on labelled cases (2.10) · round: {}".format(round_name), "",
             "Neutral prompt (prompt_v0.py), JSON verdict, temperature 0. Dev + holdout cases; eval cases unseen.", "",
             "| Model | Attacks: first case flagged | Any case flagged | Other-type attacks (any) | Malicious cases flagged | Benign cases flagged | of them in waves | AUC | Invalid |",
             "|---|---|---|---|---|---|---|---|---|"]
    for s in sorted(summaries, key=lambda s: (-s["all"]["attack_first_case_flagged"], s["all"]["benign_flagged"])):
        a = s["all"]
        o = s["type_other"]
        lines.append("| {} | {}/{} | {}/{} | {}/{} | {}/{} | {}/{} | {} | {} | {} |".format(
            s["model"], a["attack_first_case_flagged"], a["attacks"], a["attack_any_case_flagged"], a["attacks"],
            o["any_case_flagged"], o["attacks"], a["malicious_flagged"], a["malicious_cases"], a["benign_flagged"],
            a["benign_cases"], a["benign_wave_cases_flagged"], a["auc"], s["invalid"]))
    save_text("score_models_{}.md".format(round_name), "\n".join(lines) + "\n")
    print("\n".join(lines))


def main() -> None:
    round_name = sys.argv[1] if len(sys.argv) > 1 else "quick"
    wanted = set(sys.argv[2:])
    os.makedirs(SCORES, exist_ok=True)
    cases = case_set(round_name)
    print("{} cases in round {}".format(len(cases), round_name), flush=True)
    for name, gguf, *_ in CANDIDATES:
        if (wanted and name not in wanted) or not ready(gguf) or name in UNSUPPORTED:
            continue
        print("score", name, flush=True)
        try:
            run_model(name, gguf, cases, round_name)
        except Exception as exc:  # noqa: BLE001 -- the next model still runs
            print("  failed:", exc, flush=True)
    summaries = []                                     # every model scored so far in this round, not just this call
    ids = {c["case_id"] for c in cases}
    for name, *_ in CANDIDATES:
        path = os.path.join(SCORES, "{}.{}.jsonl".format(name.replace(" ", "_"), round_name))
        if os.path.exists(path):
            rows = [r for r in map(json.loads, open(path, encoding="utf-8")) if r["case_id"] in ids]
            if len(rows) == len(ids):
                summaries.append(summarize(name, rows))
    report(round_name, summaries)


if __name__ == "__main__":
    main()
