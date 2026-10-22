"""2.11 Decision matrix: speed on the target, timeliness it buys, accuracy, gates.

Inputs: out/bench_speed.jsonl (2.9), out/score_models_quick.json (2.10),
out/attack_tempo.json (2.3) and a Mac-to-target speed factor taken from published
llama.cpp figures for an 8-core x86 desktop (see FINDINGS.md, 2.9).

Target decision time = case tokens / (Mac prompt speed / factor) + verdict tokens
/ (Mac generation speed / factor), for today's case format (median ~480 tokens)
and for a compact 95th-percentile case (250 tokens), in two scenarios:

  typical       a modern 8-core desktop or laptop: prompts about as fast as the Mac
                CPU (Q4_K kernels are relatively slow on Apple CPUs), writing 1.7x slower
  conservative  an older chip, or "8 cores" that are 8 virtual CPUs: prompts 2x
                slower, writing 3x slower

Expected timeliness = the mean tempo curve (2.3) at that delay. Gates are the ones
fixed in README.md before measuring; the speed gate uses the conservative scenario.

    .venv/bin/python research/decide.py
"""

from __future__ import annotations

import argparse
import bisect
import json
import os

from common import OUT, save_json, save_text

VERDICT_TOKENS = 10            # {"verdict": "attack"} in most tokenizers
COMPACT_TOKENS = 250            # a 95th-percentile case once the format is made compact (2.6)
MEMORY_GATE_MB = 8192
DELAY_GATE_S = 5.0


def tempo_curve() -> tuple[list[float], list[float]]:
    t = json.load(open(os.path.join(OUT, "attack_tempo.json"), encoding="utf-8"))
    xs = [float(d) for d in t["delays_s"]]
    return xs, [t["summary"][str(d)]["mean"] for d in t["delays_s"]]


def interp(xs: list[float], ys: list[float], x: float) -> float:
    if x <= xs[0]:
        return ys[0]
    if x >= xs[-1]:
        return ys[-1]
    i = bisect.bisect_right(xs, x)
    x0, x1, y0, y1 = xs[i - 1], xs[i], ys[i - 1], ys[i]
    return y0 + (y1 - y0) * (x - x0) / (x1 - x0)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--typical", default="1.0,1.7", help="prompt,generation slow-down of a typical target vs the Mac CPU")
    ap.add_argument("--conservative", default="2.0,3.0", help="the same for a weak target")
    args = ap.parse_args()
    scen = {"typical": tuple(map(float, args.typical.split(","))), "conservative": tuple(map(float, args.conservative.split(",")))}
    xs, ys = tempo_curve()
    speed = {r["model"]: r for r in map(json.loads, open(os.path.join(OUT, "bench_speed.jsonl"), encoding="utf-8"))}
    def load(round_name: str) -> dict:
        path = os.path.join(OUT, "score_models_{}.json".format(round_name))
        return {s["model"]: s for s in json.load(open(path, encoding="utf-8"))} if os.path.exists(path) else {}
    acc, acc_v1 = load("quick"), load("quickv1")
    rows = []
    for name, r in speed.items():
        case_tokens = sorted(r["case_tokens"])[len(r["case_tokens"]) // 2]
        times = {}
        for sname, (fp, ft) in scen.items():
            pp, tg = r["pp512_tps"] / fp, r["tg32_tps"] / ft
            times[sname] = (case_tokens / pp + VERDICT_TOKENS / tg, COMPACT_TOKENS / pp + VERDICT_TOKENS / tg)
        t_now, t_compact = times["conservative"]
        a = acc.get(name, {}).get("all", {})
        o = acc.get(name, {}).get("type_other", {})
        row = {
            "model": name, "params_b": r["params_b"], "memory_mb": r["rss_after_mb"],
            "typical_now_s": round(times["typical"][0], 1), "typical_compact_s": round(times["typical"][1], 1),
            "decision_s_now": round(t_now, 1), "decision_s_compact": round(t_compact, 1),
            "timeliness_typical_compact": round(interp(xs, ys, times["typical"][1]), 2),
            "timeliness_now": round(interp(xs, ys, t_now), 2), "timeliness_compact": round(interp(xs, ys, t_compact), 2),
            "attacks_any": "{}/{}".format(a.get("attack_any_case_flagged"), a.get("attacks")) if a else None,
            "attacks_first": "{}/{}".format(a.get("attack_first_case_flagged"), a.get("attacks")) if a else None,
            "other_types": "{}/{}".format(o.get("any_case_flagged"), o.get("attacks")) if o else None,
            "benign_flagged": "{}/{}".format(a.get("benign_flagged"), a.get("benign_cases")) if a else None,
            "auc": a.get("auc"), "invalid": acc.get(name, {}).get("invalid"),
        }
        v1 = acc_v1.get(name, {}).get("all", {})
        row["v1"] = ("{} · {}/{} · {}".format(v1.get("attack_first_case_flagged"), v1.get("benign_flagged"),
                                            v1.get("benign_cases"), v1.get("auc")) if v1 else "–")
        row["gate_speed"] = t_compact <= DELAY_GATE_S
        row["gate_memory"] = r["rss_after_mb"] <= MEMORY_GATE_MB
        row["gate_valid"] = (row["invalid"] or 0) <= 0.01 * max(1, acc.get(name, {}).get("n", 1))
        rows.append(row)
    rows.sort(key=lambda r: r["decision_s_compact"])
    save_json("decide.json", {"scenarios": scen, "rows": rows})
    lines = ["# Decision matrix (2.11)", "",
             "Decision on the target = reading the case + a {}-token verdict. Typical target: Mac CPU speed / {} (prompt) "
             "and / {} (writing); conservative: / {} and / {}. Today's cases ≈ 480 tokens; compact = {} tokens. "
             "Timeliness = mean tempo curve (2.3) at that delay.".format(VERDICT_TOKENS, *scen["typical"], *scen["conservative"], COMPACT_TOKENS), "",
             "| Model | Params (B) | Memory (MB) | Decision, compact case: typical · conservative (s) | Timeliness typical · conservative | Today's case, conservative (s) | Attacks any · first | Other types | Benign flagged | AUC | Prompt v1: first · benign · AUC | Gates speed · memory · valid |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append("| {} | {} | {} | {} · {} | {} · {} | {} | {} · {} | {} | {} | {} | {} | {} · {} · {} |".format(
            r["model"], r["params_b"], r["memory_mb"], r["typical_compact_s"], r["decision_s_compact"],
            r["timeliness_typical_compact"], r["timeliness_compact"], r["decision_s_now"], r["attacks_any"], r["attacks_first"],
            r["other_types"], r["benign_flagged"], r["auc"], r["v1"],
            *("pass" if r[g] else "FAIL" for g in ("gate_speed", "gate_memory", "gate_valid"))))
    save_text("decide.md", "\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
