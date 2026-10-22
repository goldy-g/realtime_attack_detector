"""2.9 Speed on the CPU: raw throughput and the real cost of one decision.

For each model, CPU only (no Metal, no Accelerate device), 8 threads:
  1. llama-bench: prompt processing over 512 tokens and generation of 32 tokens.
  2. llama-server: load time, resident memory, and decisions on four real cases
     with the fixed prompt (prompt_v0.py). The first call reads the whole prompt;
     the next ones reuse the cached system prefix, as a running detector would.
     A verdict-only reply is what an alert needs; one full reply with a reason
     shows the extra cost of a sentence.

    .venv/bin/python research/bench_speed.py [model name ...]

Appends to research/out/bench_speed.jsonl (one line per model) and rewrites bench_speed.md.
"""

from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys

from candidates import CANDIDATES, UNSUPPORTED, ready
from common import OUT, ROOT, save_text
from llm import MODELS, Server
from prompt_v0 import GRAMMAR_FULL, GRAMMAR_VERDICT, messages

CASES = os.path.join(ROOT, "data", "cache", "research", "cases.jsonl")
RESULTS = os.path.join(OUT, "bench_speed.jsonl")


def sample_cases() -> list[dict]:
    """Four dev cases: an encoded-PowerShell alert point, two median-size benign processes, one benign flow."""
    cases = [json.loads(line) for line in open(CASES, encoding="utf-8")]
    dev = [c for c in cases if c["split"] == "dev" and c["source"] == "wave"]
    med = statistics.median(c["chars"] for c in dev)
    alert = next(c for c in dev if c["is_alert_point"] and "Decoded -EncodedCommand" in c["text"])
    procs = sorted((c for c in dev if c["label"] == "benign" and c["kind"] == "process"), key=lambda c: abs(c["chars"] - med))[:2]
    flow = sorted((c for c in dev if c["label"] == "benign" and c["kind"] == "flow"), key=lambda c: abs(c["chars"] - med))[0]
    return [alert] + procs + [flow]


def llama_bench(gguf: str) -> dict:
    out = subprocess.run(["llama-bench", "-m", os.path.join(MODELS, gguf), "-ngl", "0", "-dev", "none", "-t", "8",
                          "-p", "512", "-n", "32", "-r", "2", "-o", "json"], capture_output=True, text=True, timeout=1800)
    rows = json.loads(out.stdout)
    res = {"params_b": round(rows[0]["model_n_params"] / 1e9, 2), "size_gb": round(rows[0]["model_size"] / 1e9, 2),
           "model_type": rows[0]["model_type"]}
    for r in rows:
        key = "pp512" if r["n_prompt"] else "tg32"
        res[key + "_tps"] = round(r["avg_ts"], 1)
    return res


def bench(name: str, gguf: str, cases: list[dict]) -> dict:
    row = {"model": name, "file": gguf}
    row.update(llama_bench(gguf))
    srv = Server(gguf, cpu=True)
    try:
        row["load_s"] = round(srv.wait(), 2)
        row["rss_loaded_mb"] = round(srv.rss_mb())
        calls = []
        for i, c in enumerate(cases):
            r = srv.chat(messages(c["text"]), max_tokens=16, grammar=GRAMMAR_VERDICT)
            calls.append({"case": c["case_id"], "warm": i > 0, **{k: r[k] for k in
                          ("wall_s", "prompt_n", "prompt_ms", "predicted_n", "predicted_ms", "cache_n", "prompt_tokens")},
                          "verdict": (r["parsed"] or {}).get("verdict")})
        full = srv.chat(messages(cases[0]["text"]), max_tokens=110, grammar=GRAMMAR_FULL)
        row["full_reply"] = {k: full[k] for k in ("wall_s", "prompt_n", "predicted_n", "predicted_ms")}
        row["full_reply"]["text"] = full["text"]
        row["system_tokens"] = srv.tokens(messages("")[0]["content"])
        row["case_tokens"] = [srv.tokens(c["text"]) for c in cases]
        row["rss_after_mb"] = round(srv.rss_mb())
    finally:
        srv.stop()
    row["calls"] = calls
    warm = [c["wall_s"] for c in calls if c["warm"]]
    row["decision_warm_s_median"] = round(statistics.median(warm), 2)
    row["decision_cold_s"] = round(calls[0]["wall_s"], 2)
    return row


def report() -> None:
    rows = [json.loads(line) for line in open(RESULTS, encoding="utf-8")]
    lines = ["# CPU speed (2.9)", "",
             "Apple M5 Pro CPU only, 8 threads, llama.cpp build 11669. Decision = verdict-only JSON on a real case "
             "after the system prompt is cached (median of three); cold = first call, whole prompt.", "",
             "| Model | Params (B) | File (GB) | Prompt t/s | Gen t/s | Load (s) | Memory (MB) | Case tokens | Decision warm (s) | Cold (s) | + reason (s) |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda r: r["decision_warm_s_median"]):
        lines.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            r["model"], r["params_b"], r["size_gb"], r.get("pp512_tps"), r.get("tg32_tps"), r["load_s"],
            r["rss_after_mb"], "/".join(str(x) for x in r["case_tokens"]), r["decision_warm_s_median"],
            r["decision_cold_s"], round(r["full_reply"]["wall_s"], 2)))
    save_text("bench_speed.md", "\n".join(lines) + "\n")
    print("\n".join(lines))


def main() -> None:
    wanted = set(sys.argv[1:])
    cases = sample_cases()
    done = set()
    if os.path.exists(RESULTS):
        done = {json.loads(line)["model"] for line in open(RESULTS, encoding="utf-8")}
    for name, gguf, *_ in CANDIDATES:
        if (wanted and name not in wanted) or name in done or not ready(gguf) or name in UNSUPPORTED:
            continue
        print("bench", name, flush=True)
        try:
            row = bench(name, gguf, cases)
        except Exception as exc:  # noqa: BLE001 -- recorded, the next model still runs
            row = None
            print("  failed:", exc, flush=True)
        if row:
            with open(RESULTS, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(row) + "\n")
            print("  warm decision {} s, pp {} t/s, tg {} t/s".format(row["decision_warm_s_median"], row["pp512_tps"], row["tg32_tps"]), flush=True)
    report()


if __name__ == "__main__":
    main()
