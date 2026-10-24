"""Specialist-prompt test for the Remote Desktop hop: can the SLM itself catch it? Offline, nothing in submission/ changes.

Idea: code only routes. An outbound connection to port 3389 goes to a lateral-movement
specialist prompt with worked examples from the training days, cached in its own slot;
the SLM still makes the decision. Variants, all with Gemma 4 E4B, the detector's own case
text (submission/cases.py), reply grammar and temperature 0:

    P0  the submitted verdict prompt (v1.5), no examples
    S0  the specialist prompt, no examples
    S   the specialist prompt + 4 worked examples (2 attack, 2 normal)
    C   the submitted verdict prompt + the same 4 examples (one prompt for every case)

Worked examples come from the training days only. The training days hold 16 outbound
Remote Desktop connections from mstsc.exe: 2 attack hops on host-339f (a session that
came in through a local tunnel) and 14 scripted benign ones (`mstsc.exe /f /v:<ip>`),
7 on host-339f and 7 on host-efdb. Both attack examples are host-339f's hops. The normal
examples come from one machine, and that machine's benign connections are left out of
the test (demo set A: host-339f's, testing host-efdb's 7; set B: the reverse).

Test items: eval w01's hop (the only Remote Desktop case in the 203 dev, holdout and eval
cases); three probes of w01 that remove one cue at a time, because the training data cannot
tell the cues apart (both attack examples and w01 run as `sysadmin`, started by hand from the
desktop in a session that came in by Remote Desktop; every benign example is a scripted
`mstsc.exe /f /v:` under a named user from a local session): no session lines, the account
renamed, and both; the benign connections of the held-out machine; and, for S-A and C-A,
the full case set in data/cache/detector/cases.jsonl (S-A: benign cases only, as a stress
test, since the router sends no other case there; C-A: every case, since C would judge them all).

    python research/specialist_rdp.py            # writes research/out/specialist_rdp.{md,json}
    python research/specialist_rdp.py --model fallback --small   # P0 and S0 with Gemma 4 E2B -> specialist_rdp_e2b.*
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
from submission import config, prompts  # noqa: E402
from submission.baseline import Candidate, Fleet  # noqa: E402
from submission.cases import render  # noqa: E402
from submission.engine import parse_verdict  # noqa: E402
from submission.llm import VERDICT_SLOT, LlamaServer  # noqa: E402
from submission.state import MachineState, base  # noqa: E402

TRAIN = os.path.join(ROOT, "data", "train")
CASES = os.path.join(ROOT, "data", "cache", "detector", "cases.jsonl")
OUT = os.path.join(ROOT, "research", "out")
RDP_MACHINES = ("host-339f", "host-efdb")

SPECIALIST_SYSTEM = """You are a security analyst reviewing outbound Remote Desktop connections on Windows workstations in real time.

A triage step has flagged one connection to port 3389 because the program had not used that port in the machine's last hour. You see the connection, the processes behind it, how the desktop session that made it began, and the machine's recent activity. Decide whether it is lateral movement by an intruder or normal remote administration.

What matters most is how the desktop session making the connection began:
- A session that itself arrived by Remote Desktop, from another machine or through a local tunnel (a Remote Desktop logon from the machine itself), and now opens Remote Desktop to yet another machine forms a chain of hops. Intruders with stolen credentials move this way, one machine after the next.
- A connection from a session that began at the machine itself is usually administration: help desk, IT staff, or scripts that connect with fixed arguments.

How the program was started, by a script or by a person at the desktop, does not decide on its own. Tunnelling tools, credential theft or new accounts shortly before make an attack more likely.

Reply with the verdict, attack or normal, then a space and your confidence from 0 to 100. Nothing else."""


def is_rdp_out(ev: dict) -> bool:
    p = ev.get("properties") or {}
    return (ev.get("object") == "FLOW" and ev.get("action") == "START" and p.get("dest_port") == "3389"
            and p.get("direction") == "outbound" and base(p.get("image_path")) == "mstsc.exe")


def training_rdp_cases() -> list[dict]:
    """Every outbound mstsc.exe -> 3389 connection on the training days, rendered as the detector renders a case."""
    fleet, out = Fleet(config.FLEET_FILE), []
    for m in RDP_MACHINES:
        with gzip.open(os.path.join(TRAIN, m + ".labels.json.stream"), "rt", encoding="utf-8") as fh:
            labels = json.load(fh)
        mal, ctx = set(labels.get("malicious_event_ids") or []), set(labels.get("context_event_ids") or [])
        state = MachineState(m)
        with gzip.open(os.path.join(TRAIN, m + ".events.jsonl.stream"), "rt", encoding="utf-8") as fh:
            for raw in fh:
                ev = json.loads(raw)
                t = state.add(ev)
                if not is_rdp_out(ev):
                    continue
                key = ("mstsc.exe", "3389")
                cand = Candidate(ev, "flow", key, fleet.count(fleet.flows, key, m), fleet.others(m), t)
                eid = ev["id"]
                out.append({"item": "{} {}".format(m, ev["timestamp"][11:19]), "machine": m, "event_id": eid,
                            "label": "malicious" if eid in mal else "context" if eid in ctx else "benign",
                            "text": render(state, cand)})
    return out


def strip_session(text: str) -> str:
    return "\n".join(ln for ln in text.split("\n")
                     if not ln.startswith(("Its desktop session began", "Remote Desktop chain:")))


def rename_account(text: str) -> str:
    return text.replace("sysadmin", "mrivera")


def demo_turns(attacks: list[dict], normals: list[dict]) -> list[dict]:
    """Worked examples as earlier chat turns, attack and normal alternating, a normal one last."""
    turns = []
    for a, n in zip(attacks, normals):
        turns += [{"role": "user", "content": a["text"]}, {"role": "assistant", "content": "attack 90"},
                  {"role": "user", "content": n["text"]}, {"role": "assistant", "content": "normal 90"}]
    return turns


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--model", default="main", choices=("main", "fallback"), help="Gemma 4 E4B or the E2B fallback")
    ap.add_argument("--small", action="store_true", help="only P0 and S0 on the Remote Desktop items")
    args = ap.parse_args()
    suffix = "" if args.model == "main" else "_e2b"
    train = training_rdp_cases()
    attacks = [c for c in train if c["label"] == "malicious"]
    benign = {m: [c for c in train if c["machine"] == m and c["label"] == "benign"] for m in RDP_MACHINES}
    assert len(attacks) == 2 and all(len(v) == 7 for v in benign.values()), (len(attacks), {k: len(v) for k, v in benign.items()})
    with open(CASES, encoding="utf-8") as fh:
        cases = [json.loads(ln) for ln in fh]
    w01 = [c for c in cases if c["wave"] == "w01" and c.get("alert_point")]
    assert len(w01) == 1 and "3389" in w01[0]["text"]
    w01 = {"item": "eval w01 hop", "machine": "host-83fa", "event_id": w01[0]["event_id"], "label": "malicious",
           "text": w01[0]["text"]}
    # Probes: the attack examples and w01 share the account (sysadmin) and the launch (explorer.exe, no arguments),
    # while every benign example is a scripted `mstsc.exe /f /v:` under a named user, so remove one cue at a time.
    probes = [{**w01, "item": "w01 probe: no session lines", "label": "probe", "text": strip_session(w01["text"])},
              {**w01, "item": "w01 probe: account renamed", "label": "probe", "text": rename_account(w01["text"])},
              {**w01, "item": "w01 probe: both", "label": "probe", "text": rename_account(strip_session(w01["text"]))}]
    routed = [c for c in cases if c["kind"] == "flow" and '"3389"' in json.dumps(c["pair"])]

    # Demo sets: both attack hops; two normal examples from one machine, one before the attack and one after.
    norm_a = [benign["host-339f"][0], benign["host-339f"][3]]          # 12:25:16 and 13:51:27
    norm_b = [benign["host-efdb"][0], benign["host-efdb"][4]]          # 01:20:18 and 09:38:11
    demos = {"A": demo_turns(attacks, norm_a), "B": demo_turns(attacks, norm_b)}
    held_out = {"A": benign["host-efdb"], "B": benign["host-339f"]}

    small_all = attacks + benign["host-339f"] + benign["host-efdb"] + [w01] + probes
    runs = [  # (variant, demo set, system prompt, demo turns, items)
        ("P0", "-", prompts.VERDICT_SYSTEM, [], small_all),
        ("S0", "-", SPECIALIST_SYSTEM, [], small_all),
        ("S", "A", SPECIALIST_SYSTEM, demos["A"], [w01] + probes + held_out["A"]),
        ("S", "B", SPECIALIST_SYSTEM, demos["B"], [w01] + probes + held_out["B"]),
        ("C", "A", prompts.VERDICT_SYSTEM, demos["A"], [w01] + probes + held_out["A"]),
        ("C", "B", prompts.VERDICT_SYSTEM, demos["B"], [w01] + probes + held_out["B"]),
        ("S", "A full", SPECIALIST_SYSTEM, demos["A"],
         [dict(c, item="{} {}".format(c["split"], c["wave"])) for c in cases if c["label"] == "benign"]),
        ("C", "A full", prompts.VERDICT_SYSTEM, demos["A"],
         [dict(c, item="{} {}".format(c["split"], c["wave"])) for c in cases]),
    ]

    if args.small:
        runs = runs[:2]
    server = LlamaServer(config.find_server(),
                         config.find_model(config.MODEL_FILE if args.model == "main" else config.FALLBACK_MODEL_FILE))
    server.start()
    rows, t_start = [], time.perf_counter()
    try:
        for variant, dset, system, turns, items in runs:
            t0 = time.perf_counter()
            for it in items:
                msgs = [{"role": "system", "content": system}] + turns + [{"role": "user", "content": it["text"]}]
                out = server.chat(msgs, 16, VERDICT_SLOT, prompts.VERDICT_GRAMMAR)
                verdict, conf = parse_verdict(out["text"])
                rows.append({"variant": variant, "demos": dset, "item": it["item"], "event_id": it["event_id"],
                             "label": it["label"], "split": it.get("split", "train" if it["machine"] in RDP_MACHINES else "eval"),
                             "alert_point": bool(it.get("alert_point")), "attack_id": it.get("attack_id"),
                             "wave": it.get("wave"), "verdict": verdict, "confidence": conf,
                             "s": round(out["wall_s"], 3), "prompt_n": out["prompt_n"], "cache_n": out["cache_n"]})
            print("{} {:7} {:4} items in {:5.0f}s".format(variant, dset, len(items), time.perf_counter() - t0), flush=True)
    finally:
        server.stop()

    os.makedirs(OUT, exist_ok=True)
    meta = {"model": server.name, "routed_cases_in_case_set": [c["wave"] for c in routed],
            "demo_items": {"A": [c["item"] for c in attacks + norm_a], "B": [c["item"] for c in attacks + norm_b]},
            "demo_prefix_chars": {k: sum(len(t["content"]) for t in v) for k, v in demos.items()},
            "seconds": round(time.perf_counter() - t_start)}
    with open(os.path.join(OUT, "specialist_rdp{}.json".format(suffix)), "w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "rows": rows, "training_rdp_cases": train}, fh, ensure_ascii=False, indent=1)
    report(rows, meta, suffix)


def flagged(r: dict) -> bool:
    return r["verdict"] == "attack" and r["confidence"] >= config.ALERT_MIN_CONFIDENCE


def report(rows: list[dict], meta: dict, suffix: str = "") -> None:
    lines = ["# Specialist-prompt test for the Remote Desktop hop", "",
             "Generated by `research/specialist_rdp.py` with {} (offline, temperature 0, the detector's case text "
             "and reply grammar). Demo set A = both host-339f attack hops + two host-339f benign connections; "
             "set B = both attack hops + two host-efdb benign connections. Routed cases in the 203-case set: {}.".format(
                 meta["model"], ", ".join(meta["routed_cases_in_case_set"]) or "none"), "",
             "## Remote Desktop items", "", "| Variant | Demos | Item | Label | Verdict | s |", "|---|---|---|---|---|---|"]
    for r in rows:
        if "full" in r["demos"]:
            continue
        lines.append("| {} | {} | {} | {} | {} {} | {:.2f} |".format(r["variant"], r["demos"], r["item"], r["label"],
                                                                      r["verdict"], r["confidence"], r["s"]))
    lines += ["", "## Full case set", ""]
    for variant in ("S", "C"):
        rs = [r for r in rows if r["variant"] == variant and r["demos"] == "A full"]
        if not rs:
            continue
        ben = [r for r in rs if r["label"] == "benign"]
        fb = [r for r in ben if flagged(r)]
        lines.append("- {} with demo set A: benign cases flagged {}/{} ({}); median {:.2f} s per verdict, "
                     "median new prompt tokens {}.".format(
                         variant, len(fb), len(ben), ", ".join("{} {}".format(r["item"], r["verdict"] + " " + str(r["confidence"]))
                                                               for r in fb) or "none",
                         statistics.median(r["s"] for r in rs), statistics.median(r["prompt_n"] or 0 for r in rs)))
        firsts = {}
        for r in rs:
            if r["label"] == "malicious":
                firsts.setdefault((r["wave"], r["attack_id"]), r)
        if firsts:
            caught = [k for k, r in firsts.items() if flagged(r)]
            lines.append("  Attacks flagged at their first case: {}/{}; missed: {}.".format(
                len(caught), len(firsts), ", ".join("{} {}".format(*k) for k in firsts if k not in caught) or "none"))
    with open(os.path.join(OUT, "specialist_rdp{}.md".format(suffix)), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
