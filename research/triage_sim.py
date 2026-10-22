"""2.5 Triage feasibility: novelty against the warm-up hour, with and without a fleet baseline.

The model can only judge a few cases per minute, so a cheap triage must pick
them. This replays three candidate rules on every validation and eval wave:

  V1  process start whose parent -> child pair never appeared in the warm-up hour
  V2  V1, plus an outbound connection whose process -> destination port pair never appeared
  V3  V2, minus pairs that are common on other machines' benign days ("fleet baseline",
      built leave-machine-out from the training days, benign events only)

Per wave it reports candidates per minute, the largest burst in 10 s, whether the
alert point itself is a candidate, and the best timeliness reachable if the model
answered at the first malicious candidate after 0, 2 or 5 seconds.

Writes research/out/triage_sim.json and triage_sim.md, and the candidates themselves to
data/cache/research/candidates.jsonl for the case set (2.7).
"""

from __future__ import annotations

import gzip
import json
import os
import statistics
from collections import Counter, defaultdict

from attack_tempo import score_at
from common import (EVAL, ROOT, VAL, answers, base, day_events, day_labels, machines, parse_ts, pmap,
                    props, save_json, save_text, wave_stream, waves)

FLEET_MIN_MACHINES = 3          # a pair on at least this many other machines counts as common
CACHE = os.path.join(ROOT, "data", "cache", "research")


def proc_key(ev: dict) -> tuple[str, str]:
    p = props(ev)
    return base(p.get("parent_image_path")), base(p.get("image_path"))


def flow_key(ev: dict) -> tuple[str, str] | None:
    p = props(ev)
    if p.get("direction") != "outbound":
        return None
    return base(p.get("image_path")), p.get("dest_port") or ""


def day_fleet(row: dict) -> dict:
    """Benign process pairs and flow pairs of one training day."""
    labels = day_labels(row["machine"])
    bad = set(labels["malicious_event_ids"]) | set(labels.get("context_event_ids") or [])
    pairs, flows = set(), set()
    with gzip.open(day_events(row["machine"]), "rt", encoding="utf-8") as fh:
        for line in fh:
            if '"object":"PROCESS"' in line and '"action":"CREATE"' in line:
                ev = json.loads(line)
                if ev["id"] not in bad:
                    pairs.add(proc_key(ev))
            elif '"object":"FLOW"' in line:
                ev = json.loads(line)
                k = flow_key(ev)
                if k and ev["id"] not in bad:
                    flows.add(k)
    return {"machine": row["machine"], "pairs": sorted(map(list, pairs)), "flows": sorted(map(list, flows))}


def fleet_counts() -> tuple[dict, dict, dict, dict]:
    days = pmap(day_fleet, machines())
    pair_m, flow_m = defaultdict(set), defaultdict(set)
    for d in days:
        for k in d["pairs"]:
            pair_m[tuple(k)].add(d["machine"])
        for k in d["flows"]:
            flow_m[tuple(k)].add(d["machine"])
    return pair_m, flow_m, {d["machine"]: d for d in days}, {}


def label_of(eid: str, ev: dict, a: dict) -> str:
    if eid in a["_mal"]:
        return "malicious"
    if eid in a["_ctx"]:
        return "context"
    chain = a["event_chain"].get(eid)
    if (chain is not None and chain in a["_exc"]) or (chain is None and ev.get("actorID") in a["_exa"]):
        return "excused"
    return "benign"


def simulate(data_dir: str, wave: dict, a: dict, pair_m: dict, flow_m: dict) -> tuple[dict, list[dict]]:
    warm = wave_stream(data_dir, wave["wave_id"], "warmup")
    live = wave_stream(data_dir, wave["wave_id"], "live")
    a["_mal"], a["_ctx"] = set(a["malicious_event_ids"]), set(a.get("context_event_ids") or [])
    a["_exc"], a["_exa"] = set(a.get("excused_chains") or []), set(a.get("excused_actors") or [])
    seen_pairs = {proc_key(e) for e in warm if e["object"] == "PROCESS" and e["action"] == "CREATE"}
    seen_flows = {flow_key(e) for e in warm if e["object"] == "FLOW"} - {None}
    me = wave["machine"]

    def common(table: dict, key) -> bool:
        return len(table.get(key, set()) - {me}) >= FLEET_MIN_MACHINES

    cands = []
    for e in live:
        rule = None
        if e["object"] == "PROCESS" and e["action"] == "CREATE":
            k = proc_key(e)
            if k not in seen_pairs:
                rule = ("V1", common(pair_m, k))
                seen_pairs.add(k)                  # only the first occurrence is new
        elif e["object"] == "FLOW":
            k = flow_key(e)
            if k and k not in seen_flows:
                rule = ("V2", common(flow_m, k))
                seen_flows.add(k)
        if rule:
            cands.append({"wave": wave["wave_id"], "machine": me, "event_id": e["id"], "ts": e["timestamp"],
                          "t": parse_ts(e["timestamp"]), "rule": rule[0], "fleet_common": rule[1],
                          "label": label_of(e["id"], e, a), "attack_id": a.get("event_attack", {}).get(e["id"])})

    live_s = parse_ts(wave["live_end"]) - parse_ts(wave["live_start"])
    variants = {"V1": lambda c: c["rule"] == "V1", "V2": lambda c: True,
                "V3": lambda c: not c["fleet_common"]}
    res = {"wave": wave["wave_id"], "kind": "attack" if a.get("attack") else "benign",
           "split": (wave.get("sets") or ["eval"])[0] if data_dir == VAL else "eval",
           "live_min": round(live_s / 60, 2), "variants": {}}
    feed_end = max(parse_ts(e["timestamp"]) for e in live)
    for name, keep in variants.items():
        cs = [c for c in cands if keep(c)]
        times = [c["t"] for c in cs]
        burst = max((sum(1 for u in times if t <= u < t + 10) for t in times), default=0)
        v = {"n": len(cs), "per_min": round(len(cs) / (live_s / 60), 2), "burst_10s": burst,
             "labels": dict(Counter(c["label"] for c in cs))}
        if a.get("attack"):
            per_attack = {}
            for atk in a["attacks"]:
                aid, t0 = atk["attack_id"], parse_ts(atk["alert_from"])
                mal_times = sorted(parse_ts(e["timestamp"]) for e in live
                                   if e["id"] in a["_mal"] and a["event_attack"].get(e["id"]) == aid)
                first = next((c for c in cs if c["label"] == "malicious" and c["attack_id"] == aid), None)
                row = {"alert_point_is_candidate": any(c["event_id"] == atk["first_alertable_event_id"] for c in cs)}
                if first and mal_times:
                    lag = first["t"] - t0
                    row.update(first_candidate_after_s=round(lag, 3),
                               best_timeliness={str(d): round(score_at(mal_times, t0, feed_end, lag + d), 4) for d in (0, 2, 5)})
                else:
                    row.update(first_candidate_after_s=None, best_timeliness={"0": 0.0, "2": 0.0, "5": 0.0})
                per_attack[aid] = row
            v["attacks"] = per_attack
        res["variants"][name] = v
    return res, cands


def main() -> None:
    pair_m, flow_m, _, _ = fleet_counts()
    rows, all_cands = [], []
    for data_dir in (VAL, EVAL):
        ans = answers(data_dir)
        for w in waves(data_dir):
            r, cands = simulate(data_dir, w, ans[w["wave_id"]], pair_m, flow_m)
            rows.append(r)
            all_cands += cands
    os.makedirs(CACHE, exist_ok=True)
    with open(os.path.join(CACHE, "candidates.jsonl"), "w", encoding="utf-8") as fh:
        for c in all_cands:
            fh.write(json.dumps(c) + "\n")

    summary = {}
    for name in ("V1", "V2", "V3"):
        for group, sel in (("val benign", lambda r: r["split"] != "eval" and r["kind"] == "benign"),
                           ("val attack", lambda r: r["split"] != "eval" and r["kind"] == "attack"),
                           ("eval", lambda r: r["split"] == "eval")):
            rs = [r for r in rows if sel(r)]
            per_min = [r["variants"][name]["per_min"] for r in rs]
            atk = [x for r in rs for x in r["variants"][name].get("attacks", {}).values()]
            summary["{} · {}".format(name, group)] = {
                "waves": len(rs), "per_min_median": round(statistics.median(per_min), 2),
                "per_min_p95": round(sorted(per_min)[max(0, int(0.95 * len(per_min)) - 1)], 2),
                "per_min_max": max(per_min), "burst_10s_max": max(r["variants"][name]["burst_10s"] for r in rs),
                "benign_candidates": sum(r["variants"][name]["labels"].get("benign", 0) for r in rs),
                "attacks": len(atk),
                "alert_point_covered": sum(x["alert_point_is_candidate"] for x in atk),
                "attack_has_candidate": sum(x["first_candidate_after_s"] is not None for x in atk),
                "best_timeliness_mean_0s": round(statistics.fmean([x["best_timeliness"]["0"] for x in atk]), 3) if atk else None,
                "best_timeliness_mean_2s": round(statistics.fmean([x["best_timeliness"]["2"] for x in atk]), 3) if atk else None,
                "best_timeliness_mean_5s": round(statistics.fmean([x["best_timeliness"]["5"] for x in atk]), 3) if atk else None,
            }
    save_json("triage_sim.json", {"fleet_min_machines": FLEET_MIN_MACHINES, "summary": summary, "waves": rows})

    lines = ["# Triage feasibility (2.5)", "",
             "V1 new parent→child pair · V2 + new process→port outbound · V3 = V2 minus pairs common on ≥{} other machines.".format(FLEET_MIN_MACHINES),
             "", "| Variant · waves | Waves | Cases/min median · p95 · max | Max in 10 s | Benign cases | Alert point is a case | Attack has a case | Best timeliness at +0 s · +2 s · +5 s |",
             "|---|---|---|---|---|---|---|---|"]
    for k, s in summary.items():
        lines.append("| {} | {} | {} · {} · {} | {} | {} | {} | {} | {} |".format(
            k, s["waves"], s["per_min_median"], s["per_min_p95"], s["per_min_max"], s["burst_10s_max"],
            s["benign_candidates"],
            "{}/{}".format(s["alert_point_covered"], s["attacks"]) if s["attacks"] else "–",
            "{}/{}".format(s["attack_has_candidate"], s["attacks"]) if s["attacks"] else "–",
            "{} · {} · {}".format(s["best_timeliness_mean_0s"], s["best_timeliness_mean_2s"], s["best_timeliness_mean_5s"]) if s["attacks"] else "–"))
    misses = [(r["wave"], aid, x) for r in rows for aid, x in r["variants"]["V3"].get("attacks", {}).items()
              if not x["alert_point_is_candidate"]]
    lines += ["", "Attacks whose alert point is not a V3 case:", ""]
    lines += ["- {} {}: first malicious case {} s after the alert point".format(w, aid, x["first_candidate_after_s"]) for w, aid, x in misses] or ["- none"]
    save_text("triage_sim.md", "\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
