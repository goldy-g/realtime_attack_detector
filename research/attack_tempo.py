"""2.3 Attack tempo: what each second of decision delay costs in timeliness.

For every attack wave (22 validation waves, 3 eval waves) it replays the
scorer's rule from evaluator/metrics.py: an alert d seconds after the alert
point has seen k of the attack's n malicious events and scores (n - k + 1) / n;
after the last malicious event the score decays to zero at the post-stream
deadline (feed end + 300 s). In real time an event is delivered at its own
timestamp, so k is the number of malicious events stamped at or before the alert.

Writes research/out/attack_tempo.json and attack_tempo.md.
"""

from __future__ import annotations

import bisect
import statistics

from common import EVAL, VAL, answers, parse_ts, save_json, save_text, wave_stream, waves

DELAYS = [0, 0.5, 1, 2, 3, 5, 8, 10, 15, 20, 30, 45, 60, 90, 120]
GRACE_S = 300.0


def score_at(times: list[float], alert_from: float, feed_end: float, d: float) -> float:
    n = len(times)
    t = alert_from + d
    last = times[-1]
    if t <= last:
        k = max(1, bisect.bisect_right(times, t))
        return (n - k + 1) / n
    deadline = feed_end + GRACE_S
    return (1 / n) * max(0.0, (deadline - t) / (deadline - last))


def wave_rows(data_dir: str, source: str) -> list[dict]:
    rows = []
    ans = answers(data_dir)
    for w in waves(data_dir):
        a = ans[w["wave_id"]]
        if not a.get("attack"):
            continue
        live = wave_stream(data_dir, w["wave_id"], "live")
        ts = {e["id"]: parse_ts(e["timestamp"]) for e in live}
        feed_end = max(ts.values())
        mal = set(a["malicious_event_ids"])
        for attack in a["attacks"]:
            aid = attack["attack_id"]
            times = sorted(ts[i] for i in mal if a["event_attack"].get(i) == aid and i in ts)
            if not times:
                continue
            t0 = parse_ts(attack["alert_from"])
            within = {s: sum(1 for x in times if x <= t0 + s) for s in (1, 5, 10, 30)}
            rows.append({
                "source": source, "wave": w["wave_id"], "split": w.get("sets", [""])[0] if source == "val" else "eval",
                "attack_id": aid, "name": attack["name"], "n": len(times),
                "seen_within_s": within,
                "second_event_after_s": round(times[1] - t0, 3) if len(times) > 1 else None,
                "tenth_event_after_s": round(times[9] - t0, 3) if len(times) > 9 else None,
                "last_event_after_s": round(times[-1] - t0, 1),
                "score": {str(d): round(score_at(times, t0, feed_end, d), 4) for d in DELAYS},
            })
    return rows


def main() -> None:
    rows = wave_rows(VAL, "val") + wave_rows(EVAL, "eval")
    summary = {}
    for d in DELAYS:
        vals = [r["score"][str(d)] for r in rows]
        summary[str(d)] = {"mean": round(statistics.fmean(vals), 4), "median": round(statistics.median(vals), 4),
                           "min": round(min(vals), 4),
                           "share_ge_0.9": round(sum(v >= 0.9 for v in vals) / len(vals), 3)}
    save_json("attack_tempo.json", {"delays_s": DELAYS, "summary": summary, "attacks": rows})

    lines = ["# Attack tempo (2.3)", "",
             "Timeliness score an alert would earn d seconds after the alert point, over {} attack waves "
             "({} validation, {} eval).".format(len(rows), sum(r["source"] == "val" for r in rows),
                                               sum(r["source"] == "eval" for r in rows)), "",
             "| Delay (s) | Mean | Median | Worst | Attacks ≥ 0.9 |", "|---|---|---|---|---|"]
    for d in DELAYS:
        s = summary[str(d)]
        lines.append("| {} | {:.3f} | {:.3f} | {:.3f} | {:.0%} |".format(d, s["mean"], s["median"], s["min"], s["share_ge_0.9"]))
    lines += ["", "| Wave | Attack | n in window | 2nd event after | events in 1 s · 5 s · 10 s · 30 s | score at 2 s · 5 s · 10 s · 30 s |",
              "|---|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda r: r["score"]["5"]):
        w = r["seen_within_s"]
        lines.append("| {} | {} | {} | {} s | {} · {} · {} · {} | {} · {} · {} · {} |".format(
            r["wave"], r["name"][:60], r["n"], r["second_event_after_s"], w[1], w[5], w[10], w[30],
            r["score"]["2"], r["score"]["5"], r["score"]["10"], r["score"]["30"]))
    save_text("attack_tempo.md", "\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
