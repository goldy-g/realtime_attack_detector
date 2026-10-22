"""Score alerts against current attack labels: what was caught, when, and how fast.

Every rule lives here, with tests in test_metrics.py. Nothing is judged by a
model, so a scorecard you produce is the one we produce from the same alerts.

Attack labels (answers with `event_attack`, the current release)
---------------------------------------------------------------
Every event of a wave is benign, *malicious* or *context*. Each attack has one
alert point (`alert_from`): the first event at which an analyst reading the
attack's events in order can conclude it is an attack. Attack events from it on
are malicious, attack events before it are context. Each attack's steps are its
activities from the alert point on, in time order; step 1 is the alert point.
Per wave, alerts are processed in emission order; an alert's `event_id` decides
its outcome:

- unknown id, or an id not yet delivered when the alert was raised -> *invalid*
- warm-up alert (no attack event is ever in the warm-up)            -> false alarm
- a malicious event of attack A, first alert on A                   -> *detection*
- a malicious event of an attack already detected                   -> duplicate
- a context event                                                    -> *context*:
                                                                       neutral
- chain / dispatcher process tied to documented attacker activity
  outside the labels (`excused_chains` / `excused_actors`)           -> *excused*:
                                                                       neutral
- anything else                                                      -> false alarm

Any event can be alerted on, including events of dispatcher processes
(services, svchost: an inbound RDP connection is one). False alarms are
counted once per distinct benign chain, or per distinct dispatcher process
(keyed by actorID); repeats are reported, not counted.

Timeliness: delay = callback time - `alert_from`. Progress counts raw malicious
events seen at callback time: event score = (n - k + 1) / n, where k of n
malicious events have occurred. It is 1.0 after event 1 and before event 2,
and 1/n at the final malicious event. After execution, that final-event score
decays linearly to zero by the post-stream deadline; a result at or after the
deadline is a miss.

Metrics
-------
- recall               attack waves with at least one detected attack / attack waves
- wave delay           callback time - attack alert point
- timeliness score     mean per-attack event score above (missed = 0)
- false alarms         total, per wave, warm-up vs live
- explanation precision per detecting alert: listed IDs delivered by alert time,
                         excluding context IDs, that are malicious / eligible listed IDs
- explanations         share of received explanations listing valid, labeled IDs
"""

from __future__ import annotations

import datetime as dt
import math
import re
import statistics

_FRAC = re.compile(r"\.(\d+)")


def parse_dt(s: str) -> dt.datetime:
    """ISO 8601 timestamp (eCAR style, any fraction length, offset or Z) -> aware datetime."""
    s = str(s).strip().replace("Z", "+00:00")
    m = _FRAC.search(s)
    if m:
        s = s[:m.start()] + "." + (m.group(1) + "000000")[:6] + s[m.end():]
    t = dt.datetime.fromisoformat(s)
    return t if t.tzinfo is not None else t.replace(tzinfo=dt.timezone.utc)


def parse_ts(s: str) -> float:
    """ISO 8601 timestamp -> epoch seconds."""
    return parse_dt(s).timestamp()


def percentile(values: list[float], q: float) -> float:
    """Linear-interpolated percentile; q in [0, 100]."""
    if not values:
        return 0.0
    xs = sorted(values)
    pos = (len(xs) - 1) * (q / 100.0)
    lo, hi = math.floor(pos), math.ceil(pos)
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


def score_wave(alerts: list[dict], answer: dict) -> dict:
    """Score alerts against current attack, event, and process-chain labels."""
    if "event_attack" not in answer:
        raise ValueError("answers must use the current event_attack label schema")
    event_chain = answer.get("event_chain") or {}
    event_attack = answer.get("event_attack") or {}
    bad_events = set(answer.get("malicious_event_ids") or [])
    ctx_events = set(answer.get("context_event_ids") or [])
    excused_chains = set(answer.get("excused_chains") or [])
    excused_actors = set(answer.get("excused_actors") or [])
    attacks = {a["attack_id"]: a for a in answer.get("attacks") or []}
    malicious_by_attack = {
        aid: sum(1 for eid in bad_events if event_attack.get(eid) == aid)
        for aid in attacks
    }
    detected: dict[str, dict] = {}
    fa_keys: dict[str, str] = {}                 # key -> phase of the first alert on it
    rows, ev_prec = [], []
    for a in alerts:
        eid = str(a.get("event_id") or "")
        phase = a.get("phase", "live")
        row = {"alert_id": a.get("alert_id"), "event_id": eid, "phase": phase,
               "chain_id": None, "attack_id": None, "outcome": "invalid", "delay_s": None}
        rows.append(row)
        cited = list(dict.fromkeys(a.get("explanation_event_ids_available_at_alert") or []))
        if eid not in event_chain or not a.get("delivered", True):
            row["explanation_event_ids_valid"] = []
            continue
        chain = event_chain[eid]
        row["chain_id"] = chain
        target_attack = event_attack.get(eid)
        row["explanation_event_ids_valid"] = [
            cited_id for cited_id in cited
            if target_attack in attacks
            and cited_id in event_chain
            and event_attack.get(cited_id) == target_attack
            and (cited_id in bad_events or cited_id in ctx_events)
        ]
        if phase == "live" and eid in bad_events and event_attack.get(eid) in attacks:
            aid = event_attack[eid]
            row["attack_id"] = aid
            if aid in detected:
                row["outcome"] = "duplicate"
                continue
            t = parse_ts(a["alert_ts"])
            deadline = parse_ts(a["post_stream_deadline_ts"])
            if t >= deadline:
                row["outcome"] = "late_timeout"
                continue
            n = malicious_by_attack[aid]
            seen = max(1, min(n, int(a["malicious_events_seen"])))
            last_malicious = parse_ts(a["last_malicious_ts"])
            delay = t - parse_ts(attacks[aid]["alert_from"])
            on_time = t <= last_malicious
            if on_time:
                event_score = (n - seen + 1) / n if n else 1.0
                status = "caught_on_time"
            else:
                remaining = max(0.0, (deadline - t) / (deadline - last_malicious))
                event_score = (1 / n) * remaining if n else 0.0
                status = "caught_after_execution"
            detected[aid] = {
                "attack_id": aid,
                "name": attacks[aid].get("name", aid),
                "status": status,
                "alert_id": a.get("alert_id"),
                "alert_ts": a["alert_ts"],
                "delay_s": delay,
                "caught_at_event": seen,
                "n_malicious_events": n,
                "event_score": event_score,
            }
            row.update(outcome="detection", delay_s=delay)
            precision_ids = [cited_id for cited_id in cited
                             if cited_id in event_chain and cited_id not in ctx_events]
            ev_prec.append(sum(1 for cited_id in precision_ids
                               if cited_id in bad_events and event_attack.get(cited_id) == aid)
                            / len(precision_ids) if precision_ids else 0.0)
            continue
        if phase == "live" and eid in ctx_events:
            row["outcome"] = "context"
            continue
        if phase == "live" and ((chain is not None and chain in excused_chains) or (
                chain is None and a.get("event_actor") in excused_actors)):
            row["outcome"] = "excused"
            continue
        key = "chain:" + chain if chain is not None else "proc:" + str(a.get("event_actor") or eid)
        if key in fa_keys:
            row["outcome"] = "repeat_false_alarm"
        else:
            fa_keys[key] = phase
            row["outcome"] = "false_alarm"
        row["fa_key"] = key

    attack = bool(answer.get("attack"))
    onset = min((parse_ts(a["alert_from"]) for a in attacks.values()), default=None)
    first = min((parse_ts(d["alert_ts"]) for d in detected.values()), default=None)
    count = lambda o: sum(1 for r in rows if r["outcome"] == o)  # noqa: E731
    attack_results = {
        aid: detected.get(aid, {
            "attack_id": aid, "name": a.get("name", aid), "status": "missed",
            "caught_at_event": None, "n_malicious_events": malicious_by_attack[aid], "event_score": 0.0,
        })
        for aid, a in attacks.items()
    }
    return {
        "attack": attack,
        "detected": attack and bool(detected),
        "delay_s": first - onset if (attack and first is not None and onset is not None) else None,
        "n_attacks": len(attacks),
        "attacks_detected": len(detected),
        "attacks": attack_results,
        "n_alerts": len(alerts),
        "false_alarms": len(fa_keys),
        "false_alarms_warmup": sum(1 for p in fa_keys.values() if p == "warmup"),
        "false_alarms_live": sum(1 for p in fa_keys.values() if p != "warmup"),
        "repeat_false_alarms": count("repeat_false_alarm"),
        "duplicates": count("duplicate"),
        "late_timeout": count("late_timeout"),
        "excused": count("excused"),
        "context": count("context"),
        "invalid": count("invalid"),
        "evidence_precision": ev_prec,
        "alerts": rows,
    }


def score(alerts: list[dict], answers: dict, wave_ids: list[str]) -> dict:
    """Score a run: alerts (each with a `wave`) over the waves in `wave_ids`.

    answers  answers.json "waves" mapping wave_id -> answer
    """
    per_wave = {}
    for w in wave_ids:
        per_wave[w] = score_wave([a for a in alerts if a.get("wave") == w], answers[w])
    vals = list(per_wave.values())
    attack = [v for v in vals if v["attack"]]
    delays = [v["delay_s"] for v in attack if v["delay_s"] is not None]
    attack_rows = [d for v in attack for d in v["attacks"].values()]
    att_scores = [d["event_score"] if d else 0.0 for d in attack_rows]
    caught_first = sum(1 for v in attack for d in v["attacks"].values()
                       if d and d["status"] == "caught_on_time" and d["caught_at_event"] == 1)
    ev = [p for v in vals for p in v["evidence_precision"]]
    tot = lambda k: sum(v.get(k, 0) for v in vals)  # noqa: E731
    n_att = len(attack)
    return {
        "summary": {
            "n_waves": len(vals),
            "n_attack_waves": n_att,
            "attack_waves_detected": sum(1 for v in attack if v["detected"]),
            "recall": sum(1 for v in attack if v["detected"]) / n_att if n_att else 0.0,
            "delay_s_p50": statistics.median(delays) if delays else None,
            "delay_s_max": max(delays) if delays else None,
            "n_attacks": tot("n_attacks"),
            "attacks_detected": tot("attacks_detected"),
            "caught_at_first_event": caught_first,
            "caught_on_time": sum(1 for d in attack_rows if d and d.get("status", "caught_on_time") == "caught_on_time"),
            "caught_after_execution": sum(1 for d in attack_rows if d and d.get("status") == "caught_after_execution"),
            "missed_attacks": sum(1 for d in attack_rows if not d or d.get("status") == "missed"),
            "timeliness_score": statistics.fmean(att_scores) if att_scores else 0.0,
            "n_alerts": tot("n_alerts"),
            "false_alarms": tot("false_alarms"),
            "false_alarms_per_wave": tot("false_alarms") / len(vals) if vals else 0.0,
            "false_alarms_warmup": tot("false_alarms_warmup"),
            "false_alarms_live": tot("false_alarms_live"),
            "repeat_false_alarms": tot("repeat_false_alarms"),
            "duplicates": tot("duplicates"),
            "excused": tot("excused"),
            "context": tot("context"),
            "invalid": tot("invalid"),
            "late_timeout": tot("late_timeout"),
            "evidence_precision": statistics.fmean(ev) if ev else 0.0,
        },
        "waves": per_wave,
    }


def explanation_summary(alerts: list[dict]) -> dict:
    """Explanation latency and whether it lists valid, labeled event IDs."""
    exp = [a["explain_s"] for a in alerts if a.get("explain_s") is not None]
    explained = [a for a in alerts if a.get("explanation_received")]
    ok = sum(1 for a in explained if a.get("explanation_event_ids_valid"))
    return {"explain_s_p50": percentile(exp, 50), "explain_s_p95": percentile(exp, 95),
            "explained": len(explained), "explanations_with_valid_event_ids": ok}


def decision_summary(alerts: list[dict]) -> dict:
    """Latency of the calls that returned alerts (one value per alert)."""
    dec = [a["call_s"] for a in alerts if a.get("call_s") is not None]
    return {"decision_s_p50": percentile(dec, 50), "decision_s_p95": percentile(dec, 95)}
