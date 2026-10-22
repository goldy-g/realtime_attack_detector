"""SQ-1 offline: experts for known behaviours, the SLM for the rest.

Reuses the saved Gemma 4 E4B verdicts (no model calls) and measures two variants:

  A  feed and rank  experts only reorder the case queue (and would add evidence);
                    the SLM makes every decision, so recall / false alarms / AUC are
                    the SLM's and the only measurable change is how soon each
                    attack's case reaches the model.
  B  raise          an expert may raise an alert at once; it never clears a case,
                    so a "normal" from an expert still goes to the SLM.

Experts: the five rules in experts.py (behind a router) and two small trained models
on the same named facts (a depth-3 decision tree and gradient-boosted trees).
Trained models learn on dev only; holdout is only checked. Eval cases stay unseen.

Survival rule (fixed before measuring): an expert is kept only if, on the cases it
claims, it beats the SLM on the holdout (catches at least as many attacks at their
first case and raises no more benign cases, and is strictly better on catches,
false alarms or alert time) AND it still does so in the leave-one-attack-type-out
test (with its own attack type held out of how it was built).

    data/cache/sq1-venv/bin/python research/sq1/run.py

Writes research/out/sq1_results.md.
"""

from __future__ import annotations

import bisect
import json
import os
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from experts import EXPERTS, OFFICE, SOURCES, flags, parse, route  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CACHE = os.path.join(ROOT, "data", "cache", "research")
OUT = os.path.join(ROOT, "research", "out")
SERVICE_S = (1.7, 3.4)                  # seconds per verdict on a typical / weak 8-core target (FINDINGS 2.9)
TRAINED = ("tree", "gbt")


# --- data ---------------------------------------------------------------------------------------------

def load_cases() -> list[dict]:
    cases = [json.loads(line) for line in open(os.path.join(CACHE, "cases.jsonl"), encoding="utf-8")]
    cases = [c for c in cases if c["split"] in ("dev", "holdout")]
    for c in cases:
        c["f"] = parse(c)
        c["g"] = flags(c["f"])
        c["t"] = datetime.fromisoformat(c["ts"]).timestamp()
    return cases


def load_slm(round_name: str) -> dict:
    """case_id -> (attack: bool, score 0-100), the score as research/score_models.py computes it."""
    out = {}
    for r in map(json.loads, open(os.path.join(CACHE, "scores", "Gemma-4-E4B.{}.jsonl".format(round_name)), encoding="utf-8")):
        p = r.get("parsed") or {}
        conf = p.get("confidence", 50)
        attack = p.get("verdict") == "attack"
        out[r["case_id"]] = (attack, conf if attack else 100 - conf)
    return out


def type_of() -> dict:
    """attack_id -> attack type, from the alert point in the attack catalogue (2.2)."""
    out = {}
    for r in json.load(open(os.path.join(OUT, "attack_catalogue.json"), encoding="utf-8")):
        ap = r["alert_point"] or {}
        parent, actor = ap.get("parent") or "", ap.get("actor_image") or ""
        out[r["attack_id"]] = ("wmi_ps" if parent == "wmiprvse.exe" else "office" if parent in OFFICE else
                               "updater" if parent == "gup.exe" else "batch" if parent == "cmd.exe" else
                               "rdp" if actor == "mstsc.exe" else "payload_flow")
    return out


def alert_from() -> dict:
    return {r["attack_id"]: datetime.fromisoformat(r["alert_from"]).timestamp()
            for r in json.load(open(os.path.join(OUT, "attack_catalogue.json"), encoding="utf-8"))}


def tempo_curves() -> dict:
    """attack_id -> (delays, scores): the scorer's timeliness by delay after the alert point (2.3)."""
    d = json.load(open(os.path.join(OUT, "attack_tempo.json"), encoding="utf-8"))
    delays = d["delays_s"]
    return {a["attack_id"]: (delays, [a["score"][str(x)] for x in delays]) for a in d["attacks"]}


def timeliness(curve, delay: float | None) -> float:
    if delay is None:
        return 0.0
    xs, ys = curve
    if delay <= 0:
        return ys[0]
    if delay >= xs[-1]:
        return ys[-1]
    i = bisect.bisect_right(xs, delay)
    x0, x1, y0, y1 = xs[i - 1], xs[i], ys[i - 1], ys[i]
    return y0 + (y1 - y0) * (delay - x0) / (x1 - x0)


# --- trained experts ----------------------------------------------------------------------------------

FEATURES = None


def matrix(cases: list[dict]) -> np.ndarray:
    global FEATURES
    FEATURES = FEATURES or list(cases[0]["g"])
    return np.array([[float(c["g"][k]) for k in FEATURES] for c in cases])


def train(cases: list[dict]) -> dict:
    """Both trained experts on malicious (1) vs benign (0); context and excused cases are left out.

    The raise threshold is the highest score any training benign case got: zero
    training false alarms, the strictest setting that still lets a model raise.
    """
    rows = [c for c in cases if c["label"] in ("malicious", "benign")]
    x, y = matrix(rows), np.array([c["label"] == "malicious" for c in rows], dtype=int)
    models = {"tree": DecisionTreeClassifier(max_depth=3, class_weight="balanced", random_state=0),
              "gbt": GradientBoostingClassifier(n_estimators=100, max_depth=2, learning_rate=0.1, random_state=0)}
    out = {}
    for name, m in models.items():
        m.fit(x, y)
        p = m.predict_proba(x)[:, 1]
        out[name] = (m, float(max(p[y == 0])) if (y == 0).any() else 0.5)
    return out


def tree_path(m: DecisionTreeClassifier, row: np.ndarray) -> list[str]:
    """The decision tree's path for one case, as evidence a reader (or the SLM) can check."""
    t, node, path = m.tree_, 0, []
    while t.children_left[node] != -1:
        k, thr = FEATURES[t.feature[node]], t.threshold[node]
        left = row[t.feature[node]] <= thr
        path.append("{} {} {:.2g}".format(k, "≤" if left else ">", thr))
        node = t.children_left[node] if left else t.children_right[node]
    return path


def score_trained(cases: list[dict], models: dict) -> None:
    x = matrix(cases)
    for name, (m, thr) in models.items():
        p = m.predict_proba(x)[:, 1]
        for c, pi in zip(cases, p):
            c[name] = (bool(pi > thr), float(pi))


# --- metrics ------------------------------------------------------------------------------------------

def auc(pos: list[float], neg: list[float]) -> float | None:
    if not pos or not neg:
        return None
    return sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))


def attacks(rows: list[dict]) -> dict:
    by = defaultdict(list)
    for c in rows:
        if c["label"] == "malicious":
            by[(c["wave"], c["attack_id"])].append(c)
    return {k: sorted(v, key=lambda c: c["t"]) for k, v in by.items()}


def detect(rows: list[dict], flagged, score) -> dict:
    atk = attacks(rows)
    mal = [c for c in rows if c["label"] == "malicious"]
    ben = [c for c in rows if c["label"] == "benign"]
    a = auc([score(c) for c in mal], [score(c) for c in ben])
    return {"attacks": len(atk), "first": sum(flagged(v[0]) for v in atk.values()),
            "any": sum(any(flagged(c) for c in v) for v in atk.values()),
            "mal": len(mal), "mal_flagged": sum(map(flagged, mal)),
            "ben": len(ben), "ben_flagged": sum(map(flagged, ben)), "auc": round(a, 3) if a is not None else None}


def fmt_detect(d: dict) -> str:
    return "{}/{} | {}/{} | {}/{} | {}/{} | {}".format(d["first"], d["attacks"], d["any"], d["attacks"],
                                                      d["mal_flagged"], d["mal"], d["ben_flagged"], d["ben"], d["auc"])


# --- the case queue, replayed -------------------------------------------------------------------------

def replay(cases: list[dict], slm: dict, service_s: float, order, raise_fn=None) -> dict:
    """Alert time per attack when one SLM worker takes cases in `order` (lower key first).

    Cases arrive at their own timestamps; the worker takes the best waiting case,
    spends service_s on it and alerts if the SLM said attack. With raise_fn (variant B)
    an expert alert goes out as the case arrives. Returns (wave, attack_id) -> time.
    """
    groups = defaultdict(list)
    for c in cases:
        groups[c["wave"]].append(c)
    first_alert = {}
    for wave, cs in groups.items():
        cs = sorted(cs, key=lambda c: c["t"])
        clock, i, waiting = cs[0]["t"], 0, []

        def mark(c, t):
            if c["label"] == "malicious":
                k = (wave, c["attack_id"])
                first_alert[k] = min(first_alert.get(k, t), t)

        while i < len(cs) or waiting:
            while i < len(cs) and cs[i]["t"] <= clock:
                if raise_fn and raise_fn(cs[i]):
                    mark(cs[i], cs[i]["t"])
                waiting.append(cs[i])
                i += 1
            if not waiting:
                clock = cs[i]["t"]
                continue
            nxt = min(waiting, key=order)
            waiting.remove(nxt)
            clock += service_s
            if slm.get(nxt["case_id"], (False, 0))[0]:
                mark(nxt, clock)
    return first_alert


def timeliness_table(cases, slm, curves, starts, orders: dict, split: str) -> dict:
    rows = [c for c in cases if c["split"] == split]
    keys = [k for k in attacks(rows) if k[1] in curves]
    out = {}
    for name, (order, raise_fn) in orders.items():
        for s in SERVICE_S:
            fa = replay(rows, slm, s, order, raise_fn)
            delays = [fa[k] - starts[k[1]] if k in fa else None for k in keys]
            out[(name, s)] = (statistics.fmean(timeliness(curves[k[1]], d) for k, d in zip(keys, delays)),
                              statistics.median([d for d in delays if d is not None] or [0]), len(keys))
    return out


# --- main ---------------------------------------------------------------------------------------------

RULES = [n for n, _ in EXPERTS]
RULE_FN = dict(EXPERTS)
CONCLUSION = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conclusion.md")


def rule_raise(c: dict, names) -> bool:
    """Variant B: the expert the router picks among `names` calls the case an attack."""
    r = route(c["f"], c["g"], names)
    return bool(r and r[1])


def claims(name: str, c: dict) -> bool:
    return name in TRAINED or c["solo"][name] is not None


def raises(name: str, c: dict) -> bool:
    return c[name][0] if name in TRAINED else bool(c["solo"][name] and c["solo"][name][0])


def expert_stats(cases, slm, name, split) -> dict:
    """One expert alone on the cases it claims, against the SLM on the same cases."""
    rows = [c for c in cases if c["split"] == split and claims(name, c)]
    atk = {k: v for k, v in attacks([c for c in cases if c["split"] == split]).items() if claims(name, v[0])}
    n = Counter(c["label"] for c in rows)
    res = {"atk": len(atk), "n": n, "e_c": sum(raises(name, v[0]) for v in atk.values()),
           "e_b": sum(raises(name, c) for c in rows if c["label"] == "benign")}
    for b in ("v1", "v0"):
        res[b + "_c"] = sum(slm[b].get(v[0]["case_id"], (False, 0))[0] for v in atk.values())
        ben = [c for c in rows if c["label"] == "benign" and c["case_id"] in slm[b]]
        res[b + "_b"], res[b + "_bn"] = sum(slm[b][c["case_id"]][0] for c in ben), len(ben)
    return res


def mean_timeliness(cases, slm, curves, starts, keys, service_s, order, raise_fn=None) -> float | None:
    if not keys:
        return None
    waves_needed = {k[0] for k in keys}
    fa = replay([c for c in cases if c["wave"] in waves_needed], slm, service_s, order, raise_fn)
    return statistics.fmean(timeliness(curves[k[1]], fa[k] - starts[k[1]] if k in fa else None) for k in keys)


def main() -> None:
    cases = load_cases()
    slm = {"v1": load_slm("quickv1"), "v0": load_slm("full")}
    slm_q = {**slm["v0"], **slm["v1"]}          # v1 where scored; v0 for benign window cases outside the quick set
    types, starts, curves = type_of(), alert_from(), tempo_curves()
    for c in cases:
        c["type"] = types.get(c["attack_id"]) if c["attack_id"] else None
        c["solo"] = {n: fn(c["f"], c["g"]) for n, fn in EXPERTS}
        c["rule"] = route(c["f"], c["g"])
    models = train([c for c in cases if c["split"] == "dev"])
    score_trained(cases, models)
    all_types = sorted({c["type"] for c in cases if c["label"] == "malicious"})
    rarity = lambda c: (c["fleet"], c["t"])  # noqa: E731

    def rules_first(names, score=None):
        return lambda c: (-int(rule_raise(c, names)), -(score(c) if score else 0), c["fleet"], c["t"])

    # ---- 1 · each expert alone
    per = {(n, s): expert_stats(cases, slm, n, s) for n in RULES + list(TRAINED) for s in ("dev", "holdout")}

    # ---- 4 · leave one attack type out (computed before the survival table needs it)
    loato = {}
    for T in all_types:
        left = [n for n in RULES if SOURCES[n] - {T}]
        m = train([c for c in cases if c["split"] == "dev" and c["type"] != T])
        x = matrix(cases)
        tr = {name: {c["case_id"]: bool(pi > thr) for c, pi in zip(cases, mod.predict_proba(x)[:, 1])}
              for name, (mod, thr) in m.items()}
        atk = {k: v for k, v in attacks(cases).items() if types.get(k[1]) == T}
        firsts = [v[0] for v in atk.values()]
        rr = [route(c["f"], c["g"], left) for c in firsts]
        hb = [c for c in cases if c["split"] == "holdout" and c["label"] == "benign"]
        keys = [k for k in atk if k[1] in curves]
        s0 = SERVICE_S[0]
        loato[T] = {
            "n": len(atk), "left": left,
            "v1": sum(slm["v1"].get(c["case_id"], (False, 0))[0] for c in firsts),
            "v0": sum(slm["v0"].get(c["case_id"], (False, 0))[0] for c in firsts),
            "rules": sum(bool(r and r[1]) for r in rr), "by": Counter(r[0] for r in rr if r and r[1]),
            "solo": {n: sum(bool(c["solo"][n] and c["solo"][n][0]) for c in firsts) for n in left},
            "tree": sum(tr["tree"][c["case_id"]] for c in firsts), "gbt": sum(tr["gbt"][c["case_id"]] for c in firsts),
            "fa": (sum(rule_raise(c, left) for c in hb), sum(tr["tree"][c["case_id"]] for c in hb),
                   sum(tr["gbt"][c["case_id"]] for c in hb)),
            "tl_n": len(keys),
            "tl": {"today": mean_timeliness(cases, slm_q, curves, starts, keys, s0, rarity),
                   "A": mean_timeliness(cases, slm_q, curves, starts, keys, s0, rules_first(left)),
                   "B": mean_timeliness(cases, slm_q, curves, starts, keys, s0, rarity, lambda c: rule_raise(c, left))},
        }

    # ---- 5 · survival
    surv = []
    for name in RULES + list(TRAINED):
        h = per[(name, "holdout")]
        if h["atk"] == 0:
            hold, hold_s = False, "no: no holdout attack in its behaviour"
        else:
            no_worse = h["e_c"] >= h["v1_c"] and h["e_b"] <= h["v1_b"]
            more = h["e_c"] > h["v1_c"] or h["e_b"] < h["v1_b"]
            hold = no_worse and (more or h["e_c"] > 0)          # same catches, but an expert alert goes out at once
            hold_s = "{}: caught {}/{} vs SLM {}/{}, benign raised {} vs {}{}".format(
                "yes" if hold else "no", h["e_c"], h["atk"], h["v1_c"], h["atk"], h["e_b"], h["v1_b"],
                "" if not hold else (" (catches more)" if more else " (same catches, alert at arrival)"))
        if name in TRAINED:
            ok = all(loato[T][name] >= loato[T]["v1"] for T in all_types)
            lo_s = "; ".join("{} {}/{} (SLM {})".format(T, loato[T][name], loato[T]["n"], loato[T]["v1"]) for T in all_types)
        else:
            own = [T for T in sorted(SOURCES[name]) if T in loato]
            ok = bool(own) and all(name in loato[T]["left"] and loato[T]["solo"][name] >= max(1, loato[T]["v1"]) for T in own)
            lo_s = "; ".join("{}: {}".format(T, "removed (written only from it)" if name not in loato[T]["left"] else
                                             "caught {}/{} (SLM {})".format(loato[T]["solo"][name], loato[T]["n"], loato[T]["v1"]))
                             for T in own)
        surv.append((name, hold, hold_s, ok, lo_s, hold and ok))
    keep = [s[0] for s in surv if s[5]]
    kept_rules = [n for n in keep if n in RULES]
    kept_trained = [n for n in keep if n in TRAINED]

    def kept_raise(c):
        return rule_raise(c, kept_rules) or any(c[t][0] for t in kept_trained)

    configs = {"SLM alone = variant A": lambda c: False,
               "B · kept experts": kept_raise,
               "B · all five rules": lambda c: rule_raise(c, RULES),
               "B · tree": lambda c: c["tree"][0],
               "B · gbt": lambda c: c["gbt"][0],
               "B · all rules + gbt": lambda c: rule_raise(c, RULES) or c["gbt"][0]}
    det = {}
    for b in ("v1", "v0"):
        for cname, raise_fn in configs.items():
            for split in ("dev", "holdout"):
                rows = [c for c in cases if c["split"] == split and c["case_id"] in slm[b]]
                det[(b, cname, split)] = detect(rows, lambda c: slm[b][c["case_id"]][0] or raise_fn(c),
                                                lambda c: 100.0 if raise_fn(c) else slm[b][c["case_id"]][1])
    orders = {"today: fleet rarity, then age": (rarity, None),
              "A · kept experts first": (rules_first(kept_rules), None),
              "A · all rules first": (rules_first(RULES), None),
              "A · all rules, then gbt score": (rules_first(RULES, lambda c: c["gbt"][1]), None),
              "B · kept experts raise": (rarity, kept_raise),
              "B · all five rules raise": (rarity, lambda c: rule_raise(c, RULES))}
    tl = {split: timeliness_table(cases, slm_q, curves, starts, orders, split) for split in ("dev", "holdout")}

    # ---- the report
    L = []
    w = L.append
    if os.path.exists(CONCLUSION):
        L += open(CONCLUSION, encoding="utf-8").read().rstrip("\n").split("\n")
        w("")
    w("## Headline · holdout, prompt v1 baseline")
    w("")
    w("Kept experts: **{}**.".format(", ".join(keep) or "none"))
    w("")
    w("| Variant | Attacks at first case | Benign flagged | AUC | Mean timeliness @ {} s | @ {} s |".format(*SERVICE_S))
    w("|---|---|---|---|---|---|")
    for label, cname, oname in (("SLM alone, today's queue", "SLM alone = variant A", "today: fleet rarity, then age"),
                                ("A · kept experts rank the queue", "SLM alone = variant A", "A · kept experts first"),
                                ("B · kept experts may raise", "B · kept experts", "B · kept experts raise"),
                                ("B · all five rules may raise", "B · all five rules", "B · all five rules raise")):
        d = det[("v1", cname, "holdout")]
        w("| {} | {}/{} | {}/{} | {} | {:.3f} | {:.3f} |".format(label, d["first"], d["attacks"], d["ben_flagged"], d["ben"],
                                                                d["auc"], tl["holdout"][(oname, SERVICE_S[0])][0],
                                                                tl["holdout"][(oname, SERVICE_S[1])][0]))
    w("")
    w("# Detail")
    w("")
    w("Saved Gemma 4 E4B verdicts, no model calls. Baselines: **v1** = prompt v1 on the quick set "
      "(354 cases: all 117 malicious, 173 benign), the prompt the detector starts from; **v0** = prompt v0 on every "
      "dev + holdout case (703 cases, 522 benign). Eval cases unseen. Trained models learn on dev only. "
      "Script: `research/sq1/run.py` (rules in `research/sq1/experts.py`).")
    w("")
    w("Detection columns: attacks flagged at their first case · at any case · malicious cases flagged · benign cases "
      "flagged (false alarms) · AUC malicious vs benign. Context cases are attack activity that earns nothing and costs nothing.")
    w("")
    w("## 1 · Each expert alone, on the cases it claims")
    w("")
    w("A rule claims the cases inside its behaviour (no router here); the trained models claim every case. "
      "\"Caught\" = attacks whose first malicious case the expert claims and calls an attack. The SLM columns are the "
      "same cases: v1 covers only the quick-set cases, v0 all of them.")
    w("")
    w("| Expert | Written from | Split | Claimed: mal · ctx · benign | Expert: caught · benign raised | SLM v1: caught · benign flagged | SLM v0: caught · benign flagged |")
    w("|---|---|---|---|---|---|---|")
    for name in RULES + list(TRAINED):
        for split in ("dev", "holdout"):
            r = per[(name, split)]
            n = r["n"]
            w("| {} | {} | {} | {} · {} · {} | {}/{} · {}/{} | {}/{} · {}/{} | {}/{} · {}/{} |".format(
                name, ", ".join(sorted(SOURCES.get(name, {"dev labels"}))), split, n["malicious"], n["context"], n["benign"],
                r["e_c"], r["atk"], r["e_b"], n["benign"], r["v1_c"], r["atk"], r["v1_b"], r["v1_bn"],
                r["v0_c"], r["atk"], r["v0_b"], r["v0_bn"]))
    w("")
    w("Raise thresholds of the trained models (zero dev false alarms): tree {:.2f}, gbt {:.2f}.".format(
        models["tree"][1], models["gbt"][1]))
    w("")
    w("## 2 · Variants A and B: detection on dev and holdout")
    w("")
    w("| Baseline | Variant | Split | First case | Any case | Malicious flagged | Benign flagged | AUC |")
    w("|---|---|---|---|---|---|---|---|")
    for b in ("v1", "v0"):
        for cname in configs:
            for split in ("dev", "holdout"):
                w("| {} | {} | {} | {} |".format(b, cname, split, fmt_detect(det[(b, cname, split)])))
    w("")
    w("Variant A never changes a verdict, so its rows are the SLM's. B can only add alerts; AUC under B gives an "
      "expert-raised case the top score.")
    w("")
    w("## 3 · Alert time: the case queue replayed")
    w("")
    w("Every dev / holdout triage case arrives at its own timestamp; one SLM worker takes the best waiting case and "
      "needs {} s (typical 8-core target) or {} s (weak target) per verdict; an expert alert under B goes out as the "
      "case arrives. Timeliness is the scorer's per-attack score at that delay after the alert point (2.3), for the "
      "attacks with a measured tempo curve (the validation waves plus training-day windows of the same attacks). "
      "v1 verdicts; v0 for benign window cases outside the quick set, which only occupy the worker. The replay "
      "has no merging of identical pairs and no skipping of alerted processes, so absolute delays are pessimistic; "
      "compare rows, not absolutes.".format(*SERVICE_S))
    w("")
    w("| Queue / alerting | Split | Mean timeliness @ {0} s | Median delay @ {0} s | Mean timeliness @ {1} s | Median delay @ {1} s |".format(*SERVICE_S))
    w("|---|---|---|---|---|---|")
    for split in ("dev", "holdout"):
        for name in orders:
            a, b_ = tl[split][(name, SERVICE_S[0])], tl[split][(name, SERVICE_S[1])]
            w("| {} | {} ({} attacks) | {:.3f} | {:.1f} s | {:.3f} | {:.1f} s |".format(name, split, a[2], a[0], a[1], b_[0], b_[1]))
    w("")
    key_auc = lambda f: auc([f(c) for c in cases if c["label"] == "malicious"], [f(c) for c in cases if c["label"] == "benign"])  # noqa: E731
    w("Ranking quality of the queue key alone (AUC malicious vs benign, all dev + holdout cases): fleet rarity "
      "{:.3f} · kept experts first {:.3f} · all rules first {:.3f} · all rules then gbt {:.3f}.".format(
          key_auc(lambda c: -c["fleet"]), key_auc(lambda c: rule_raise(c, kept_rules) * 1000 - c["fleet"]),
          key_auc(lambda c: rule_raise(c, RULES) * 1000 - c["fleet"]), key_auc(lambda c: rule_raise(c, RULES) * 2 + c["gbt"][1])))
    w("")
    w("## 4 · Leave one attack type out")
    w("")
    w("For each attack type T: rules written only from T are removed (a rule written from several types stays), and "
      "both trained models are retrained on dev without T (threshold again at zero training false alarms). Measured "
      "on T's attacks in dev + holdout at their first case. Benign raised = holdout benign cases the T-less experts "
      "raise. Timeliness @ {} s on T's attacks with a tempo curve: today's queue · A with the T-less rules ranking · "
      "B with the T-less rules raising.".format(SERVICE_S[0]))
    w("")
    w("| Held out T | Attacks | SLM v1 | SLM v0 | Rules left | Rules caught (by) | tree | gbt | Holdout benign raised: rules · tree · gbt | Timeliness today · A · B |")
    w("|---|---|---|---|---|---|---|---|---|---|")
    fmt_t = lambda v: "-" if v is None else "{:.2f}".format(v)  # noqa: E731
    for T in all_types:
        r = loato[T]
        w("| {} | {} | {}/{} | {}/{} | {} | {}/{} ({}) | {}/{} | {}/{} | {} · {} · {} | {} · {} · {} |".format(
            T, r["n"], r["v1"], r["n"], r["v0"], r["n"], len(r["left"]), r["rules"], r["n"],
            ", ".join("{} {}".format(k, v) for k, v in r["by"].items()) or "-", r["tree"], r["n"], r["gbt"], r["n"],
            *r["fa"], *(fmt_t(r["tl"][k]) for k in ("today", "A", "B"))))
    w("")
    w("## 5 · Which experts survive")
    w("")
    w("| Expert | Holdout: beats SLM v1 on its own cases? | LOATO: with its own type held out, still at least the SLM there? | Verdict |")
    w("|---|---|---|---|")
    for name, hold, hold_s, ok, lo_s, kept in surv:
        w("| {} | {} | {}: {} | **{}** |".format(name, hold_s, "yes" if ok else "no", lo_s, "keep" if kept else "drop"))
    w("")
    w("## 6 · Evidence an expert hands the explanation")
    w("")
    shown = set()
    for c in sorted(cases, key=lambda c: (c["split"], c["t"])):
        for n in RULES:
            s = c["solo"][n]
            if s and s[0] and n not in shown and c["label"] == "malicious":
                shown.add(n)
                w("- `{}` · {} → {}".format(c["case_id"], n, "; ".join(s[1])))
    ex = max((c for c in cases if c["split"] == "holdout" and c["label"] == "malicious"), key=lambda c: c["tree"][1])
    w("- `{}` · tree (p={:.2f}, raise threshold {:.2f}) → {}".format(
        ex["case_id"], ex["tree"][1], models["tree"][1], " → ".join(tree_path(models["tree"][0], matrix([ex])[0]))))
    imp = sorted(zip(FEATURES, models["gbt"][0].feature_importances_), key=lambda t: -t[1])[:6]
    w("- gbt: top features by importance: " + ", ".join("{} {:.2f}".format(k, v) for k, v in imp))
    w("")

    with open(os.path.join(OUT, "sq1_results.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
