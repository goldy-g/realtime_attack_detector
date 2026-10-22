"""SQ-1 offline: experts for known behaviours, the SLM for the rest.

Reuses the saved Gemma 4 E4B verdicts (no model calls) and measures two variants:

  A  feed and rank  experts only reorder the case queue (and would add evidence);
                    the SLM makes every decision, so recall / false alarms / AUC are
                    the SLM's and the only measurable change is how soon each
                    attack's case reaches the model.
  B  raise          an expert may raise an alert at once; it never clears a case,
                    so a "normal" from an expert still goes to the SLM.

Experts: the five rules in experts.py (behind a router); three small trained models
(a depth-3 decision tree and gradient-boosted trees on the rules' named facts, and a
character n-gram logistic regression, "ngram", on the case text the SLM reads, with user,
host, time and address names masked); and Laya, the zero-shot encoder from 2.10, through
its saved scores (quick set only). Trained models learn on dev only; holdout is only
checked. Eval cases stay unseen.

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
import re
import statistics
import sys
import warnings
from collections import Counter, defaultdict
from datetime import datetime

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.tree import DecisionTreeClassifier

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from experts import EXPERTS, OFFICE, SOURCES, flags, parse, route  # noqa: E402

warnings.filterwarnings("ignore", message="Unknown solver options")   # scipy vs scikit-learn 1.5 noise, harmless

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CACHE = os.path.join(ROOT, "data", "cache", "research")
OUT = os.path.join(ROOT, "research", "out")
SERVICE_S = (1.7, 3.4)                  # seconds per verdict on a typical / weak 8-core target (FINDINGS 2.9)
TRAINED = ("tree", "gbt", "ngram")
LAYA = "laya"                           # zero-shot, saved p(attack) from the "attack or normal" question
# Names the text model must not learn: the red team's accounts (domain accounts keep only "admin or not"),
# machines, user folders, clock times and addresses.
MASKS = [(re.compile(r"SYSTEMIACOM\\[^\s:,;]+", re.I),
          lambda m: "DOMAIN\\admin" if "administrator" in m.group(0).lower() else "DOMAIN\\user"),
         (re.compile(r"host-[0-9a-f]{4}"), lambda m: "host"),
         (re.compile(r"\\users\\[^\\\s\"]+", re.I), lambda m: "\\users\\name"),
         (re.compile(r"\d{4}-\d\d-\d\d"), lambda m: "date"),
         (re.compile(r"\d\d:\d\d:\d\d(\.\d+)?"), lambda m: "time"),
         (re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b"), lambda m: "ip")]


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


def masked(text: str) -> str:
    for rx, repl in MASKS:
        text = rx.sub(repl, text)
    return text


def inputs(name: str, cases: list[dict]):
    """What each trained model reads: the named facts, or the masked case text."""
    return [masked(c["text"]) for c in cases] if name == "ngram" else matrix(cases)


def train(cases: list[dict]) -> dict:
    """The trained experts on malicious (1) vs benign (0); context and excused cases are left out.

    The raise threshold is the highest score any training benign case got: zero
    training false alarms, the strictest setting that still lets a model raise.
    """
    rows = [c for c in cases if c["label"] in ("malicious", "benign")]
    y = np.array([c["label"] == "malicious" for c in rows], dtype=int)
    models = {"tree": DecisionTreeClassifier(max_depth=3, class_weight="balanced", random_state=0),
              "gbt": GradientBoostingClassifier(n_estimators=100, max_depth=2, learning_rate=0.1, random_state=0),
              "ngram": make_pipeline(TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True),
                                    LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000))}
    out = {}
    for name, m in models.items():
        x = inputs(name, rows)
        m.fit(x, y)
        p = m.predict_proba(x)[:, 1]
        out[name] = (m, float(max(p[y == 0])) if (y == 0).any() else 0.5)
    return out


def predict(models: dict, cases: list[dict]) -> dict:
    """name -> (raise flags, scores) for every case."""
    out = {}
    for name, (m, thr) in models.items():
        p = m.predict_proba(inputs(name, cases))[:, 1]
        out[name] = (p > thr, p)
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
    for name, (flag, p) in predict(models, cases).items():
        for c, fi, pi in zip(cases, flag, p):
            c[name] = (bool(fi), float(pi))


def text_terms(models: dict, k: int = 10) -> list[str]:
    """The character n-grams that push the text model hardest toward "attack"."""
    vec, lr = models["ngram"][0].named_steps.values()
    terms = vec.get_feature_names_out()
    return [repr(terms[i]) for i in np.argsort(-lr.coef_[0])[:k]]


def load_laya() -> dict:
    """case_id -> Laya's zero-shot p(attack) for the "attack or normal" question (quick set, research/score_laya.py)."""
    rows = map(json.loads, open(os.path.join(CACHE, "scores", "Laya.quick.jsonl"), encoding="utf-8"))
    return {r["case_id"]: r["p_choice"] for r in rows if r.get("p_choice") is not None}


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


MODELS = list(TRAINED) + [LAYA]              # experts that claim every case (Laya: every quick-set case)


def claims(name: str, c: dict) -> bool:
    if name == LAYA:
        return c[LAYA][1] is not None
    return name in TRAINED or c["solo"][name] is not None


def raises(name: str, c: dict) -> bool:
    return c[name][0] if name in MODELS else bool(c["solo"][name] and c["solo"][name][0])


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
    laya = load_laya()
    laya_thr = max(laya[c["case_id"]] for c in cases
                   if c["split"] == "dev" and c["label"] == "benign" and c["case_id"] in laya)
    for c in cases:
        p = laya.get(c["case_id"])
        c[LAYA] = (p is not None and p > laya_thr, p)
    all_types = sorted({c["type"] for c in cases if c["label"] == "malicious"})
    rarity = lambda c: (c["fleet"], c["t"])  # noqa: E731

    def rules_first(names, score=None):
        return lambda c: (-int(rule_raise(c, names)), -(score(c) if score else 0), c["fleet"], c["t"])

    def score_first(name):
        return lambda c: (-(c[name][1] if c[name][1] is not None else -1), c["fleet"], c["t"])

    # ---- 1 · each expert alone
    per = {(n, s): expert_stats(cases, slm, n, s) for n in RULES + MODELS for s in ("dev", "holdout")}

    # ---- 4 · leave one attack type out (computed before the survival table needs it)
    loato = {}
    for T in all_types:
        left = [n for n in RULES if SOURCES[n] - {T}]
        pr = predict(train([c for c in cases if c["split"] == "dev" and c["type"] != T]), cases)
        tr = {name: {c["case_id"]: bool(f) for c, f in zip(cases, flag)} for name, (flag, _) in pr.items()}
        tr[LAYA] = {c["case_id"]: c[LAYA][0] for c in cases}     # zero-shot: never trained, threshold from dev benign only
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
            "m": {n: sum(tr[n][c["case_id"]] for c in firsts) for n in MODELS},
            "fa": {"rules": sum(rule_raise(c, left) for c in hb), **{n: sum(tr[n][c["case_id"]] for c in hb) for n in MODELS}},
            "laya_scored": sum(c[LAYA][1] is not None for c in firsts),
            "tl_n": len(keys),
            "tl": {"today": mean_timeliness(cases, slm_q, curves, starts, keys, s0, rarity),
                   "A": mean_timeliness(cases, slm_q, curves, starts, keys, s0, rules_first(left)),
                   "B": mean_timeliness(cases, slm_q, curves, starts, keys, s0, rarity, lambda c: rule_raise(c, left)),
                   **{"A_" + n: mean_timeliness(cases, slm_q, curves, starts, keys, s0,
                                                (lambda sc: lambda c: (-sc[c["case_id"]], c["fleet"], c["t"]))(
                                                    {c["case_id"]: p for c, p in zip(cases, pr[n][1])}))
                      for n in ("gbt", "ngram")}},
        }

    # ---- 5 · survival
    surv = []
    for name in RULES + MODELS:
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
        if name in MODELS:
            ok = all(loato[T]["m"][name] >= loato[T]["v1"] for T in all_types)
            lo_s = "; ".join("{} {}/{} (SLM {})".format(T, loato[T]["m"][name], loato[T]["n"], loato[T]["v1"]) for T in all_types)
        else:
            own = [T for T in sorted(SOURCES[name]) if T in loato]
            ok = bool(own) and all(name in loato[T]["left"] and loato[T]["solo"][name] >= max(1, loato[T]["v1"]) for T in own)
            lo_s = "; ".join("{}: {}".format(T, "removed (written only from it)" if name not in loato[T]["left"] else
                                             "caught {}/{} (SLM {})".format(loato[T]["solo"][name], loato[T]["n"], loato[T]["v1"]))
                             for T in own)
        surv.append((name, hold, hold_s, ok, lo_s, hold and ok))
    keep = [s[0] for s in surv if s[5]]
    kept_rules = [n for n in keep if n in RULES]
    kept_models = [n for n in keep if n in MODELS]

    def kept_raise(c):
        return rule_raise(c, kept_rules) or any(c[t][0] for t in kept_models)

    configs = {"SLM alone = variant A": lambda c: False,
               "B · kept experts": kept_raise,
               "B · all five rules": lambda c: rule_raise(c, RULES),
               "B · tree": lambda c: c["tree"][0],
               "B · gbt": lambda c: c["gbt"][0],
               "B · ngram": lambda c: c["ngram"][0],
               "B · laya": lambda c: c[LAYA][0],
               "B · all rules + gbt": lambda c: rule_raise(c, RULES) or c["gbt"][0]}
    det = {}
    for b in ("v1", "v0"):
        for cname, raise_fn in configs.items():
            if b == "v0" and cname == "B · laya":
                continue                    # Laya has no score for the benign window cases outside the quick set
            for split in ("dev", "holdout"):
                rows = [c for c in cases if c["split"] == split and c["case_id"] in slm[b]]
                det[(b, cname, split)] = detect(rows, lambda c: slm[b][c["case_id"]][0] or raise_fn(c),
                                                lambda c: 100.0 if raise_fn(c) else slm[b][c["case_id"]][1])
    kept_first = lambda c: (-int(kept_raise(c)), c["fleet"], c["t"])  # noqa: E731
    orders = {"today: fleet rarity, then age": (rarity, None),
              "A · kept experts first": (kept_first, None),
              "A · all rules first": (rules_first(RULES), None),
              "A · all rules, then gbt score": (rules_first(RULES, lambda c: c["gbt"][1]), None),
              "A · gbt score first": (score_first("gbt"), None),
              "A · ngram score first": (score_first("ngram"), None),
              "B · kept experts raise": (rarity, kept_raise),
              "B · all five rules raise": (rarity, lambda c: rule_raise(c, RULES))}
    tl = {split: timeliness_table(cases, slm_q, curves, starts, orders, split) for split in ("dev", "holdout")}
    # Laya scored only the quick set, which holds every case of the validation waves: compare queues there.
    wave_cases = [c for c in cases if c["source"] == "wave"]
    orders_w = {"today: fleet rarity, then age": (rarity, None),
                "A · kept experts first": (kept_first, None),
                "A · laya score first": (score_first(LAYA), None),
                "A · kept experts, then laya score": (lambda c: (-int(kept_raise(c)), -c[LAYA][1], c["fleet"], c["t"]), None),
                "B · laya raises": (rarity, lambda c: c[LAYA][0])}
    tl_w = {split: timeliness_table(wave_cases, slm_q, curves, starts, orders_w, split) for split in ("dev", "holdout")}

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
                                ("A · trained gbt ranks the queue", "SLM alone = variant A", "A · gbt score first"),
                                ("A · trained ngram ranks the queue", "SLM alone = variant A", "A · ngram score first"),
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
    w("A rule claims the cases inside its behaviour (no router here); the trained models claim every case, Laya every "
      "quick-set case (the only ones it scored). \"Caught\" = attacks whose first malicious case the expert claims and "
      "calls an attack. The SLM columns are the same cases: v1 covers only the quick-set cases, v0 all of them.")
    w("")
    w("| Expert | Written from | Split | Claimed: mal · ctx · benign | Expert: caught · benign raised | SLM v1: caught · benign flagged | SLM v0: caught · benign flagged |")
    w("|---|---|---|---|---|---|---|")
    origin = {LAYA: "zero-shot (never trained)"}
    for name in RULES + MODELS:
        for split in ("dev", "holdout"):
            r = per[(name, split)]
            n = r["n"]
            w("| {} | {} | {} | {} · {} · {} | {}/{} · {}/{} | {}/{} · {}/{} | {}/{} · {}/{} |".format(
                name, origin.get(name) or ", ".join(sorted(SOURCES.get(name, {"dev labels"}))), split,
                n["malicious"], n["context"], n["benign"],
                r["e_c"], r["atk"], r["e_b"], n["benign"], r["v1_c"], r["atk"], r["v1_b"], r["v1_bn"],
                r["v0_c"], r["atk"], r["v0_b"], r["v0_bn"]))
    w("")
    w("Raise thresholds (zero dev false alarms): tree {:.2f}, gbt {:.2f}, ngram {:.2f}, laya {:.3f}. Laya's "
      "zero-shot AUC on this set is 0.792 for this question (0.761 for its yes/no question; research/out/score_laya.md), "
      "against 0.956 for the SLM with prompt v1.".format(models["tree"][1], models["gbt"][1], models["ngram"][1], laya_thr))
    w("")
    w("## 2 · Variants A and B: detection on dev and holdout")
    w("")
    w("| Baseline | Variant | Split | First case | Any case | Malicious flagged | Benign flagged | AUC |")
    w("|---|---|---|---|---|---|---|---|")
    for b in ("v1", "v0"):
        for cname in configs:
            for split in ("dev", "holdout"):
                if (b, cname, split) in det:
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
    def key_auc(f, rows=cases):
        return auc([f(c) for c in rows if c["label"] == "malicious"], [f(c) for c in rows if c["label"] == "benign"])

    quick = [c for c in cases if c[LAYA][1] is not None]
    w("Ranking quality of the queue key alone (AUC malicious vs benign). All dev + holdout cases: fleet rarity "
      "{:.3f} · kept experts first {:.3f} · all rules first {:.3f} · all rules then gbt {:.3f} · gbt {:.3f} · ngram {:.3f}. "
      "Quick set (where Laya has scores): fleet rarity {:.3f} · laya {:.3f} · gbt {:.3f} · ngram {:.3f}. The trained "
      "models' AUCs include their own dev training cases; the holdout-only AUCs are gbt {:.3f} and ngram {:.3f}.".format(
          key_auc(lambda c: -c["fleet"]), key_auc(lambda c: kept_raise(c) * 1000 - c["fleet"]),
          key_auc(lambda c: rule_raise(c, RULES) * 1000 - c["fleet"]), key_auc(lambda c: rule_raise(c, RULES) * 2 + c["gbt"][1]),
          key_auc(lambda c: c["gbt"][1]), key_auc(lambda c: c["ngram"][1]),
          key_auc(lambda c: -c["fleet"], quick), key_auc(lambda c: c[LAYA][1], quick),
          key_auc(lambda c: c["gbt"][1], quick), key_auc(lambda c: c["ngram"][1], quick),
          key_auc(lambda c: c["gbt"][1], [c for c in cases if c["split"] == "holdout"]),
          key_auc(lambda c: c["ngram"][1], [c for c in cases if c["split"] == "holdout"])))
    w("")
    w("**Laya as a queue key.** Laya scored only the quick set, which holds every case of the validation waves, so "
      "these queues replay the wave cases alone (15 dev and 7 holdout attacks); the first two rows repeat the main "
      "table's queues on the same cases for a like-for-like comparison.")
    w("")
    w("| Queue / alerting | Split | Mean timeliness @ {0} s | Median delay @ {0} s | Mean timeliness @ {1} s | Median delay @ {1} s |".format(*SERVICE_S))
    w("|---|---|---|---|---|---|")
    for split in ("dev", "holdout"):
        for name in orders_w:
            a, b_ = tl_w[split][(name, SERVICE_S[0])], tl_w[split][(name, SERVICE_S[1])]
            w("| {} | {} ({} attacks) | {:.3f} | {:.1f} s | {:.3f} | {:.1f} s |".format(name, split, a[2], a[0], a[1], b_[0], b_[1]))
    w("")
    w("## 4 · Leave one attack type out")
    w("")
    w("For each attack type T: rules written only from T are removed (a rule written from several types stays), and "
      "the three trained models are retrained on dev without T (threshold again at zero training false alarms). "
      "Laya was never trained on these labels and its threshold comes from dev benign cases only, so its row is "
      "already a held-out result. Measured on T's attacks in dev + holdout at their first case. Benign raised = "
      "holdout benign cases the T-less experts raise (Laya: quick-set holdout benign only). Timeliness @ {} s on T's "
      "attacks with a tempo curve: today's queue · A with the T-less rules ranking · B with the T-less rules "
      "raising · A with the T-less gbt ranking · A with the T-less ngram ranking.".format(SERVICE_S[0]))
    w("")
    w("| Held out T | Attacks | SLM v1 | SLM v0 | Rules left | Rules caught (by) | tree | gbt | ngram | laya | Holdout benign raised: rules · tree · gbt · ngram · laya | Timeliness today · A rules · B rules · A gbt · A ngram |")
    w("|---|---|---|---|---|---|---|---|---|---|---|---|")
    fmt_t = lambda v: "-" if v is None else "{:.2f}".format(v)  # noqa: E731
    for T in all_types:
        r = loato[T]
        w("| {} | {} | {}/{} | {}/{} | {} | {}/{} ({}) | {} | {} · {} | {} |".format(
            T, r["n"], r["v1"], r["n"], r["v0"], r["n"], len(r["left"]), r["rules"], r["n"],
            ", ".join("{} {}".format(k, v) for k, v in r["by"].items()) or "-",
            " | ".join("{}/{}".format(r["m"][n], r["n"]) for n in MODELS),
            r["fa"]["rules"], " · ".join(str(r["fa"][n]) for n in MODELS),
            " · ".join(fmt_t(r["tl"][k]) for k in ("today", "A", "B", "A_gbt", "A_ngram"))))
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
    w("- ngram: the character n-grams that push hardest toward \"attack\": " + ", ".join(text_terms(models)))
    w("- laya: a probability only; it gives no reason a reader or the SLM could check.")
    w("")

    with open(os.path.join(OUT, "sq1_results.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
