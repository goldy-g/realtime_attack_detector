"""SQ-1 follow-up: can better cleaning, features or models make a trained expert beat the SLM?

Same data, splits and tests as run.py: train on dev, raise above the highest score a training
benign case got, check the 9 holdout attacks at their first case, then leave each attack type
out of training. One row per training setup, each adding one change:

  G0  gbt as in run.py
  G1  + cleaning: drop "malicious" cases that are system plumbing (svchost / lsass network
        traffic during the WMI attack, nothing the attacker wrote), and weight attack types
        equally (one attack type, WMI, is 64 of the 70 dev attack cases)
  G2  + concept features suggested by the dev attacks and general security knowledge:
        an application that never starts code starts a shell or script host; how many
        PowerShell stealth markers; a URL in a shell command; a process that started
        seconds ago calls a public address
  G3  + concept features suggested only by the holdout attacks (hindsight, so optimistic):
        a program run from a user folder, also as the child of an application; a public
        destination on a non-web port
  G4  G3 with monotonic gradient boosting (a suspicious marker can never lower the score)
  G5  concepts only: G2's concept features plus generic context (fleet rarity, public or
        private, user, ports), with no program names and no single PowerShell flags, so the
        model cannot lean on "it is PowerShell"
  G6  G5 + G3's hindsight concepts
  N0  ngram as in run.py
  N1  ngram on cleaned text (the event's own lines, no recent-activity lines, base64 blobs
        dropped, decoded commands kept) + G1 cleaning
  N2  N1's text cleaning alone;  N3  G1 cleaning alone (full text)
  ·H  a setup with an honest threshold: the highest out-of-fold dev benign score (5 folds
        grouped by machine) instead of the in-sample one

    data/cache/sq1-venv/bin/python research/sq1/train_better.py

Writes research/out/sq1_training.md.
"""

from __future__ import annotations

import os

for _v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "VECLIB_MAXIMUM_THREADS"):
    os.environ.setdefault(_v, "1")          # one core: a real-time detector run may be timing itself on this CPU

import re  # noqa: E402
import sys  # noqa: E402
import warnings  # noqa: E402
from collections import Counter  # noqa: E402

import numpy as np  # noqa: E402
from sklearn.ensemble import GradientBoostingClassifier, HistGradientBoostingClassifier  # noqa: E402
from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.model_selection import GroupKFold  # noqa: E402
from sklearn.pipeline import make_pipeline  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run  # noqa: E402
from experts import LOLBINS, SHELLS, USER_DIR  # noqa: E402

warnings.filterwarnings("ignore", message="Unknown solver options")

NOTES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "training_conclusion.md")
CODE = SHELLS | LOLBINS
NORMAL_LAUNCHERS = {"explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "services.exe", "svchost.exe",
                    "userinit.exe", "winlogon.exe", "wininit.exe", "smss.exe", "csrss.exe", "taskeng.exe",
                    "taskhostw.exe", "runtimebroker.exe", "sihost.exe"}
PLUMBING = {"svchost.exe", "lsass.exe"}
URL = re.compile(r"https?://|\\\\[a-z0-9.-]+\\", re.I)
B64_BLOB = re.compile(r"[A-Za-z0-9+/=]{40,}")
STARTED = re.compile(r"^Process: \S+ started (\d\d):(\d\d):(\d\d)", re.M)
UP = {"parent_wmi", "parent_office", "parent_updater", "child_shell", "child_lolbin", "child_powershell", "ps_encoded",
      "ps_hidden", "ps_noprofile", "cradle", "long_b64", "user_dir", "dest_public", "fleet0", "unusual_launch",
      "stealth_count", "url_in_shell", "young_public_call", "runs_from_user_dir", "app_starts_user_dir_program",
      "public_nonweb"}
DOWN = {"fleet_log"}
SETUPS = [
    {"name": "G0", "what": "gbt as in run.py", "model": "gbt", "clean": False, "concepts": 0},
    {"name": "G1", "what": "+ cleaning, attack types weighted equally", "model": "gbt", "clean": True, "concepts": 0},
    {"name": "G2", "what": "+ concept features from the dev attacks", "model": "gbt", "clean": True, "concepts": 1},
    {"name": "G3", "what": "+ concept features from the holdout attacks (hindsight)", "model": "gbt", "clean": True, "concepts": 2},
    {"name": "G4", "what": "G3, monotonic boosting", "model": "hgb", "clean": True, "concepts": 2},
    {"name": "G5", "what": "concepts only, no program names", "model": "gbt", "clean": True, "concepts": 1, "only": True},
    {"name": "G6", "what": "G5 + hindsight concepts", "model": "gbt", "clean": True, "concepts": 2, "only": True},
    {"name": "N0", "what": "ngram as in run.py", "model": "ngram", "clean": False, "text": "full"},
    {"name": "N1", "what": "ngram on cleaned text + cleaning", "model": "ngram", "clean": True, "text": "event"},
    {"name": "N2", "what": "N1's text cleaning alone", "model": "ngram", "clean": False, "text": "event"},
    {"name": "N3", "what": "G1's cleaning alone (full text)", "model": "ngram", "clean": True, "text": "full"},
    {"name": "G2H", "what": "G2 with an honest (out-of-fold) threshold", "model": "gbt", "clean": True, "concepts": 1, "oof": True},
    {"name": "G5H", "what": "G5 with an honest (out-of-fold) threshold", "model": "gbt", "clean": True, "concepts": 1, "only": True, "oof": True},
    {"name": "N1H", "what": "N1 with an honest (out-of-fold) threshold", "model": "ngram", "clean": True, "text": "event", "oof": True},
]
# What a concepts-only model may read: no program names, no single PowerShell flag.
GENERIC = {"is_flow", "fleet0", "fleet_log", "parent_unseen", "user_system", "user_admin", "dest_public", "port_web",
           "port_high", "udp", "recent", "cmd_len_log", "long_b64"}


def first_path(cmd: str) -> str:
    cmd = cmd.strip()
    return cmd[1:].split('"', 1)[0] if cmd.startswith('"') else cmd.split(" ", 1)[0]


def seconds(h, m, s) -> int:
    return int(h) * 3600 + int(m) * 60 + int(s)


def concepts(c: dict, level: int) -> dict:
    """Security concepts that can carry from one attack type to another."""
    if level == 0:
        return {}
    f, g = c["f"], c["g"]
    proc = c["kind"] == "process"
    parent = f["parent"].get("img", "")
    launcher_app = proc and bool(parent) and parent not in NORMAL_LAUNCHERS and parent != f["image"]
    age = None
    m = STARTED.search(c["text"]) if not proc else None
    if m:
        age = (seconds(*c["ts"][11:19].split(":")) - seconds(*m.groups())) % 86400
    out = {"unusual_launch": launcher_app and f["image"] in CODE,
           "stealth_count": g["ps_encoded"] + g["ps_hidden"] + g["ps_noprofile"] + g["cradle"],
           "url_in_shell": proc and f["image"] in CODE and bool(URL.search(f["cmd"])),
           "young_public_call": (not proc) and f["public"] and age is not None and age <= 10}
    if level >= 2:
        from_user = bool(USER_DIR.search(first_path(f["cmd"])))
        out.update({"runs_from_user_dir": from_user, "app_starts_user_dir_program": launcher_app and from_user,
                    "public_nonweb": (not proc) and f["public"] and f["port"] not in (80, 443)})
    return out


def event_text(c: dict) -> str:
    """The case without its recent-activity lines and machine line, base64 blobs dropped, names masked."""
    lines = c["text"].split("\n")
    cut = next((i for i, line in enumerate(lines) if line.startswith("Recent activity")), len(lines))
    return run.masked(B64_BLOB.sub(" b64 ", "\n".join(lines[1:cut])))


def training_rows(cases: list[dict], setup: dict) -> list[dict]:
    rows = [c for c in cases if c["label"] in ("malicious", "benign")]
    if setup["clean"]:
        rows = [c for c in rows if not (c["label"] == "malicious" and c["kind"] == "flow" and c["f"]["image"] in PLUMBING)]
    return rows


def weights(rows: list[dict], setup: dict) -> np.ndarray | None:
    """Each attack type gets the same total weight, and all attacks together weigh as much as all benign cases."""
    if not setup["clean"]:
        return None
    per_type = Counter(c["type"] for c in rows if c["label"] == "malicious")
    n_ben = sum(c["label"] == "benign" for c in rows)
    w = np.array([1 / (len(per_type) * per_type[c["type"]]) if c["label"] == "malicious" else 1 / n_ben for c in rows])
    return w * len(rows) / w.sum()


class Expert:
    """One training setup, fitted: the model, its feature keys and its raise threshold."""

    def __init__(self, setup: dict, cases: list[dict]):
        self.setup = setup
        rows = training_rows(cases, setup)
        self.keys = list(rows[0]["g"]) + list(concepts(rows[0], setup.get("concepts", 0)))
        if setup.get("only"):
            self.keys = [k for k in self.keys if k in GENERIC or k not in rows[0]["g"]]
        y = np.array([c["label"] == "malicious" for c in rows], dtype=int)
        w = weights(rows, setup)
        self.model = self._fit(rows, y, w)
        if setup.get("oof"):
            groups = [c["machine"] for c in rows]
            oof = np.zeros(len(rows))
            for tr, te in GroupKFold(n_splits=5).split(rows, y, groups):
                m = self._fit([rows[i] for i in tr], y[tr], None if w is None else w[tr])
                oof[te] = m.predict_proba(self._x([rows[i] for i in te]))[:, 1]
            self.thr = float(oof[y == 0].max())
        else:
            self.thr = float(self.model.predict_proba(self._x(rows))[:, 1][y == 0].max())

    def _x(self, rows: list[dict]):
        s = self.setup
        if s["model"] == "ngram":
            return [event_text(c) if s["text"] == "event" else run.masked(c["text"]) for c in rows]
        level = s.get("concepts", 0)
        return np.array([[float({**c["g"], **concepts(c, level)}[k]) for k in self.keys] for c in rows])

    def _fit(self, rows, y, w):
        s = self.setup
        x = self._x(rows)
        if s["model"] == "ngram":
            m = make_pipeline(TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True),
                              LogisticRegression(C=1.0, class_weight=None if w is not None else "balanced", max_iter=2000))
            return m.fit(x, y, logisticregression__sample_weight=w)
        if s["model"] == "hgb":
            cst = [1 if k in UP else -1 if k in DOWN else 0 for k in self.keys]
            m = HistGradientBoostingClassifier(max_depth=3, learning_rate=0.1, max_iter=200, min_samples_leaf=5,
                                               l2_regularization=1.0, monotonic_cst=cst, random_state=0)
            return m.fit(x, y, sample_weight=w)
        m = GradientBoostingClassifier(n_estimators=100, max_depth=2, learning_rate=0.1, random_state=0)
        return m.fit(x, y, sample_weight=w)

    def scores(self, cases: list[dict]) -> dict:
        return dict(zip((c["case_id"] for c in cases), self.model.predict_proba(self._x(cases))[:, 1]))


def main() -> None:
    cases = run.load_cases()
    types = run.type_of()
    for c in cases:
        c["type"] = types.get(c["attack_id"]) if c["attack_id"] else None
    slm = run.load_slm("quickv1")
    dev = [c for c in cases if c["split"] == "dev"]
    hold = [c for c in cases if c["split"] == "holdout"]
    hold_ben = [c for c in hold if c["label"] == "benign"]
    firsts_h = {k: v[0] for k, v in run.attacks(hold).items()}              # holdout: (wave, attack_id) -> first case
    unseen = {types[k[1]]: c for k, c in firsts_h.items() if types[k[1]] in ("updater", "payload_flow")}
    all_types = sorted({c["type"] for c in cases if c["label"] == "malicious"})
    firsts_all = {}
    for (wave, aid), v in run.attacks(cases).items():
        firsts_all.setdefault(types[aid], []).append(v[0])

    L = []
    w = L.append
    if os.path.exists(NOTES):
        L += open(NOTES, encoding="utf-8").read().rstrip("\n").split("\n")
        w("")
    w("## Results")
    w("")
    w("Holdout: 9 attacks (7 WMI PowerShell, the updater, the payload connection) and 113 benign cases. "
      "\"Benign above\" = holdout benign cases scoring at or above that attack's first case: the false alarms "
      "it would cost to catch it by lowering the threshold. Leave-one-type-out: retrained on dev without the "
      "type, then T's attacks in dev + holdout at their first case. SLM rows: Gemma 4 E4B with prompt v1 (benign "
      "counted over the 29 holdout benign cases of the quick set) and prompt v0 (all 113). \"Plumbing\" = the "
      "svchost / lsass network cases labelled malicious, left out of the AUC so cleaned and uncleaned setups "
      "compare fairly.")
    w("")
    w("| Setup | What changed | Holdout caught (of 9) | Holdout false alarms, of 113 (of them also flagged by SLM v0) | AUC without plumbing | Benign above: updater · payload | Leave-one-type-out caught: " +
      " · ".join(all_types) + " | Leave-one-type-out false alarms (worst T) | Threshold |")
    w("|---|---|---|---|---|---|---|---|---|")
    plumbing = lambda c: c["label"] == "malicious" and c["kind"] == "flow" and c["f"]["image"] in PLUMBING  # noqa: E731
    pos_h = [c for c in hold if c["label"] == "malicious" and not plumbing(c)]
    slm0 = run.load_slm("full")
    slm0_fa = {c["case_id"] for c in hold_ben if slm0[c["case_id"]][0]}
    v_types = {}
    for tag, verdicts in (("v1", slm), ("v0", slm0)):
        v_types[tag] = {T: sum(verdicts.get(c["case_id"], (False, 0))[0] for c in firsts_all[T]) for T in all_types}
        ben = [c for c in hold_ben if c["case_id"] in verdicts]
        a_ = run.auc([verdicts[c["case_id"]][1] for c in pos_h if c["case_id"] in verdicts], [verdicts[c["case_id"]][1] for c in ben])
        w("| SLM {} | Gemma 4 E4B, prompt {} | {}/9 | {}/{} | {:.3f} | - · - | {} | - | - |".format(
            tag, tag, sum(verdicts.get(c["case_id"], (False, 0))[0] for c in firsts_h.values()),
            sum(verdicts[c["case_id"]][0] for c in ben), len(ben), a_,
            " · ".join("{}/{}".format(v_types[tag][T], len(firsts_all[T])) for T in all_types)))
    v1_types = v_types["v1"]
    summary = {}
    for setup in SETUPS:
        ex = Expert(setup, dev)
        sc = ex.scores(cases)
        caught = [types[k[1]] for k, c in firsts_h.items() if sc[c["case_id"]] > ex.thr]
        missed = sorted({types[k[1]] for k, c in firsts_h.items() if sc[c["case_id"]] <= ex.thr})
        fa = {c["case_id"] for c in hold_ben if sc[c["case_id"]] > ex.thr}
        a = run.auc([sc[c["case_id"]] for c in pos_h], [sc[c["case_id"]] for c in hold_ben])
        above = {T: sum(sc[b["case_id"]] >= sc[c["case_id"]] for b in hold_ben) for T, c in unseen.items()}
        lo, lo_fa = {}, 0
        for T in all_types:
            ex_t = Expert(setup, [c for c in dev if c["type"] != T])
            sc_t = ex_t.scores(firsts_all[T] + hold_ben)
            lo[T] = sum(sc_t[c["case_id"]] > ex_t.thr for c in firsts_all[T])
            lo_fa = max(lo_fa, sum(sc_t[c["case_id"]] > ex_t.thr for c in hold_ben))
        summary[setup["name"]] = {"caught": len(caught), "benign": len(fa), "extra": len(fa - slm0_fa), "lo": lo, "lo_fa": lo_fa}
        w("| {} | {} | {}/9{} | {} ({}) | {:.3f} | {} · {} | {} | {} | {:.2f} |".format(
            setup["name"], setup["what"], len(caught), " (missed: {})".format(", ".join(missed)) if missed else "",
            len(fa), len(fa & slm0_fa), a, above["updater"], above["payload_flow"],
            " · ".join("{}/{}".format(lo[T], len(firsts_all[T])) for T in all_types), lo_fa, ex.thr))
    w("")
    ties = [n for n, s in summary.items() if s["caught"] >= 8 and all(s["lo"][T] >= v1_types[T] for T in all_types)]
    beats = [n for n in ties if summary[n]["caught"] > 8 or summary[n]["extra"] == 0 and summary[n]["lo_fa"] == 0]
    w("Setups that catch at least the SLM's 8 of 9 holdout attacks and match it on every held-out type: **{}**. "
      "Of those, setups that would also add no false alarm the SLM does not raise already: **{}**.".format(
          ", ".join(ties) or "none", ", ".join(beats) or "none"))
    w("")
    rows = training_rows(dev, {"clean": True})
    w("Cleaning removed {} of {} dev attack cases (svchost / lsass network traffic). Dev attack cases by type "
      "after cleaning: {}.".format(sum(c["label"] == "malicious" for c in dev) - sum(c["label"] == "malicious" for c in rows),
                                    sum(c["label"] == "malicious" for c in dev),
                                    ", ".join("{} {}".format(k, v) for k, v in sorted(Counter(c["type"] for c in rows if c["label"] == "malicious").items()))))
    w("")
    with open(os.path.join(run.OUT, "sq1_training.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
