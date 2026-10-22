"""Run the evaluator and keep a live status of the run.

Every evaluation goes through this wrapper so it can be watched while it runs.
Arguments after `--` go to evaluator/evaluate.py unchanged; --out, --report and
--label default to the run's own folder and name.

    python tools/run.py v1 -- --detector submission.my_detector:MyDetector \\
        --set full --answers data/cache/eval_answers.json

Everything lands in results/<label>/:
  meta.json       what was run: command, waves, expected time
  live.log        the evaluator's raw output, unbuffered
  progress.log    one line at the start, a few while running, one at the end
  status.json     the run as the workspace page shows it: phase, elapsed and
                  expected time, every wave with its outcome, running totals
  report.txt      the evaluator's report without its progress ticker
  alerts.jsonl, alerts.run.json, scorecard.json   as the evaluator writes them

    python tools/run.py --status results/<label>    # rebuild status.json of a finished run
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shlex
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "evaluator"))
import metrics  # noqa: E402  -- the evaluator's own scoring

ALERT_WAIT_S = 10.0        # evaluator: fixed wait for late alerts after each wave
WAVE_RE = re.compile(r"wave (\S+) \(([^)]*)\): (.*)$")
DONE_RE = re.compile(r"(\d+) alerts\s+warm-up\s+([\d.]+)s\s+live\s+([\d.]+)s\s+lag max\s+([\d.]+)s"
                     r"(?:\s+DROPPED (\d+) events)?")
BUILD_RE = re.compile(r"build time: ([\d.]+)s")
DETECTOR_RE = re.compile(r"constructing (\S+) \.\.\.")


# --------------------------------------------------------------------------- helpers

def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def iso_at(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")


def load_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: str, obj) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1)
    os.replace(tmp, path)


def clock(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    seconds = int(round(seconds))
    return "{}:{:02d}".format(seconds // 60, seconds % 60) if seconds < 3600 else \
        "{}:{:02d}:{:02d}".format(seconds // 3600, seconds // 60 % 60, seconds % 60)


def source_name(data_dir: str) -> str:
    rel = os.path.relpath(os.path.abspath(data_dir), ROOT).replace("\\", "/")
    return {"data/eval": "eval", "data/cache/val": "validation"}.get(rel, rel)


def eval_flags(argv: list[str]) -> argparse.Namespace:
    """The evaluator flags the wrapper needs to read; all of them are passed through as given."""
    ap = argparse.ArgumentParser(add_help=False)
    for flag in ("--detector", "--waves", "--answers", "--out", "--report", "--label"):
        ap.add_argument(flag)
    ap.add_argument("--set", default="fast")
    ap.add_argument("--mode", default="realtime")
    ap.add_argument("--data", default=os.path.join(ROOT, "data", "eval"))
    ap.add_argument("--no-explain", action="store_true")
    return ap.parse_known_args(argv)[0]


def select_waves(data_dir: str, set_name: str, waves_arg: str | None) -> list[dict]:
    """The waves evaluate.py will play, in its order (public waves only)."""
    waves = load_json(os.path.join(data_dir, "waves.json"))["waves"]
    if waves_arg:
        ids = {x.strip() for x in waves_arg.split(",") if x.strip()}
        return [w for w in waves if w["wave_id"] in ids]
    name = "full" if set_name == "all" else set_name
    return [w for w in waves if name in w["sets"]]


def load_answers(path: str | None) -> dict:
    if not path or not os.path.exists(path):
        return {}
    answers = load_json(path).get("waves", {})
    for answer in answers.values():          # the gap tools/fix_eval_answers.py fills
        answer.setdefault("event_attack", {})
    return answers


def attack_rows(attacks: dict) -> list[dict]:
    return [{"name": a.get("name"), "status": a.get("status"), "delay_s": a.get("delay_s"),
             "caught_at_event": a.get("caught_at_event"), "n_malicious": a.get("n_malicious_events"),
             "score": a.get("event_score")} for a in attacks.values()]


def outcome_of(attack_wave: bool, n_attacks: int, detected: int, false_alarms: int) -> str:
    if attack_wave:
        return "detected" if n_attacks and detected == n_attacks else ("partial" if detected else "missed")
    return "false_alarm" if false_alarms else "clean"


# --------------------------------------------------------------------------- live parsing

def parse_log(text: str) -> dict:
    """Read the evaluator's console output: build time, finished waves, the wave in progress."""
    out = {"detector": None, "build_s": None, "done": [], "current": None}
    for line in text.split("\n"):
        for piece in line.split("\r"):
            if (m := DETECTOR_RE.search(piece)):
                out["detector"] = m.group(1)
            if (m := BUILD_RE.search(piece)):
                out["build_s"] = float(m.group(1))
            if (m := WAVE_RE.search(piece)):
                out["current"] = (m.group(1), m.group(3).strip())
            if (m := DONE_RE.search(piece)):
                out["done"].append({"alerts": int(m.group(1)), "warm_s": float(m.group(2)),
                                    "live_s": float(m.group(3)), "lag_s": float(m.group(4)),
                                    "dropped": int(m.group(5) or 0)})
                out["current"] = None
    return out


def phase_of(text: str) -> str:
    if "waiting for explanations" in text:
        return "explanations"
    if "waiting for alerts" in text:
        return "waiting for alerts"
    if text.startswith("warm-up"):
        return "warm-up"
    if text.startswith("loading"):
        return "loading"
    return "live"


def clean_report(text: str) -> str:
    """The evaluator's console output without the progress ticker; finished waves keep one line."""
    lines = []
    for line in text.split("\n"):
        piece = line.split("\r")[-1].rstrip()
        wave, done = WAVE_RE.search(piece), DONE_RE.search(piece)
        if wave and done:
            lines.append("  wave {:<12} {}".format(wave.group(1), piece[done.start():]))
        elif not wave and piece.strip():
            lines.append(piece)
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- status

class Status:
    def __init__(self, run_dir: str, meta: dict) -> None:
        self.run_dir, self.meta = run_dir, meta
        self.answers = load_answers(meta.get("answers"))
        self.scored: dict[str, dict] = {}     # wave id -> outcome, once the wave is finished
        data_dir = os.path.join(ROOT, {"eval": "data/eval", "validation": "data/cache/val"}.get(meta.get("source"), ""))
        path = os.path.join(data_dir, "waves.json")
        self.known = {w["wave_id"]: w for w in load_json(path)["waves"]} if os.path.isfile(path) else {}

    def path(self, name: str) -> str:
        return os.path.join(self.run_dir, name)

    def alerts_by_wave(self) -> dict[str, list[dict]]:
        by: dict[str, list[dict]] = {}
        if os.path.exists(self.path("alerts.jsonl")):
            with open(self.path("alerts.jsonl"), encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        rec = json.loads(line)
                        by.setdefault(rec["wave"], []).append(rec)
        return by

    def score(self, wave_id: str, alerts: list[dict]) -> dict:
        if wave_id not in self.scored:
            answer = self.answers.get(wave_id)
            if not answer:
                self.scored[wave_id] = {}
            else:
                r = metrics.score_wave(alerts, answer)
                self.scored[wave_id] = {
                    "n_attacks": r["n_attacks"], "detected": r["attacks_detected"],
                    "false_alarms": r["false_alarms"],
                    "scores": [a["event_score"] for a in r["attacks"].values()],
                    "attacks": attack_rows(r["attacks"]),
                    "outcome": outcome_of(bool(r["attack"]), r["n_attacks"], r["attacks_detected"], r["false_alarms"]),
                }
        return self.scored[wave_id]

    def base_row(self, w: dict) -> dict:
        k = self.known.get(w["id"], {})
        window = (metrics.parse_ts(k["live_end"]) - metrics.parse_ts(k["live_start"])) if k.get("live_start") else None
        return {"id": w["id"], "kind": w["kind"], "machine": w.get("machine") or k.get("machine"),
                "state": "pending", "alerts": 0,
                "warmup_events": w.get("warmup_events", k.get("warmup_events")),
                "live_events": w.get("live_events", k.get("live_events")),
                "live_start": k.get("live_start"), "live_end": k.get("live_end"), "live_window_s": window,
                "source_attack": k.get("source_attack")}

    def rows_live(self, parsed: dict) -> list[dict]:
        alerts = self.alerts_by_wave()
        rows = []
        for i, w in enumerate(self.meta["waves"]):
            row = self.base_row(w)
            if i < len(parsed["done"]):
                d = parsed["done"][i]
                sc = self.score(w["id"], alerts.get(w["id"], []))
                row.update(state="done", alerts=d["alerts"], dropped=d["dropped"], lag_s=d["lag_s"],
                           warm_s=d["warm_s"], live_s=d["live_s"], attacks=sc.get("attacks", []),
                           outcome=sc.get("outcome"), false_alarms=sc.get("false_alarms", 0),
                           detected=sc.get("detected"), n_attacks=sc.get("n_attacks"),
                           timeliness=(sum(sc["scores"]) / len(sc["scores"])) if sc.get("scores") else None)
            elif parsed["current"] and parsed["current"][0] == w["id"]:
                row.update(state="running", phase=phase_of(parsed["current"][1]))
            rows.append(row)
        return rows

    def rows_final(self, card: dict, runinfo: dict) -> list[dict]:
        rows = []
        for w in self.meta["waves"]:
            v, wi = card["waves"].get(w["id"]), (runinfo.get("waves") or {}).get(w["id"], {})
            if v is None:
                rows.append({**self.base_row(w), "state": "skipped"})
                continue
            scores = [a.get("event_score", 0.0) for a in v["attacks"].values()]
            rows.append({
                **self.base_row(w), "state": "done", "alerts": v["n_alerts"],
                "warm_s": wi.get("warm_s"), "live_s": wi.get("live_wall_s"), "wall_s": wi.get("wall_s"),
                "post_wait_s": wi.get("post_stream_wait_s"),
                "attacks": attack_rows(v["attacks"]),
                "outcome": outcome_of(bool(v["attack"]), v["n_attacks"], v["attacks_detected"], v["false_alarms"]),
                "false_alarms": v["false_alarms"], "detected": v["attacks_detected"], "n_attacks": v["n_attacks"],
                "timeliness": (sum(scores) / len(scores)) if scores else None,
                "dropped": wi.get("warm_events", 0) - wi.get("warm_delivered", 0)
                           + wi.get("live_events", 0) - wi.get("live_delivered", 0),
                "lag_s": wi.get("max_lag_s"),
            })
        return rows

    def build(self, final: bool = False, exit_code: int | None = None, error: str | None = None) -> dict:
        meta = self.meta
        text = open(self.path("live.log"), encoding="utf-8", errors="replace").read() \
            if os.path.exists(self.path("live.log")) else ""
        parsed = parse_log(text)
        card = load_json(self.path("scorecard.json")) if final and os.path.exists(self.path("scorecard.json")) else None
        runinfo = load_json(self.path("alerts.run.json")) if final and os.path.exists(self.path("alerts.run.json")) else {}
        rows = self.rows_final(card, runinfo) if card else self.rows_live(parsed)

        done = [r for r in rows if r["state"] == "done"]
        scores = [s for r in done for s in ([r["timeliness"]] * (r.get("n_attacks") or 0) if r.get("timeliness") is not None else [])]
        totals = {
            "waves": len(rows), "done": len(done),
            "attack_waves": sum(r["kind"] == "attack" for r in rows),
            "alerts": sum(r.get("alerts", 0) for r in done),
            "attacks": sum(len(self.answers.get(r["id"], {}).get("attacks") or []) for r in rows),
            "detected": sum(r.get("detected") or 0 for r in done),
            "missed": sum((r.get("n_attacks") or 0) - (r.get("detected") or 0) for r in done),
            "false_alarms": sum(r.get("false_alarms") or 0 for r in done),
            "dropped": sum(r.get("dropped") or 0 for r in done),
            "errors": 0,
            "lag_max_s": max([r.get("lag_s") or 0.0 for r in done], default=0.0),
            "timeliness": (sum(scores) / len(scores)) if scores else None,
        }
        if card:
            s, timing = card["summary"], card.get("timing") or {}
            dm = s.get("detection_metrics") or {}
            totals.update(alerts=s["n_alerts"], attacks=s["n_attacks"], detected=s["attacks_detected"],
                          missed=s["missed_attacks"], false_alarms=s["false_alarms"],
                          timeliness=s["timeliness_score"] if s["n_attacks"] else None,
                          precision=dm.get("precision"), recall=dm.get("recall"), f1=dm.get("f1"),
                          evidence_precision=s.get("evidence_precision") if s["attacks_detected"] else None,
                          dropped=timing.get("events_dropped", totals["dropped"]),
                          errors=timing.get("n_errors", 0), lag_max_s=timing.get("max_live_lag_s", totals["lag_max_s"]))

        build_s = parsed["build_s"] if parsed["build_s"] is not None else (card or {}).get("build_s")
        if final:
            state = "finished" if exit_code in (0, None) and not error else "failed"
        else:
            state = "running" if build_s is not None else "building"
        started = dt.datetime.fromisoformat(meta["triggered_at"]).timestamp()
        finished_at = meta.get("finished_at") if final else None
        end = dt.datetime.fromisoformat(finished_at).timestamp() if finished_at else time.time()
        current = next(({"wave": r["id"], "phase": r.get("phase")} for r in rows if r["state"] == "running"), None)
        status = {
            "label": meta["label"], "note": meta.get("note"),
            "detector": meta.get("detector") or parsed["detector"],
            "source": meta["source"], "set": meta["set"], "mode": meta["mode"], "explain": meta["explain"],
            "command": meta["command"], "status": state,
            "triggered_at": meta["triggered_at"], "finished_at": finished_at,
            "elapsed_s": round(end - started, 1),
            "expected_s": round(meta["expected_s"] + (build_s or 0.0), 1),
            "build_s": build_s, "current": current, "waves": rows, "totals": totals,
            "error": error, "exit_code": exit_code, "updated_at": now_iso(),
        }
        write_json(self.path("status.json"), status)
        return status


def progress_line(s: dict) -> str:
    t = s["totals"]
    head = "RUN {} {} · {}/{} waves".format(s["label"], s["status"], t["done"], t["waves"])
    parts = [head, "{} alerts".format(t["alerts"])]
    if t["attacks"]:
        parts.append("{}/{} attacks caught".format(t["detected"], t["attacks"]))
    parts.append("{} false alarms".format(t["false_alarms"]))
    if s["status"] in ("finished", "failed"):
        if t.get("timeliness") is not None:
            parts.append("timeliness {:.3f}".format(t["timeliness"]))
        parts.append("{} dropped, {} errors".format(t["dropped"], t["errors"]))
        parts.append(clock(s["elapsed_s"]))
        if s.get("error"):
            parts.append(s["error"])
    else:
        parts.append("{} of ~{}".format(clock(s["elapsed_s"]), clock(s["expected_s"])))
    return " · ".join(parts)


# --------------------------------------------------------------------------- run

def start_run(label: str, note: str | None, passthrough: list[str], force: bool) -> int:
    run_dir = os.path.join(ROOT, "results", label)
    if os.path.isdir(run_dir) and os.listdir(run_dir) and not force:
        sys.exit("results/{} already exists; pick another label or pass --force".format(label))
    os.makedirs(run_dir, exist_ok=True)
    flags = eval_flags(passthrough)
    data_dir = os.path.abspath(flags.data)
    answers_path = flags.answers or os.path.join(data_dir, "answers.json")
    answers = load_answers(answers_path)
    waves = select_waves(data_dir, flags.set, flags.waves)

    args = list(passthrough)
    rel = lambda name: os.path.relpath(os.path.join(run_dir, name), ROOT)  # noqa: E731
    if not flags.out:
        args += ["--out", rel("alerts.jsonl")]
    if not flags.report:
        args += ["--report", rel("scorecard.json")]
    if not flags.label:
        args += ["--label", label]

    per_wave = [(metrics.parse_ts(w["live_end"]) - metrics.parse_ts(w["live_start"])
                 if flags.mode == "realtime" else 0.0) + ALERT_WAIT_S + 0.3 for w in waves]
    meta = {
        "label": label, "note": note, "detector": flags.detector,
        "source": source_name(data_dir), "set": "subset" if flags.waves else flags.set, "mode": flags.mode,
        "explain": not flags.no_explain, "answers": answers_path,
        "command": "python evaluator/evaluate.py " + " ".join(shlex.quote(a) for a in args),
        "triggered_at": now_iso(), "expected_s": round(sum(per_wave), 1),
        "waves": [{"id": w["wave_id"], "machine": w["machine"],
                   "kind": "attack" if answers.get(w["wave_id"], {}).get("attack") else "benign",
                   "warmup_events": w.get("warmup_events"), "live_events": w.get("live_events")} for w in waves],
    }
    write_json(os.path.join(run_dir, "meta.json"), meta)
    status = Status(run_dir, meta)
    progress_path = os.path.join(run_dir, "progress.log")
    open(progress_path, "w").close()

    def emit(line: str) -> None:
        with open(progress_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        print(line, flush=True)

    emit("RUN {} started · {} waves ({} {}, {}) · expected ~{}".format(
        label, len(waves), meta["source"], meta["set"], meta["mode"], clock(meta["expected_s"])))
    status.build()
    interval = min(300.0, max(45.0, meta["expected_s"] / 8))
    with open(os.path.join(run_dir, "live.log"), "w", encoding="utf-8") as log:
        proc = subprocess.Popen([sys.executable, "-u", os.path.join(ROOT, "evaluator", "evaluate.py"), *args],
                                cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                env={**os.environ, "PYTHONUNBUFFERED": "1"})
        next_emit = time.time() + interval
        while proc.poll() is None:
            time.sleep(2)
            s = status.build()
            if time.time() >= next_emit:
                emit(progress_line(s))
                next_emit = time.time() + interval

    text = open(os.path.join(run_dir, "live.log"), encoding="utf-8", errors="replace").read()
    with open(os.path.join(run_dir, "report.txt"), "w", encoding="utf-8") as fh:
        fh.write(clean_report(text))
    error = None
    if proc.returncode != 0:
        last = [ln for ln in text.replace("\r", "\n").split("\n") if ln.strip()]
        error = last[-1].strip()[:200] if last else "exit {}".format(proc.returncode)
    meta["finished_at"] = now_iso()
    write_json(os.path.join(run_dir, "meta.json"), meta)
    emit(progress_line(status.build(final=True, exit_code=proc.returncode, error=error)))
    return proc.returncode


def meta_from_results(run_dir: str) -> dict:
    """Reconstruct meta.json for a run recorded before this wrapper existed."""
    card = load_json(os.path.join(run_dir, "scorecard.json"))
    runinfo = load_json(os.path.join(run_dir, "alerts.run.json"))
    wave_ids = list(card["waves"])
    data_dir = os.path.join(ROOT, "data", "eval" if all(w.startswith("w0") for w in wave_ids) else "cache/val")
    answers_path = os.path.join(ROOT, "data", "cache", "eval_answers.json") if data_dir.endswith("eval") \
        else os.path.join(data_dir, "answers.json")
    known = {w["wave_id"]: w for w in load_json(os.path.join(data_dir, "waves.json"))["waves"]}
    report = open(os.path.join(run_dir, "report.txt"), encoding="utf-8").read()
    detector = (DETECTOR_RE.search(report) or [None, None])[1]
    finished = os.path.getmtime(os.path.join(run_dir, "scorecard.json"))
    elapsed = runinfo.get("total_wall_s", 0.0) + (card.get("build_s") or 0.0)
    return {
        "label": card["label"], "note": None, "detector": detector, "source": source_name(data_dir),
        "set": card["set"], "mode": card["mode"], "explain": None, "answers": answers_path,
        "command": None, "triggered_at": iso_at(finished - elapsed), "finished_at": iso_at(finished),
        "expected_s": round(elapsed, 1),
        "waves": [{"id": w, "machine": known.get(w, {}).get("machine"),
                   "kind": "attack" if card["waves"][w]["attack"] else "benign",
                   "warmup_events": known.get(w, {}).get("warmup_events"),
                   "live_events": known.get(w, {}).get("live_events")} for w in wave_ids],
    }


def main() -> int:
    argv = sys.argv[1:]
    passthrough = argv[argv.index("--") + 1:] if "--" in argv else []
    own = argv[:argv.index("--")] if "--" in argv else argv
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("label", nargs="?", help="run name, also its folder under results/")
    ap.add_argument("--note", help="one line on what this run tests")
    ap.add_argument("--force", action="store_true", help="reuse an existing results/<label> folder")
    ap.add_argument("--status", metavar="RUN_DIR", help="rebuild status.json of a finished run and exit")
    args = ap.parse_args(own)
    if args.status:
        run_dir = os.path.abspath(args.status)
        meta_path = os.path.join(run_dir, "meta.json")
        meta = load_json(meta_path) if os.path.exists(meta_path) else meta_from_results(run_dir)
        print(progress_line(Status(run_dir, meta).build(final=True)))
        return 0
    if not args.label or not passthrough:
        ap.error("give a label and the evaluator arguments after --")
    return start_run(args.label, args.note, passthrough, args.force)


if __name__ == "__main__":
    sys.exit(main())
