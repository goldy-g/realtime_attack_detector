"""The evaluation harness. This is the thing that grades you.

    python evaluator/evaluate.py --detector submission.my_detector:MyDetector               # fast set, real time
    python evaluator/evaluate.py --detector submission.my_detector:MyDetector --set full    # full set
    python evaluator/evaluate.py --detector submission.my_detector:MyDetector --mode instant  # debug, NOT graded
    python evaluator/evaluate.py --alerts results/alerts.jsonl                               # re-score a run

What it does, in order:

1. Imports your class and constructs it once with the training directory.
   Construction is timed separately as build time.
2. For every wave of the set (data/eval/waves.json):
   - start_wave(machine), then the warm-up events through on_event() back to
     back. Warm-up compute is capped at 120 s; the rest is dropped.
     - on_live(), then live events in real time. `on_event()` should return
         promptly; callback results may arrive asynchronously.
     - after the final feed call, wait ten seconds for alerts, then finish when
         all alerts have explanations, with a five-minute post-feed hard limit.
     Alert timestamps come from callback arrival, not the referenced event's time.
3. Scores the alerts against data/eval/answers.json (see metrics.py).

`--mode instant` replays the live part without pacing and stamps alerts with
the triggering event's timestamp. It is for debugging only and is NOT graded.
We run exactly this code, unchanged, in real-time mode on held-out waves.
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import importlib
import json
import math
import os
import sys
import threading
import time
from collections import deque
from shutil import get_terminal_size

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

from detector_interface import WaveCallbacks  # noqa: E402
from metrics import decision_summary, explanation_summary, parse_dt, parse_ts, percentile, score  # noqa: E402

for _s in (sys.stdout, sys.stderr):          # Windows consoles default to cp1252
    if hasattr(_s, "reconfigure"):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass

DEFAULT_DATA = os.path.join(ROOT, "data", "eval")
DEFAULT_TRAIN = os.path.join(ROOT, "data", "train")
DEFAULT_HIDDEN_DATA = None
DEFAULT_OUT = os.path.join(ROOT, "results", "alerts.jsonl")
WARMUP_CAP_S = 120.0          # warm-up compute per wave
LIVE_GRACE_S = 30.0           # the live part ends at live_end + this
POST_STREAM_GRACE_S = 300.0    # delayed alert/explanation callbacks after event feeding
POST_STREAM_ALERT_WAIT_S = 10.0
MAX_EXPLANATION_CHARS = 4000
MAX_EXPLANATION_EVENT_IDS = 200
BANNER = "*** --mode instant: DEBUG RUN, NOT GRADED -- delays are event-time, not wall-time ***"


def resolve_data_paths(root: str) -> tuple[str, str, str | None]:
    """Use optc's split public/hidden layout internally, else the public repo layout."""
    optc_data = os.path.abspath(os.path.join(root, "..", "data"))
    public_eval = os.path.join(optc_data, "public", "eval")
    public_train = os.path.join(optc_data, "public", "train")
    hidden_eval = os.path.join(optc_data, "hidden", "eval")
    if os.path.isfile(os.path.join(public_eval, "waves.json")):
        hidden = hidden_eval if os.path.isfile(os.path.join(hidden_eval, "waves.json")) else None
        return public_eval, public_train, hidden
    return os.path.join(root, "data", "eval"), os.path.join(root, "data", "train"), None


DEFAULT_DATA, DEFAULT_TRAIN, DEFAULT_HIDDEN_DATA = resolve_data_paths(ROOT)


# --------------------------------------------------------------------------- io
def iter_jsonl(path: str):
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def run_info_path(out_path: str) -> str:
    return os.path.splitext(out_path)[0] + ".run.json"


def select_waves(public_waves: list[dict], public_answers: dict | None, public_eval_dir: str,
                 set_name: str, hidden_waves: list[dict] | None = None,
                 hidden_answers: dict | None = None, hidden_eval_dir: str | None = None,
                 requested_ids: list[str] | None = None):
    """Select public waves plus hidden waves when the internal dataset is present."""
    hidden_waves = hidden_waves or []
    public_sets = {s for w in public_waves for s in w["sets"]}
    hidden_sets = {s for w in hidden_waves for s in w["sets"]}
    if requested_ids:
        public_set = hidden_set = None
    elif set_name == "all":
        public_set, hidden_set = "full", "all"
    elif set_name == "full" and hidden_waves:
        public_set, hidden_set = "full", "all"
    else:
        public_set = hidden_set = set_name
    if public_set is not None and public_set not in public_sets:
        raise ValueError("unknown public set {!r}; available: {}".format(set_name, ", ".join(sorted(public_sets))))
    if hidden_waves and hidden_set is not None and hidden_set not in hidden_sets:
        raise ValueError("internal hidden data has no set {!r}".format(hidden_set))

    answers = dict(public_answers) if public_answers is not None else None
    selected, stream_dirs = [], {}
    for wave in public_waves:
        if public_set is not None and public_set not in wave["sets"]:
            continue
        item = dict(wave)
        selected.append(item)
        stream_dirs[item["wave_id"]] = os.path.join(public_eval_dir, item["wave_id"])
    if hidden_waves:
        for wave in hidden_waves:
            if hidden_set is not None and hidden_set not in wave["sets"]:
                continue
            original_id = wave["wave_id"]
            key = "hidden-" + original_id
            item = dict(wave, wave_id=key)
            selected.append(item)
            stream_dirs[key] = os.path.join(hidden_eval_dir, original_id)
            if answers is not None and hidden_answers is not None:
                answers[key] = hidden_answers[original_id]

    if requested_ids:
        unknown = sorted(set(requested_ids) - {w["wave_id"] for w in selected})
        if unknown:
            raise ValueError("unknown wave id(s): " + ", ".join(unknown))
        selected = [w for w in selected if w["wave_id"] in requested_ids]
        set_label = "subset " + ",".join(w["wave_id"] for w in selected)
    elif hidden_waves and set_name in ("full", "all"):
        set_label = "full (public + hidden all)"
    elif hidden_waves:
        set_label = set_name + " (public + hidden)"
    else:
        set_label = set_name
    if answers is not None:
        answers = {wave["wave_id"]: answers[wave["wave_id"]] for wave in selected}
    return selected, answers, stream_dirs, set_label


def load_detector(spec: str, train_dir: str):
    if ":" not in spec:
        sys.exit("--detector must look like 'module.path:ClassName', got " + repr(spec))
    mod_name, cls_name = spec.split(":", 1)
    try:
        module = importlib.import_module(mod_name)
    except ImportError as exc:
        sys.exit("could not import {!r}: {}".format(mod_name, exc))
    print("constructing " + spec + " ...", flush=True)
    t0 = time.perf_counter()
    det = getattr(module, cls_name)(train_dir)
    build_s = time.perf_counter() - t0
    print("  build time: {:.1f}s".format(build_s), flush=True)
    return det, build_s


def iso_at(base: dt.datetime, seconds: float) -> str:
    return (base + dt.timedelta(seconds=seconds)).isoformat(timespec="milliseconds")


# --------------------------------------------------------------------------- run
class WaveState:
    """Shared between the harness thread (watchdog) and the worker driving the detector."""

    def __init__(self) -> None:
        self.phase = "setup"
        self.call_t0: float | None = None     # perf_counter when the running call started
        self.warm_s = 0.0
        self.deadline = float("inf")
        self.abandoned = False
        self.error: BaseException | None = None


class WaveProgress:
    """Render a fixed-height event panel only on an interactive terminal."""

    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.last_frame: tuple[str, ...] = ()
        self.width = 0
        self.interactive = sys.stdout.isatty()
        if self.interactive and os.name == "nt":
            import ctypes
            import msvcrt
            from ctypes import wintypes

            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            get_mode = kernel.GetConsoleMode
            get_mode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            get_mode.restype = wintypes.BOOL
            set_mode = kernel.SetConsoleMode
            set_mode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            set_mode.restype = wintypes.BOOL
            handle = msvcrt.get_osfhandle(sys.stdout.fileno())
            mode = wintypes.DWORD()
            if not get_mode(handle, ctypes.byref(mode)) or not set_mode(handle, mode.value | 0x0004):
                raise ctypes.WinError(ctypes.get_last_error())

    @staticmethod
    def event_line(event: dict) -> str:
        props = event.get("properties") or {}
        detail = next((props[key] for key in (
            "command_line", "file_path", "key", "dest_ip", "image_path",
        ) if props.get(key)), "")
        fields = [event.get("timestamp", ""), event.get("object", ""),
                  event.get("action", ""), event.get("id", ""), detail]
        # Telemetry is untrusted console text: quote controls, including ANSI escapes.
        return "    " + " | ".join(json.dumps(str(value), ensure_ascii=True)[1:-1] for value in fields)

    def update(self, status: str, events: list[dict]) -> None:
        text = "{}: {}".format(self.prefix, status)
        if self.interactive:
            width = max(1, get_terminal_size().columns - 1)
            lines = [text] + [self.event_line(event) for event in events[-5:]]
            lines.extend([""] * (6 - len(lines)))
            frame = tuple(line[:width] for line in lines)
            if frame != self.last_frame:
                move = "\x1b[6A" if self.last_frame else ""
                sys.stdout.write(move + "".join("\r\x1b[2K" + line + "\n" for line in frame))
                sys.stdout.flush()
                self.last_frame = frame
        elif (text,) != self.last_frame:
            self.width = max(self.width, len(text))
            print("\r" + text.ljust(self.width), end="", flush=True)
            self.last_frame = (text,)


class WaveCallbackRecorder:
    """Owns callback acceptance and records callbacks atomically for one wave."""

    def __init__(self, wave: dict, answer: dict | None, live: list[dict], realtime: bool,
                 res: dict, explain_enabled: bool) -> None:
        self.wave_id = wave["wave_id"]
        self.answer = answer or {}
        self.realtime = realtime
        self.res = res
        self.explain_enabled = explain_enabled
        self.lock = threading.RLock()
        self.cancelled = threading.Event()
        self.open = True
        self.phase = "setup"
        self.delivered: dict[str, str | None] = {}
        self.delivered_perf: dict[str, float] = {}
        self.delivery_order: dict[str, int] = {}
        self.delivery_count = 0
        self.recent_events: deque[dict] = deque(maxlen=5)
        self.malicious_seen: dict[str, int] = {}
        self.event_attack = self.answer.get("event_attack") or {}
        self.malicious_ids = set(self.answer.get("malicious_event_ids") or [])
        self.last_malicious_ts: dict[str, str] = {}
        self.alerts_by_id: dict[str, tuple[dict, float]] = {}
        self.alert_index = 0
        self.latest_event_ts: str | None = None
        self.live_start_dt: dt.datetime | None = None
        self.wall0: float | None = None
        self.feed_end_perf: float | None = None
        self.feed_end_stream_ts: str | None = None
        self.deadline_perf: float | None = None
        self.deadline_ts: str | None = None

        for event in live:
            event_id = event["id"]
            attack_id = self.event_attack.get(event_id)
            if event_id in self.malicious_ids and attack_id:
                self.malicious_seen.setdefault(attack_id, 0)
                previous = self.last_malicious_ts.get(attack_id)
                if previous is None or parse_ts(event["timestamp"]) > parse_ts(previous):
                    self.last_malicious_ts[attack_id] = event["timestamp"]

        self.callbacks = WaveCallbacks(self.alert, self.explain, self.cancelled)

    def set_phase(self, phase: str) -> None:
        with self.lock:
            self.phase = phase

    def start_live(self, wall0: float, live_start_dt: dt.datetime) -> None:
        with self.lock:
            self.phase = "live"
            self.wall0 = wall0
            self.live_start_dt = live_start_dt

    def mark_delivered(self, event: dict) -> None:
        with self.lock:
            event_id = event["id"]
            self.delivery_count += 1
            self.delivery_order[event_id] = self.delivery_count
            self.delivered[event_id] = event.get("actorID")
            self.delivered_perf[event_id] = time.perf_counter()
            self.latest_event_ts = event["timestamp"]
            self.recent_events.append(event)
            attack_id = self.event_attack.get(event_id)
            if event_id in self.malicious_ids and attack_id:
                self.malicious_seen[attack_id] = self.malicious_seen.get(attack_id, 0) + 1

    def _stream_ts(self, now: float) -> str:
        if self.realtime and self.wall0 is not None and self.live_start_dt is not None:
            return iso_at(self.live_start_dt, now - self.wall0)
        if self.feed_end_perf is not None and self.feed_end_stream_ts is not None:
            return iso_at(parse_dt(self.feed_end_stream_ts), now - self.feed_end_perf)
        if self.latest_event_ts is not None:
            return self.latest_event_ts
        return (self.live_start_dt or dt.datetime.now(dt.timezone.utc)).isoformat(timespec="milliseconds")

    def alert(self, event_id: str) -> str | None:
        arrival = time.perf_counter()
        event_id = str(event_id or "")
        with self.lock:
            if not self.open or (self.deadline_perf is not None and arrival >= self.deadline_perf):
                return None
            self.alert_index += 1
            alert_id = "{}-A{:04d}".format(self.wave_id, self.alert_index)
            attack_id = self.event_attack.get(event_id)
            rec = {
                "wave": self.wave_id,
                "alert_id": alert_id,
                "event_id": event_id,
                "phase": self.phase,
                "alert_ts": self._stream_ts(arrival),
                "call_s": (round(max(0.0, arrival - self.delivered_perf[event_id]), 5)
                           if event_id in self.delivered_perf else None),
                "delivered": event_id in self.delivered,
                "event_actor": self.delivered.get(event_id),
                "malicious_events_seen": self.malicious_seen.get(attack_id, 0),
                "last_malicious_ts": self.last_malicious_ts.get(attack_id),
                "post_stream_deadline_ts": self.deadline_ts,
                "delivered_count_at_alert": self.delivery_count,
                "explanation": "",
                "explanation_event_ids": [],
                "explanation_event_ids_available_at_alert": [],
                "explanation_received": False,
                "explain_s": None,
            }
            self.res["alerts"].append(rec)
            self.alerts_by_id[alert_id] = (rec, arrival)
            return alert_id

    def explain(self, alert_id: str, text: str, event_ids: list[str]) -> bool:
        arrival = time.perf_counter()
        with self.lock:
            if (not self.explain_enabled or not self.open
                    or (self.deadline_perf is not None and arrival >= self.deadline_perf)):
                return False
            found = self.alerts_by_id.get(str(alert_id))
            if found is None:
                return False
            rec, alert_arrival = found
            if rec["explanation_received"]:
                return False
            ids = list(dict.fromkeys(str(event_id) for event_id in (event_ids or []) if event_id))
            ids = ids[:MAX_EXPLANATION_EVENT_IDS]
            delivered_at_alert = rec["delivered_count_at_alert"]
            rec["explanation"] = str(text or "")[:MAX_EXPLANATION_CHARS]
            rec["explanation_event_ids"] = ids
            rec["explanation_event_ids_available_at_alert"] = [
                event_id for event_id in ids
                if self.delivery_order.get(event_id, delivered_at_alert + 1) <= delivered_at_alert
            ]
            rec["explanation_received"] = True
            rec["explain_s"] = round(max(0.0, arrival - alert_arrival), 5)
            return True

    def finish_feed(self, post_stream_grace_s: float) -> None:
        with self.lock:
            if self.feed_end_perf is not None:
                return
            self.feed_end_perf = time.perf_counter()
            self.feed_end_stream_ts = self._stream_ts(self.feed_end_perf)
            self.deadline_perf = self.feed_end_perf + post_stream_grace_s
            self.deadline_ts = iso_at(parse_dt(self.feed_end_stream_ts), post_stream_grace_s)
            for rec in self.res["alerts"]:
                rec["post_stream_deadline_ts"] = self.deadline_ts

    def close(self) -> None:
        with self.lock:
            self.open = False
            self.cancelled.set()


def drive_wave(det, wave: dict, warm: list[dict], live: list[dict], live_ts: list[float],
               realtime: bool, st: WaveState, res: dict, recorder: WaveCallbackRecorder,
               post_stream_grace_s: float) -> None:
    """Worker: feed one wave to the detector. Fills `res`."""
    live_start_dt = parse_dt(wave["live_start"])
    live_start = live_start_dt.timestamp()
    live_len = parse_ts(wave["live_end"]) - live_start
    errors: list[str] = res["errors"]

    def call(fn, *args):
        t0 = time.perf_counter()
        st.call_t0 = t0
        try:
            out = fn(*args)
        except Exception as exc:              # a crash on one event does not stop the stream
            out = None
            if len(errors) < 1000:
                errors.append("{}: {}".format(type(exc).__name__, exc))
        t1 = time.perf_counter()
        st.call_t0 = None
        return out, t1 - t0, t1

    # warm-up: back to back, compute-capped
    st.phase = "warmup"
    recorder.set_phase("warmup")
    _, s, _ = call(det.start_wave, wave["machine"], recorder.callbacks)
    st.warm_s += s
    for ev in warm:
        if st.warm_s >= WARMUP_CAP_S or st.abandoned:
            break
        recorder.mark_delivered(ev)
        _, s, _ = call(det.on_event, ev)
        st.warm_s += s
        res["warm_delivered"] += 1

    # live: real time, the clock starts before on_live
    wall0 = time.perf_counter()
    st.deadline = wall0 + live_len + LIVE_GRACE_S
    st.phase = "live"
    recorder.start_live(wall0, live_start_dt)
    call(det.on_live)
    event_s, lag = res["event_s"], 0.0
    for ev, ts in zip(live, live_ts):
        if st.abandoned:
            return
        due = wall0 + (ts - live_start)
        if realtime:
            while (now := time.perf_counter()) < due:
                time.sleep(min(due - now, 0.5))
        start = time.perf_counter()
        if start > st.deadline:
            break
        lag = max(lag, start - due) if realtime else 0.0
        recorder.mark_delivered(ev)
        _, s, _ = call(det.on_event, ev)
        event_s.append(s)
        res["live_delivered"] += 1
    res["max_lag_s"] = lag
    res["live_wall_s"] = time.perf_counter() - wall0
    recorder.finish_feed(post_stream_grace_s)


def run_wave(det, wave: dict, data_dir: str, realtime: bool, answer: dict | None,
             explain: bool, post_stream_grace_s: float = POST_STREAM_GRACE_S,
             stream_dir: str | None = None) -> tuple[dict, bool]:
    """Run one wave under a watchdog. Returns (result, hung)."""
    prefix = "  wave {} ({})".format(wave["wave_id"], wave["machine"])
    display = WaveProgress(prefix)
    display.update("loading...", [])
    wdir = stream_dir or os.path.join(data_dir, wave["wave_id"])
    warm = list(iter_jsonl(os.path.join(wdir, "warmup.stream")))
    live = list(iter_jsonl(os.path.join(wdir, "live.stream")))
    live_ts = [parse_ts(e["timestamp"]) for e in live]
    res = {"alerts": [], "errors": [], "event_s": [], "warm_events": len(warm),
           "live_events": len(live), "warm_delivered": 0, "live_delivered": 0, "alerts_lost": 0,
           "max_lag_s": 0.0, "live_wall_s": 0.0, "post_stream_wait_s": 0.0}
    st = WaveState()
    recorder = WaveCallbackRecorder(wave, answer, live, realtime, res, explain)
    live_seconds = max(0.0, live_ts[-1] - parse_ts(wave["live_start"])) if live_ts else 0.0

    def update_progress() -> None:
        with recorder.lock:
            deadline = recorder.deadline_perf
            wall0 = recorder.wall0
            events = list(recorder.recent_events)
            feed_end = recorder.feed_end_perf
            pending = sum(not rec["explanation_received"] for rec in res["alerts"]) if explain else 0
        status = ""
        if feed_end is not None:
            alert_deadline = feed_end + min(POST_STREAM_ALERT_WAIT_S, post_stream_grace_s)
            if time.perf_counter() < alert_deadline:
                deadline = alert_deadline
                status = " - waiting for alerts"
            else:
                status = " - waiting for explanations for {} alert(s)".format(pending)
        if deadline is None and realtime and wall0 is not None:
            deadline = wall0 + live_seconds + min(POST_STREAM_ALERT_WAIT_S, post_stream_grace_s)
        if deadline is not None:
            display.update("{}s{}".format(max(0, math.ceil(deadline - time.perf_counter())), status), events)
        else:
            display.update("live (instant)..." if wall0 is not None else "warm-up...", events)

    def target():
        try:
            drive_wave(det, wave, warm, live, live_ts, realtime, st, res, recorder, post_stream_grace_s)
        except BaseException as exc:          # noqa: BLE001 -- reported, never raised in the worker
            st.error = exc
            recorder.finish_feed(post_stream_grace_s)

    worker = threading.Thread(target=target, daemon=True)
    display.update("warm-up...", [])
    worker.start()
    hung = False
    while worker.is_alive():
        update_progress()
        worker.join(0.1)
        now = time.perf_counter()
        t0 = st.call_t0
        over_warm = st.phase in ("setup", "warmup") and t0 is not None and st.warm_s + now - t0 > WARMUP_CAP_S
        if worker.is_alive() and (over_warm or now > st.deadline):
            st.abandoned, hung = True, True
            if over_warm:
                st.warm_s += now - t0
            print("\n  !! a detector call is still running past the {} cap -- abandoned".format(
                "warm-up" if over_warm else "live"), flush=True)
            break
    if st.error is not None:
        recorder.close()
        print(flush=True)
        raise st.error
    res["warm_s"] = st.warm_s
    res["hung"] = hung

    if hung:
        recorder.close()
    else:
        deadline = recorder.deadline_perf or time.perf_counter()
        alert_deadline = (recorder.feed_end_perf or time.perf_counter()) + min(
            POST_STREAM_ALERT_WAIT_S, post_stream_grace_s)
        while (remaining := deadline - time.perf_counter()) > 0:
            with recorder.lock:
                pending = explain and any(not rec["explanation_received"] for rec in res["alerts"])
                if time.perf_counter() >= alert_deadline and not pending:
                    recorder.close()
                    break
            update_progress()
            time.sleep(min(remaining, 0.1))
        recorder.close()
        res["post_stream_wait_s"] = round(time.perf_counter() - (recorder.feed_end_perf or time.perf_counter()), 3)
        with recorder.lock:
            events = list(recorder.recent_events)
        display.update("0s", events)
    return res, hung


def run(det, waves: list[dict], data_dir: str, realtime: bool, explain: bool,
    out_path: str, answers: dict | None,
    post_stream_grace_s: float = POST_STREAM_GRACE_S,
    stream_dirs: dict[str, str] | None = None) -> tuple[list[dict], dict]:
    alerts: list[dict] = []
    all_event_s: list[float] = []
    info: dict = {"mode": "realtime" if realtime else "instant", "waves": {}}
    t_start = time.perf_counter()
    with open(out_path, "w", encoding="utf-8") as sink:
        for i, wave in enumerate(waves):
            w = wave["wave_id"]
            t0 = time.perf_counter()
            res, hung = run_wave(det, wave, data_dir, realtime, answers.get(w) if answers else None,
                                 explain, post_stream_grace_s, (stream_dirs or {}).get(w))
            for rec in res["alerts"]:
                sink.write(json.dumps(rec, ensure_ascii=False) + "\n")
            sink.flush()
            ev = res.pop("event_s")
            all_event_s.extend(ev)
            res.update(wall_s=time.perf_counter() - t0,
                       event_ms_p50=1000 * percentile(ev, 50), event_ms_p95=1000 * percentile(ev, 95),
                       event_ms_max=1000 * max(ev, default=0.0), n_errors=len(res["errors"]),
                       errors=res["errors"][:5])
            alerts.extend(res.pop("alerts"))
            info["waves"][w] = res
            print("  {:>3} alerts  warm-up {:5.1f}s  live {:5.1f}s  lag max {:5.2f}s{}".format(
                sum(1 for a in alerts if a["wave"] == w), res["warm_s"], res["live_wall_s"],
                res["max_lag_s"], "  DROPPED {} events".format(
                    res["live_events"] - res["live_delivered"]) if res["live_delivered"] < res["live_events"] else ""),
                flush=True)
            if hung:
                print("  !! stopping the run: remaining waves are not played and count as missed")
                for rest in waves[i + 1:]:
                    info["waves"][rest["wave_id"]] = {"skipped": True}
                break
    info["total_wall_s"] = time.perf_counter() - t_start
    info.update(event_ms_p50=1000 * percentile(all_event_s, 50), event_ms_p95=1000 * percentile(all_event_s, 95),
                event_ms_max=1000 * max(all_event_s, default=0.0))
    with open(run_info_path(out_path), "w", encoding="utf-8") as fh:
        json.dump(info, fh, indent=1)
    return alerts, info


# --------------------------------------------------------------------------- report
def timing_summary(info: dict) -> dict:
    ws = [w for w in info["waves"].values() if "warm_s" in w]
    return {
        "event_ms_p50": info.get("event_ms_p50", 0.0),
        "event_ms_p95": info.get("event_ms_p95", 0.0),
        "event_ms_max": info.get("event_ms_max", 0.0),
        "max_live_lag_s": max((w["max_lag_s"] for w in ws), default=0.0),
        "warm_s_max": max((w["warm_s"] for w in ws), default=0.0),
        "events_dropped": sum(w["warm_events"] - w["warm_delivered"] + w["live_events"] - w["live_delivered"]
                              for w in ws),
        "alerts_lost": sum(w["alerts_lost"] for w in ws),
        "n_errors": sum(w["n_errors"] for w in ws),
        "errors_sample": [e for w in ws for e in w["errors"]][:3],
        "skipped_waves": [k for k, w in info["waves"].items() if w.get("skipped")],
        "hung": any(w.get("hung") for w in ws),
        "total_wall_s": info.get("total_wall_s", 0.0),
    }


def fmt_s(x) -> str:
    return "   -   " if x is None else "{:7.3f}".format(x)


def detection_metrics(result: dict) -> dict:
    tp, fp = result["attacks_detected"], result["false_alarms"]
    fn = result["n_attacks"] - tp
    metrics = {"tp": tp, "fp": fp, "fn": fn}
    if tp + fp:
        metrics["precision"] = tp / (tp + fp)
    if tp + fn:
        metrics["recall"] = tp / (tp + fn)
    if 2 * tp + fp + fn:
        metrics["f1"] = 2 * tp / (2 * tp + fp + fn)
    return metrics


def alert_latency(alerts: list[dict]) -> dict:
    result = {**decision_summary(alerts), **explanation_summary(alerts)}
    for name, field in (("decision", "call_s"), ("explain", "explain_s")):
        values = [a[field] for a in alerts if a.get(field) is not None]
        result[name + "_count"] = len(values)
        if values:
            result[name + "_s_max"] = max(values)
    return result


def print_detection_metrics(metrics: dict) -> None:
    values = ["{} {:.1f}%".format(name.capitalize() if name != "f1" else "F1", 100 * metrics[name])
              for name in ("precision", "recall", "f1") if name in metrics]
    if values:
        print("  " + "    ".join(values))


def print_latency(lat: dict, timing: dict | None, has_events: bool) -> None:
    rows = []
    for name, label in (("decision", "Event -> alert"), ("explain", "Alert -> explanation")):
        if lat[name + "_count"]:
            rows.append((label, lat[name + "_s_p50"], lat[name + "_s_p95"], lat[name + "_s_max"], "s"))
    if timing and has_events:
        rows.append(("on_event() processing", timing["event_ms_p50"], timing["event_ms_p95"],
                     timing["event_ms_max"], "ms"))
    if rows:
        print("\n  {:25s} {:>12s} {:>12s} {:>12s}".format("", "p50", "p95", "max"))
        for label, p50, p95, maximum, unit in rows:
            print("  {:25s} {:>10.3f} {:2s} {:>10.3f} {:2s} {:>10.3f} {:2s}".format(
                label, p50, unit, p95, unit, maximum, unit))
    if lat["explained"]:
        print("  Explanations received: {}; ({} of {} list valid event IDs)".format(
            lat["explained"], lat["explanations_with_valid_event_ids"], lat["explained"]))


def print_report(label, set_name, mode, s, waves, machines, info, tim, lat, build_s) -> None:
    w = 78
    print("\n" + "=" * w)
    if mode == "instant":
        print(BANNER)
    print("RESULTS -- {}   (set: {}, mode: {}, {} waves, {} with an attack)".format(
        label, set_name, mode, s["n_waves"], s["n_attack_waves"]))
    print("=" * w)
    metrics = s["detection_metrics"]
    print("\nOVERALL DETECTION SUMMARY")
    print("\n  {:22s} {:>18s} {:>18s}".format("", "Actual attack", "Benign activity"))
    print("  {:22s} {:>18s} {:>18s}".format(
        "Alert raised", "{} TP".format(metrics["tp"]), "{} FP".format(metrics["fp"])))
    print("  {:22s} {:>18s}".format("Attack missed", "{} FN".format(metrics["fn"])))
    print_detection_metrics(metrics)
    print("\n  Attacks detected: {} / {}".format(s["attacks_detected"], s["n_attacks"]))
    print("  Caught on time / after execution / missed: {} / {} / {}".format(
        s["caught_on_time"], s["caught_after_execution"], s["missed_attacks"]))
    if s["n_attacks"]:
        print("  Timeliness score: {:.3f}".format(s["timeliness_score"]))
    print("  False alarms: {} ({:.2f} per wave; {} warm-up, {} live)".format(
        s["false_alarms"], s["false_alarms_per_wave"], s["false_alarms_warmup"], s["false_alarms_live"]))
    print("  Alerts: {} total, {} duplicates, {} repeat false alarms, {} late timeouts, {} context, {} excused, {} invalid".format(
        s["n_alerts"], s["duplicates"], s["repeat_false_alarms"], s["late_timeout"], s["context"],
        s["excused"], s["invalid"]))
    if s["attacks_detected"]:
        print("  Evidence precision: {:.1f}%".format(100 * s["evidence_precision"]))
    print("\nOVERALL LATENCY")
    has_events = any(v.get("live_delivered", 0) for v in (info or {}).get("waves", {}).values())
    print_latency(lat, tim, has_events)
    if s["delay_s_p50"] is not None:
        print("  Attack onset -> detection: {:.3f} s p50, {:.3f} s max".format(
            s["delay_s_p50"], s["delay_s_max"]))
    if tim:
        print("  Maximum stream lag: {:.3f} s; warm-up compute max: {:.1f} s".format(
            tim["max_live_lag_s"], tim["warm_s_max"]))
        print("  Total evaluation time: {:.1f} s".format(tim["total_wall_s"]))
        print("  Events dropped / alerts lost / detector errors: {} / {} / {}".format(
            tim["events_dropped"], tim["alerts_lost"], tim["n_errors"]))
        if tim["n_errors"]:
            print("  Errors: {}".format(tim["errors_sample"][:2]))
        if tim["skipped_waves"]:
            print("  Not played (detector hung): " + ", ".join(tim["skipped_waves"]))
    if build_s is not None:
        print("  One-off build: {:.1f} s (not counted above)".format(build_s))
    print("\n" + "=" * w + "\nPER-WAVE RESULTS\n" + "=" * w)
    for wid, v in waves.items():
        wi = (info or {}).get("waves", {}).get(wid, {})
        print("\n{} -- {} -- {}".format(wid, machines.get(wid, ""), "attack present" if v["attack"] else "no attack"))
        print("-" * w)
        m = v["detection_metrics"]
        print("  TP / FP / FN: {} / {} / {}".format(m["tp"], m["fp"], m["fn"]))
        print_detection_metrics(m)
        if wi.get("skipped"):
            print("  Not played: a previous detector call hung past its cap")
        for attack in v["attacks"].values():
            if attack["status"] == "missed":
                print("  {}: Missed".format(attack["name"]))
            else:
                print("  {}: {}, malicious event {} / {}; detection delay {:.3f} s".format(
                    attack["name"], attack["status"].replace("_", " ").capitalize(),
                    attack["caught_at_event"], attack["n_malicious_events"], attack["delay_s"]))
        print("  Alerts: {}; true detections: {}; false alarms: {} ({} warm-up, {} live)".format(
            v["n_alerts"], m["tp"], m["fp"], v["false_alarms_warmup"], v["false_alarms_live"]))
        print("  Duplicates / repeat false alarms / context / excused / invalid / late timeout: {} / {} / {} / {} / {} / {}".format(
            v["duplicates"], v["repeat_false_alarms"], v["context"], v["excused"], v["invalid"], v["late_timeout"]))
        if v["evidence_precision"]:
            print("  Evidence precision: {:.1f}%".format(
                100 * sum(v["evidence_precision"]) / len(v["evidence_precision"])))
        print_latency(v["latency"], wi if "warm_s" in wi else None, bool(wi.get("live_delivered")))
        if "warm_s" in wi:
            print("  Stream lag max: {:.3f} s".format(wi["max_lag_s"]))
            print("  Events delivered: {} warm-up + {} live".format(wi["warm_delivered"], wi["live_delivered"]))
            dropped = wi["warm_events"] - wi["warm_delivered"] + wi["live_events"] - wi["live_delivered"]
            print("  Events dropped / alerts lost / errors: {} / {} / {}".format(dropped, wi["alerts_lost"], wi["n_errors"]))
            print("  Wave duration: {:.1f} s".format(wi["wall_s"]))
            if wi.get("hung"):
                print("  Wave abandoned: detector call hung past its cap")
            if wi["errors"]:
                print("  Errors: {}".format(wi["errors"]))
    if mode == "instant":
        print(BANNER)
    print("=" * w)


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--detector", help="module.path:ClassName of your Detector subclass")
    ap.add_argument("--alerts", help="re-score an existing alerts.jsonl instead of running")
    ap.add_argument("--set", default="fast",
                    help="fast = public fast (~15 min; ~37 min with hidden internally); "
                        "full = public full (~57 min; ~204 min with all hidden internally)")
    ap.add_argument("--waves", default=None,
                    help="comma-separated wave IDs; internal hidden IDs use the hidden- prefix")
    ap.add_argument("--mode", choices=("realtime", "instant"), default="realtime",
                    help="realtime (default, graded) or instant (debug: no pacing, NOT graded)")
    ap.add_argument("--data", default=DEFAULT_DATA, help="directory with waves.json, <wave>/, answers.json")
    ap.add_argument("--hidden-data", default=None,
                    help="internal hidden eval directory; auto-detected in the internal release")
    ap.add_argument("--public-only", action="store_true", help="do not auto-include internal hidden waves")
    ap.add_argument("--answers", default=None, help="answer key (default: <data>/answers.json)")
    ap.add_argument("--train", default=DEFAULT_TRAIN, help="passed to your Detector's constructor")
    ap.add_argument("--out", default=DEFAULT_OUT, help="where to write alerts.jsonl")
    ap.add_argument("--report", default=None, help="also write the full scorecard as JSON")
    ap.add_argument("--no-explain", action="store_true", help="reject explanation callbacks (faster iteration)")
    ap.add_argument("--label", default=None)
    args = ap.parse_args()
    if not args.detector and not args.alerts:
        sys.exit("give --detector module:Class, or --alerts path/to/alerts.jsonl")

    answers_path = args.answers or os.path.join(args.data, "answers.json")
    public_waves = load_json(os.path.join(args.data, "waves.json"))["waves"]
    public_answers = load_json(answers_path).get("waves") if os.path.exists(answers_path) else None
    hidden_eval_dir = None if args.public_only else args.hidden_data
    if not args.public_only and hidden_eval_dir is None:
        candidate_hidden = os.path.abspath(os.path.join(ROOT, "..", "data", "hidden", "eval"))
        if os.path.isfile(os.path.join(candidate_hidden, "waves.json")):
            hidden_eval_dir = candidate_hidden
    hidden_waves, hidden_answers = None, None
    if hidden_eval_dir:
        hidden_waves = load_json(os.path.join(hidden_eval_dir, "waves.json"))["waves"]
        hidden_answer_path = os.path.join(hidden_eval_dir, "answers.json")
        hidden_answers = load_json(hidden_answer_path).get("waves") if os.path.isfile(hidden_answer_path) else None
    try:
        waves, answer_waves, stream_dirs, set_label = select_waves(
            public_waves, public_answers, args.data, args.set, hidden_waves, hidden_answers,
            hidden_eval_dir, [x.strip() for x in args.waves.split(",") if x.strip()] if args.waves else None)
    except ValueError as exc:
        sys.exit(str(exc))
    args.set = set_label
    print("set: {}   mode: {}   waves: {}".format(
        args.set, "replay of " + args.alerts if args.alerts else args.mode,
        ", ".join(w["wave_id"] for w in waves)))
    if args.mode == "instant" and not args.alerts:
        print(BANNER)

    build_s, info, mode = None, None, args.mode
    if args.alerts:
        with open(args.alerts, encoding="utf-8") as fh:
            alerts = [json.loads(ln) for ln in fh if ln.strip()]
        if os.path.exists(run_info_path(args.alerts)):
            info = load_json(run_info_path(args.alerts))
            mode = info.get("mode", mode)
            waves = [w for w in waves if w["wave_id"] in info["waves"]]
        label = args.label or os.path.basename(args.alerts)
    else:
        mod = args.detector.split(":", 1)[0]
        if mod.endswith("reference_detectors") and os.path.exists(answers_path):
            os.environ.setdefault("ORACLE_ANSWERS", os.path.abspath(answers_path))
            if hidden_eval_dir and hidden_answers is not None:
                os.environ["ORACLE_HIDDEN_ANSWERS"] = os.path.abspath(
                    os.path.join(hidden_eval_dir, "answers.json"))
        det, build_s = load_detector(args.detector, args.train)
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        alerts, info = run(det, waves, args.data, args.mode == "realtime", not args.no_explain,
                   args.out, answer_waves, stream_dirs=stream_dirs)
        print("\nalerts -> " + args.out)
        label = args.label or args.detector

    if answer_waves is None:
        print("no answer key at {} -- run recorded, scoring skipped".format(answers_path))
        return 0
    wave_ids = [w["wave_id"] for w in waves]
    result = score(alerts, answer_waves, wave_ids)
    scored = [
        {**alert, **row}
        for wave_id, wave_result in result["waves"].items()
        for alert, row in zip(
            [a for a in alerts if a.get("wave") == wave_id], wave_result["alerts"], strict=True)
    ]
    result["summary"]["detection_metrics"] = detection_metrics(result["summary"])
    for wave_id, wave_result in result["waves"].items():
        wave_result["detection_metrics"] = detection_metrics(wave_result)
        wave_result["latency"] = alert_latency([a for a in scored if a["wave"] == wave_id])
    lat = alert_latency(scored)
    tim = timing_summary(info) if info else None
    print_report(label, args.set, mode, result["summary"], result["waves"],
                 {w["wave_id"]: w["machine"] for w in waves}, info, tim, lat, build_s)
    if args.report:
        os.makedirs(os.path.dirname(os.path.abspath(args.report)), exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump({"label": label, "set": args.set, "mode": mode, "graded": mode == "realtime",
                       "build_s": build_s, "timing": tim, "latency": lat, "run": info, **result}, fh, indent=1)
        print("scorecard -> " + args.report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
