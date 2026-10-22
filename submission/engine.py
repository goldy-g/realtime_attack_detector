"""3.5-3.7 The model worker: verdicts in priority order, an alert the moment the model says attack,
then the explanation with event IDs chosen and checked by code.

One background thread makes every model call, one at a time, so a call always
has the whole CPU. `on_event()` never waits for it: the event thread only updates
state and pushes cases into a priority queue.

Rules (3.6):
- the queue puts cases an expert recognises first (experts.py, SQ-1), then orders by
  fleet rarity (rarer first), then by age. The attack's own case otherwise waits
  behind its lead-up cases, which are just as rare and arrived first. The expert
  only orders the queue and feeds the explanation; the SLM still makes every call;
- at most one alert per process: once a process is alerted on, its later cases
  (its other connections) skip the model. Its children are still judged: an
  alert that lands one step before the alert point is only "context" and earns
  nothing, and a repeat alert costs nothing (duplicates and repeat false alarms
  are free), so silencing the tree could only lose a detection (run v1.1-dev,
  atk-efdb: cmd.exe running a downloaded .bat alerted 1 s early, and the hidden
  PowerShell it started was never judged);
- verdict calls always go before explanation calls;
- when the wave closes (`callbacks.cancelled`), its pending work is dropped.
"""

from __future__ import annotations

import heapq
import itertools
import json
import logging
import threading
import time
from dataclasses import dataclass, field

from . import cases, config, experts, prompts
from .baseline import Candidate
from .llm import EXPLAIN_SLOT, VERDICT_SLOT, LlamaServer
from .state import MachineState, base, line

log = logging.getLogger("detector")

# Evidence order: what an analyst checks first. Module loads and thread events come last.
_EVIDENCE_RANK = {"PROCESS CREATE": 0, "FLOW START": 1, "SHELL COMMAND": 2, "FILE CREATE": 3, "FILE WRITE": 3,
                  "REGISTRY ADD": 4, "REGISTRY EDIT": 4, "TASK CREATE": 4, "THREAD REMOTE_CREATE": 5}


@dataclass
class Wave:
    """Everything that belongs to one wave; the worker checks `callbacks.cancelled` before acting on it."""
    machine: str
    callbacks: object
    state: MachineState
    alerted: set = field(default_factory=set)          # objectIDs of processes already alerted on
    queue: list = field(default_factory=list)          # heap of (0 if expert else 1, fleet, t, seq, Candidate)
    explain_jobs: list = field(default_factory=list)   # FIFO of dict
    stats: dict = field(default_factory=lambda: {"cases": 0, "expert_cases": 0, "judged": 0, "skipped_alerted": 0,
                                                 "shed": 0, "alerts": 0, "explained": 0, "fallback_explanations": 0})


class Engine:
    def __init__(self, server: LlamaServer) -> None:
        self.server = server
        self.lock = threading.Lock()             # guards the current wave's state, queue and job list
        self.wake = threading.Condition(self.lock)
        self.wave: Wave | None = None
        self.seq = itertools.count()
        self.decisions = open(config.DECISIONS_FILE, "a", encoding="utf-8") if config.DECISIONS_FILE else None
        self.thread = threading.Thread(target=self._run, name="model-worker", daemon=True)
        self.thread.start()

    # ------------------------------------------------------------------ called from the event thread
    def start_wave(self, wave: Wave) -> None:
        with self.lock:
            old = self.wave
            if old is not None:
                log.info("wave %s done: %s", old.machine, old.stats)
            self.wave = wave

    def submit(self, wave: Wave, cand: Candidate) -> None:
        """Queue a case. Called with the lock held by the detector."""
        wave.stats["cases"] += 1
        cand.expert = experts.hidden_powershell(cand)
        if cand.expert:
            wave.stats["expert_cases"] += 1
        heapq.heappush(wave.queue, (0 if cand.expert else 1, cand.fleet, cand.t, next(self.seq), cand))
        if len(wave.queue) > config.QUEUE_MAX:          # shed the most common pending cases
            wave.queue.sort()
            dropped = len(wave.queue) - config.QUEUE_MAX
            del wave.queue[config.QUEUE_MAX:]
            heapq.heapify(wave.queue)
            wave.stats["shed"] += dropped
        self.wake.notify()

    # ------------------------------------------------------------------ worker thread
    def _run(self) -> None:
        while True:
            with self.lock:
                while not self._has_work():
                    self.wake.wait(timeout=0.5)
                wave = self.wave
                if wave.callbacks.cancelled.is_set():
                    wave.queue.clear()
                    wave.explain_jobs.clear()
                    continue
                job = ("verdict", heapq.heappop(wave.queue)[-1]) if wave.queue else ("explain", wave.explain_jobs.pop(0))
            try:
                if job[0] == "verdict":
                    self._verdict(wave, job[1])
                else:
                    self._explain(wave, job[1])
            except Exception:  # noqa: BLE001 -- one bad case must not stop the worker
                log.exception("model worker: %s failed", job[0])
                self._recover()

    def _has_work(self) -> bool:
        w = self.wave
        return w is not None and (bool(w.queue) or bool(w.explain_jobs))

    def _recover(self) -> None:
        if not self.server.alive():
            log.warning("llama-server died; restarting")
            try:
                self.server.start()
            except Exception:  # noqa: BLE001
                log.exception("llama-server restart failed")
                time.sleep(2)

    def _verdict(self, wave: Wave, cand: Candidate) -> None:
        ev = cand.event
        case_proc = ev["objectID"] if cand.kind == "process" else ev.get("actorID")
        with self.lock:
            if case_proc in wave.alerted:
                wave.stats["skipped_alerted"] += 1
                return
            text = cases.render(wave.state, cand)
            picked_at_stream = wave.state.now
        wave.stats["judged"] += 1
        t0 = time.perf_counter()
        out = self.server.chat(prompts.verdict_messages(text), max_tokens=16, slot=VERDICT_SLOT,
                               grammar=prompts.VERDICT_GRAMMAR)
        verdict, confidence = parse_verdict(out["text"])
        attack = verdict == "attack" and confidence >= config.ALERT_MIN_CONFIDENCE
        alert_id = None
        if attack and not wave.callbacks.cancelled.is_set():
            with self.lock:
                fresh = case_proc not in wave.alerted
                if fresh:
                    wave.alerted.add(case_proc)
                    evidence = self._evidence(wave.state, ev["id"], case_proc)
            if fresh:
                alert_id = wave.callbacks.alert(ev["id"])
            if alert_id is not None:
                wave.stats["alerts"] += 1
                job = {"alert_id": alert_id, "case": text, "confidence": confidence, "proc": case_proc,
                       "evidence": evidence, "cand": cand, "alerted_at": time.perf_counter()}
                if config.EXPLAIN:
                    with self.lock:
                        wave.explain_jobs.append(job)
        self._record(wave, cand, text, verdict, confidence, out, time.perf_counter() - t0, alert_id, picked_at_stream)

    def _evidence(self, state: MachineState, alert_eid: str, proc_oid: str) -> list[str]:
        """The alert event, then the alerted process tree's events delivered so far, most telling first."""
        found = []
        for oid in state.subtree(proc_oid):
            proc = state.procs.get(oid)
            if proc:
                found += [(_EVIDENCE_RANK.get(kind, 6), t, eid) for eid, t, kind in proc.events]
        found.sort()
        ids = [alert_eid] + [eid for _, _, eid in found if eid != alert_eid]
        return ids[: config.EVIDENCE_MAX]

    def _explain(self, wave: Wave, job: dict) -> None:
        with self.lock:
            followed = []
            for oid in wave.state.subtree(job["proc"]):
                proc = wave.state.procs.get(oid)
                if proc:
                    followed += list(proc.notable)
            followed = [ln for _, ln in sorted(followed)][-10:]
        text = None
        try:
            out = self.server.chat(prompts.explain_messages(job["case"], followed, job["confidence"], job["cand"].expert),
                                   max_tokens=config.EXPLAIN_MAX_TOKENS, slot=EXPLAIN_SLOT,
                                   grammar=prompts.EXPLAIN_GRAMMAR)
            text = out["text"].strip() or None
        except Exception:  # noqa: BLE001 -- the alert still gets an explanation, from facts alone
            log.exception("explanation call failed")
        if text is None:
            wave.stats["fallback_explanations"] += 1
            text = fallback_explanation(job["cand"], job["confidence"])
        if wave.callbacks.explain(job["alert_id"], text, job["evidence"]):
            wave.stats["explained"] += 1

    def _record(self, wave: Wave, cand: Candidate, text: str, verdict: str, confidence: int, out: dict,
                seconds: float, alert_id: str | None, picked_at_stream: float) -> None:
        log.info("%s %s %s fleet=%d%s -> %s %d (%.2fs)%s", wave.machine, cand.kind, "→".join(cand.pair), cand.fleet,
                 " expert" if cand.expert else "", verdict, confidence, seconds, " ALERT " + alert_id if alert_id else "")
        if self.decisions:
            rec = {"machine": wave.machine, "event_id": cand.event["id"], "ts": cand.event["timestamp"],
                   "kind": cand.kind, "pair": cand.pair, "fleet": cand.fleet, "expert": list(cand.expert), "verdict": verdict,
                   "confidence": confidence, "alert_id": alert_id, "model_s": round(seconds, 3),
                   "queued_stream_s": round(picked_at_stream - cand.t, 3), "prompt_n": out.get("prompt_n"),
                   "cache_n": out.get("cache_n"), "case": text}
            self.decisions.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self.decisions.flush()


def parse_verdict(text: str) -> tuple[str, int]:
    try:
        obj = json.loads(text)
        return str(obj.get("verdict", "normal")), int(obj.get("confidence", 0))
    except Exception:  # noqa: BLE001 -- an unreadable reply is no evidence of an attack
        return "invalid", 0


def fallback_explanation(cand: Candidate, confidence: int) -> str:
    """Used only when the explanation call fails: the facts of the case, no model prose."""
    ev = cand.event
    p = ev.get("properties") or {}
    what = ("new process {} started by {}".format(base(p.get("image_path")), base(p.get("parent_image_path")))
            if cand.kind == "process" else
            "outbound connection from {} to {}:{}".format(base(p.get("image_path")), p.get("dest_ip"), p.get("dest_port")))
    checked = " Code also recognised: {}.".format("; ".join(cand.expert)) if cand.expert else ""
    return ("Attack: the model judged this {} to be an attack (confidence {}).\n"
            "Why this event: the {} pair is new for this machine and was seen on {} of {} other machines.{}\n"
            "Chain: {}\nEvidence: {}").format(what, confidence, " -> ".join(cand.pair), cand.fleet, cand.fleet_of, checked,
                                             " -> ".join(x for x in cand.pair if x), line(ev))
