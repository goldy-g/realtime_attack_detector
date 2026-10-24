"""Real-time attack detection with a small language model: the evaluator's entry point.

    on_event ─► state + baselines ─► triage (new?) ─► priority queue ─► SLM verdict ─► alert
                                                                              └─► SLM explanation ─► explain

Code keeps the machine's state and picks the few events that are new for it;
the language model (Gemma 4 E4B on llama.cpp's llama-server, CPU only) makes
every alert decision and writes every explanation. The design and the evidence
behind it: research/DETECTION_APPROACH.md and research/FINDINGS.md.
"""

from __future__ import annotations

import logging
import os
import statistics

try:  # evaluate.py puts evaluator/ on sys.path
    from detector_interface import Detector
except ImportError:  # imported from the repository root, e.g. by tools/ or tests
    from evaluator.detector_interface import Detector

from . import config, prompts
from .baseline import Fleet, Triage
from .engine import Engine, Wave
from .llm import EXPLAIN_SLOT, RDP_SLOT, VERDICT_SLOT, LlamaServer
from .state import MachineState

log = logging.getLogger("detector")

# A neutral case for timing the model at start-up, as long as a median real case (about 375 new
# tokens on the dev waves; a shorter probe made the model look faster than it is). Invented, not from the data.
PROBE_CASE = """Machine probe · 2000-01-01 09:00:00
New process: taskhostw.exe as alice (domain CORP)
Command line: taskhostw.exe Install $(Arg0)
Parent: svchost.exe, started 08:12:44 as SYSTEM: C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule
Grandparent: services.exe (running before the stream began)
Baseline: svchost.exe → taskhostw.exe is new for this machine (not in its last hour); seen on 58 of 61 other machines.
Recent activity of these processes:
- 08:58:02 svchost.exe started consent.exe: C:\\Windows\\system32\\consent.exe 1012 410 000001F3A2B1C2D0
- 08:58:31 svchost.exe started MusNotification.exe: C:\\Windows\\system32\\MusNotification.exe ScheduleWork
- 08:59:12 svchost.exe started wsqmcons.exe: C:\\Windows\\System32\\wsqmcons.exe
- 08:59:40 svchost.exe connected to 10.0.0.5:135
Remote logons on this machine (last 2 min):
- 08:59:51 network logon by alice (domain CORP) from 10.0.0.12"""


def _setup_logging() -> None:
    if config.LOG_FILE and not log.handlers:
        handler = logging.FileHandler(config.LOG_FILE, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)


class MyDetector(Detector):
    def __init__(self, train_dir: str) -> None:
        super().__init__(train_dir)
        _setup_logging()
        self.fleet = Fleet(config.FLEET_FILE)
        self.server = self._start_model()
        # The Remote Desktop specialist only with the main model: under it the fallback E2B missed two of three hops.
        rdp = config.RDP_SPECIALIST and os.path.basename(self.server.model) == config.MODEL_FILE
        if rdp:
            self._warm_rdp(self.server)
        log.info("Remote Desktop specialist prompt: %s", "on" if rdp else "off")
        self.engine = Engine(self.server, rdp_specialist=rdp)
        self.lock = self.engine.lock
        self.wave: Wave | None = None
        self.triage: Triage | None = None

    # ------------------------------------------------------------------ start-up (3.8)
    def _start_model(self) -> LlamaServer:
        server_bin = config.find_server()
        if not server_bin:
            raise RuntimeError("llama-server not found: put it in submission/bin/ or set DETECTOR_SERVER")
        main = config.find_model(config.MODEL_FILE)
        fallback = config.find_model(config.FALLBACK_MODEL_FILE)
        if not main and not fallback:
            raise RuntimeError("no model file found in {}; see submission/README.md".format(config.MODEL_DIRS))
        for path in [p for p in (main, fallback) if p]:
            server = LlamaServer(server_bin, path)
            server.start()
            verdict_s = self._time_verdicts(server)
            log.info("model %s: loaded in %.1fs, verdict %.2fs", server.name, server.load_s, verdict_s)
            if verdict_s <= config.MAX_VERDICT_S or path == fallback or not fallback:
                self._warm_explanations(server)
                return server
            log.warning("%s too slow here (%.2fs > %.1fs); switching to %s", server.name, verdict_s,
                        config.MAX_VERDICT_S, config.FALLBACK_MODEL_FILE)
            server.stop()
        raise RuntimeError("unreachable")

    @staticmethod
    def _time_verdicts(server: LlamaServer) -> float:
        """Median of warm verdict calls on the probe case, the system prompt already cached."""
        times = []
        for i in range(4):
            # vary the case a little so each call reads it fresh, as a real case would be
            case = PROBE_CASE.replace("09:00:00", "09:00:0{}".format(i))
            out = server.chat(prompts.verdict_messages(case), max_tokens=16, slot=VERDICT_SLOT,
                              grammar=prompts.VERDICT_GRAMMAR)
            if i:
                times.append(out["wall_s"])
        return statistics.median(times)

    @staticmethod
    def _warm_explanations(server: LlamaServer) -> None:
        """Cache the explanation prompt now, so the first real explanation is not slower."""
        if config.EXPLAIN:
            server.chat(prompts.explain_messages(PROBE_CASE, [], 0), max_tokens=8, slot=EXPLAIN_SLOT)

    @staticmethod
    def _warm_rdp(server: LlamaServer) -> None:
        """Cache the Remote Desktop specialist prompt now, so the first Remote Desktop verdict is not slower."""
        server.chat(prompts.rdp_messages(PROBE_CASE), max_tokens=16, slot=RDP_SLOT, grammar=prompts.VERDICT_GRAMMAR)

    # ------------------------------------------------------------------ the evaluator's calls
    def start_wave(self, machine: str, callbacks) -> None:
        super().start_wave(machine, callbacks)
        wave = Wave(machine=machine, callbacks=callbacks, state=MachineState(machine))
        with self.lock:
            self.wave = wave
            self.triage = Triage(machine, self.fleet)
        self.engine.start_wave(wave)

    def on_live(self) -> None:
        with self.lock:
            if self.triage:
                self.triage.live = True

    def on_event(self, event: dict) -> None:
        with self.lock:
            wave, triage = self.wave, self.triage
            if wave is None:
                return
            t = wave.state.add(event)
            cand = triage.observe(event, t)
            if cand is not None:
                self.engine.submit(wave, cand)

    def close(self) -> None:
        self.server.stop()

