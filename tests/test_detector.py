"""Unit tests for the detector's code paths, with a scripted stand-in for the model.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import base64
import os
import sys
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from submission import cases  # noqa: E402
from submission.baseline import Fleet, Triage  # noqa: E402
from submission.engine import Engine, Wave, parse_verdict  # noqa: E402
from submission.state import MachineState, norm_path, ts_seconds, user_text  # noqa: E402

N = [0]


def ev(obj, action, actor, objid=None, ts="2000-01-01T10:00:00.000-04:00", **props):
    N[0] += 1
    return {"id": "e{}".format(N[0]), "timestamp": ts, "hostname": "h", "object": obj, "action": action,
            "actorID": actor, "objectID": objid or "o{}".format(N[0]), "pid": 1, "ppid": 0, "principal": "X\\u",
            "tid": -1, "properties": props}


def pstart(parent, child, oid, ts="2000-01-01T10:00:00.000-04:00", cmd="", parent_actor="p0"):
    return ev("PROCESS", "CREATE", parent_actor, oid, ts, image_path="C:\\x\\" + child,
              parent_image_path="C:\\x\\" + parent, command_line=cmd, user="DOM\\alice")


def flow(image, actor, ip, port, proto="6", ts="2000-01-01T10:00:01.000-04:00"):
    return ev("FLOW", "START", actor, None, ts, image_path=image, dest_ip=ip, dest_port=str(port),
              src_ip="10.0.0.2", src_port="5000", direction="outbound", l4protocol=proto)


class Callbacks:
    def __init__(self):
        self.cancelled = threading.Event()
        self.alerts, self.explanations = [], []

    def alert(self, event_id):
        self.alerts.append(event_id)
        return "A{}".format(len(self.alerts))

    def explain(self, alert_id, text, ids):
        self.explanations.append((alert_id, text, ids))
        return True


class FakeServer:
    """Answers 'attack' when the case mentions the marker, 'normal' otherwise."""

    def __init__(self, marker="evil.exe"):
        self.marker, self.calls = marker, []

    def chat(self, messages, max_tokens, slot, grammar=None, timeout=None):
        text = messages[-1]["content"]
        self.calls.append(slot)
        if slot == 1:
            return {"text": "Attack: x\nWhy this event: y\nChain: a -> b\nEvidence: z", "wall_s": 0.0}
        verdict = "attack" if self.marker in text else "normal"
        return {"text": '{"verdict": "%s", "confidence": 90}' % verdict, "wall_s": 0.0}

    def alive(self):
        return True


class Parsing(unittest.TestCase):
    def test_timestamps_with_any_fraction(self):
        self.assertAlmostEqual(ts_seconds("2000-02-07T15:41:17.5-04:00") - ts_seconds("2000-02-07T15:41:17.25-04:00"), 0.25)

    def test_decode_encoded_command(self):
        blob = base64.b64encode("IEX (New-Object Net.WebClient)".encode("utf-16le")).decode()
        self.assertEqual(cases.decode_ps("powershell -noP -w 1 -enc " + blob), "IEX (New-Object Net.WebClient)")
        self.assertIsNone(cases.decode_ps("powershell -File x.ps1"))

    def test_verdict_parsing(self):
        self.assertEqual(parse_verdict('{"verdict": "attack", "confidence": 77}'), ("attack", 77))
        self.assertEqual(parse_verdict("garbage"), ("invalid", 0))

    def test_paths_and_users(self):
        self.assertEqual(norm_path("\\Device\\HarddiskVolume1\\Temp\\A.exe"), norm_path("C:\\temp\\a.exe"))
        self.assertEqual(user_text("SYSTEMIACOM\\Administrator"), "Administrator (domain SYSTEMIACOM)")


class TriageRules(unittest.TestCase):
    def setUp(self):
        self.state, self.tri = MachineState("h"), Triage("h", Fleet(None))

    def feed(self, e):
        return self.tri.observe(e, self.state.add(e))

    def test_warmup_learns_and_never_emits(self):
        self.assertIsNone(self.feed(pstart("a.exe", "b.exe", "p1")))
        self.tri.live = True
        self.assertIsNone(self.feed(pstart("a.exe", "b.exe", "p2")))          # known from warm-up
        self.assertIsNotNone(self.feed(pstart("a.exe", "c.exe", "p3")))       # new pair
        self.assertIsNone(self.feed(pstart("a.exe", "c.exe", "p4")))          # only the first occurrence

    def test_flows_and_service_noise(self):
        self.tri.live = True
        self.assertIsNotNone(self.feed(flow("C:\\x\\update.exe", "p9", "53.1.2.3", 8080)))
        self.assertIsNone(self.feed(flow("C:\\x\\svchost.exe", "p8", "10.0.0.1", 50123, proto="17")))


class CaseRendering(unittest.TestCase):
    def test_case_shows_nothing_after_its_event(self):
        state, tri = MachineState("h"), Triage("h", Fleet(None))
        tri.live = True
        first = pstart("explorer.exe", "a.exe", "P1", ts="2000-01-01T10:00:00.000-04:00", parent_actor="X")
        cand = tri.observe(first, state.add(first))
        later = pstart("explorer.exe", "later.exe", "P2", ts="2000-01-01T10:00:30.000-04:00", parent_actor="X")
        logon = ev("USER_SESSION", "REMOTE", "S", None, "2000-01-01T10:00:31.000-04:00", user="D\\eve", src_ip="10.0.0.9")
        for e in (later, logon):
            tri.observe(e, state.add(e))
        text = cases.render(state, cand)                       # rendered late, as a queued case would be
        self.assertNotIn("later.exe", text)
        self.assertNotIn("eve", text)


class EngineRules(unittest.TestCase):
    def run_wave(self, events, marker="evil.exe"):
        server, cb = FakeServer(marker), Callbacks()
        engine = Engine(server)
        wave = Wave(machine="h", callbacks=cb, state=MachineState("h"))
        tri = Triage("h", Fleet(None))
        tri.live = True
        engine.start_wave(wave)
        for e in events:
            with engine.lock:
                cand = tri.observe(e, wave.state.add(e))
                if cand:
                    engine.submit(wave, cand)
        deadline = time.time() + 5
        while time.time() < deadline:
            with engine.lock:
                if not wave.queue and not wave.explain_jobs:
                    break
            time.sleep(0.02)
        time.sleep(0.1)
        return cb, wave, server

    def test_alert_then_explanation_with_checked_ids(self):
        other = pstart("a.exe", "b.exe", "P0", parent_actor="Q1")            # an unrelated tree
        start = pstart("wmiprvse.exe", "evil.exe", "P1", parent_actor="W1")
        follow = flow("C:\\x\\evil.exe", "P1", "53.1.2.3", 443)
        cb, wave, _ = self.run_wave([other, start, follow])
        self.assertEqual(cb.alerts, [start["id"]])
        self.assertEqual(len(cb.explanations), 1)
        _, text, ids = cb.explanations[0]
        self.assertTrue(text.startswith("Attack:"))
        self.assertEqual(ids[0], start["id"])                 # the alerted event leads the evidence
        known = {e for p in wave.state.procs.values() for e, _, _ in p.events} | {start["id"]}
        self.assertTrue(set(ids) <= known)                    # only delivered events of the tree

    def test_children_of_an_alerted_process_are_still_judged(self):
        root = pstart("explorer.exe", "evil.exe", "P1", parent_actor="X1")
        child = pstart("evil.exe", "whoami.exe", "P2", parent_actor="P1")    # its case mentions evil.exe too
        cb, wave, _ = self.run_wave([root, child])
        self.assertEqual(cb.alerts, [root["id"], child["id"]])                # an early alert must not hide the next step

    def test_one_alert_per_process(self):
        start = pstart("wmiprvse.exe", "evil.exe", "P1", parent_actor="W1")
        flows = [flow("C:\\x\\evil.exe", "P1", "53.1.2.3", port) for port in (443, 8080)]
        cb, wave, _ = self.run_wave([start] + flows)
        self.assertEqual(cb.alerts, [start["id"]])                             # its later connections skip the model
        self.assertEqual(wave.stats["skipped_alerted"], 2)

    def test_cancelled_wave_does_nothing(self):
        server, cb = FakeServer(), Callbacks()
        cb.cancelled.set()
        engine = Engine(server)
        wave = Wave(machine="h", callbacks=cb, state=MachineState("h"))
        tri = Triage("h", Fleet(None))
        tri.live = True
        engine.start_wave(wave)
        e = pstart("wmiprvse.exe", "evil.exe", "P1")
        with engine.lock:
            engine.submit(wave, tri.observe(e, wave.state.add(e)))
        time.sleep(0.3)
        self.assertEqual(cb.alerts, [])
        self.assertEqual(server.calls, [])

    def test_rarer_cases_first(self):
        fleet = Fleet(None)
        fleet.machines, fleet.pairs = ["m1", "m2"], {"a.exe|common.exe": [0, 1]}
        server, cb = FakeServer(), Callbacks()
        engine = Engine(server)
        wave = Wave(machine="h", callbacks=cb, state=MachineState("h"))
        tri = Triage("h", fleet)
        tri.live = True
        with engine.lock:                                      # queue both before the worker sees the wave
            for e in (pstart("a.exe", "common.exe", "P1"), pstart("a.exe", "rare.exe", "P2")):
                engine.submit(wave, tri.observe(e, wave.state.add(e)))
            self.assertEqual(wave.queue[0][3].pair, ("a.exe", "rare.exe"))


if __name__ == "__main__":
    unittest.main()
