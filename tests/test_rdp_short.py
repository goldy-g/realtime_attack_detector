"""v1.7: the short Remote Desktop case under the fallback model.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import time
import unittest

import test_detector as td

from submission import cases, prompts
from submission.baseline import Fleet, Triage
from submission.engine import Engine, Wave
from submission.state import MachineState


def run_wave(events, marker, rdp_short):
    server, cb = td.FakeServer(marker), td.Callbacks()
    engine = Engine(server, rdp_specialist=True, rdp_short=rdp_short)
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


class ShortRdpCase(unittest.TestCase):
    CASE = ("Machine h · 2000-01-01 10:06:20\n"
            "Outbound connection: mstsc.exe → 10.0.0.8:3389 (private address, protocol TCP)\n"
            "Process: mstsc.exe, started 10:06:00 as admin (domain D)\n"
            "Its parent: explorer.exe, started 10:01:31 as admin (domain D)\n"
            "Its desktop session began 10:00:30 with a Remote Desktop logon by admin (domain D) from 10.0.0.7 "
            "(its connection came in at 10:00:00).\n"
            "Remote Desktop chain: this session arrived by Remote Desktop from 10.0.0.7 and this connection "
            "opens Remote Desktop to 10.0.0.8.\n"
            "Baseline: mstsc.exe has not used port 3389 in this machine's last hour; seen on 0 of 61 other machines.\n"
            "Recent activity of these processes:\n"
            "- 10:06:00 explorer.exe started mstsc.exe: mstsc.exe")

    def test_keeps_only_the_connection_and_chain_lines(self):
        self.assertEqual(cases.short_rdp(self.CASE).split("\n"),
                         [self.CASE.split("\n")[1], self.CASE.split("\n")[5]])

    def test_a_local_session_leaves_only_the_connection(self):
        local = "\n".join(ln for ln in self.CASE.split("\n") if not ln.startswith(("Its desktop", "Remote Desktop")))
        self.assertEqual(cases.short_rdp(local), self.CASE.split("\n")[1])

    def test_fallback_specialist_reads_the_short_case_and_explanation_the_whole(self):
        cb, wave, server = run_wave(td.EngineRules.RDP_HOP, "Remote Desktop chain", rdp_short=True)
        self.assertEqual(cb.alerts, [td.EngineRules.RDP_HOP[-1]["id"]])
        rdp_texts = [t for slot, t in server.texts if slot == 2]
        self.assertEqual(len(rdp_texts), 1)
        self.assertTrue(all(ln.startswith(cases.SHORT_RDP_LINES) for ln in rdp_texts[0].split("\n")), rdp_texts[0])
        self.assertIn("Remote Desktop chain: ", rdp_texts[0])
        self.assertEqual([s for slot, s in server.systems if slot == 2], [prompts.RDP_SYSTEM])
        explain = [t for slot, t in server.texts if slot == 1]
        self.assertTrue(explain and "Its desktop session began" in explain[0] and "Baseline:" in explain[0])

    def test_main_model_specialist_reads_the_whole_case(self):
        _, _, server = run_wave(td.EngineRules.RDP_HOP, "Remote Desktop chain", rdp_short=False)
        rdp_texts = [t for slot, t in server.texts if slot == 2]
        self.assertEqual(len(rdp_texts), 1)
        self.assertIn("Its desktop session began", rdp_texts[0])
        self.assertIn("Baseline:", rdp_texts[0])


if __name__ == "__main__":
    unittest.main()
