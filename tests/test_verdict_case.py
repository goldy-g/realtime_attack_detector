"""v1.8: the verdict's shorter case, its download line, and what the explanation is told.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest

import test_detector as td
from test_rdp_short import run_wave

from submission import cases, config, prompts

CASE = """Machine host-f3ac · 2000-01-09 10:28:11
New process: ckfgw.exe as dcoombes (domain SYSTEMIACOM)
Command line: "C:\\Users\\dcoombes\\AppData\\Local\\Temp\\cKfGW.exe"
Parent: gup.exe, started 10:28:00 as dcoombes (domain SYSTEMIACOM): "C:\\Program Files (x86)\\Notepad++\\updater\\gup.exe" -verbose -v5.82
Its program file was written 3 s earlier by gup.exe.
Baseline: gup.exe → ckfgw.exe is new for this machine (not in its last hour); seen on 0 of 61 other machines.
Recent activity of these processes:
- 10:27:52 notepad++.exe connected to 53.192.68.50:80
- 10:28:00 notepad++.exe started gup.exe: "C:\\Program Files (x86)\\Notepad++\\updater\\gup.exe" -verbose -v5.82
- 10:28:05 gup.exe connected to 53.192.68.50:80
- 10:28:05 gup.exe wrote C:\\Users\\dcoombes\\AppData\\Local\\Temp\\cKfGW.exe
Remote logons on this machine (last 2 min):
- 10:27:40 network logon by ANONYMOUS LOGON from fe80::1"""


class VerdictCase(unittest.TestCase):
    def test_drops_the_machine_line_activity_and_logons(self):
        v = cases.verdict_case(CASE)
        for gone in ("Machine ", "Recent activity", "Remote logons", "- 10:"):
            self.assertNotIn(gone, v)
        for kept in ("New process: ckfgw.exe", "Command line:", "Parent: gup.exe", "Baseline: gup.exe → ckfgw.exe"):
            self.assertIn(kept, v)

    def test_folds_a_download_into_the_written_line(self):
        v = cases.verdict_case(CASE)
        self.assertIn("Its program file was written 3 s earlier by gup.exe, right after gup.exe connected to "
                      "53.192.68.50:80 (public address).", v)

    def test_no_public_connection_by_the_writer_leaves_the_line(self):
        private = CASE.replace("- 10:28:05 gup.exe connected to 53.192.68.50:80", "- 10:28:05 gup.exe connected to 10.0.0.9:80")
        self.assertIn("Its program file was written 3 s earlier by gup.exe.\n", cases.verdict_case(private))
        other = CASE.replace("- 10:28:05 gup.exe connected to 53.192.68.50:80\n", "")
        self.assertIn("Its program file was written 3 s earlier by gup.exe.\n", cases.verdict_case(other))  # notepad++ only

    def test_a_case_without_blocks_only_loses_its_machine_line(self):
        plain = "\n".join(CASE.split("\n")[:6])
        self.assertEqual(cases.verdict_case(plain), "\n".join(CASE.split("\n")[1:6]))


class StartupCheck(unittest.TestCase):
    """v1.8.1: the main model is judged by its expected real verdict time, probe x 1.2, against 4 s."""

    def test_measured_machines(self):
        self.assertTrue(config.main_model_fits(1.44))    # the Mac's E4B probe: real median 1.65 s
        self.assertFalse(config.main_model_fits(3.88))   # the 4-core laptop's: real median 4.64 s
        self.assertTrue(config.main_model_fits(3.3))     # 3.96 s expected, just inside
        self.assertFalse(config.main_model_fits(3.4))


class ExplanationInput(unittest.TestCase):
    def test_remote_desktop_decisions_are_named(self):
        body = prompts.explain_messages("case", [], 95, (), rdp=True)[1]["content"]
        self.assertIn("The verdict was attack, confidence 95. " + prompts.RDP_DECIDED, body)
        self.assertNotIn(prompts.RDP_DECIDED, prompts.explain_messages("case", [], 95, ())[1]["content"])
        self.assertNotIn(prompts.RDP_DECIDED, prompts.explain_messages("case", [], None, (), rdp=True)[1]["content"])

    def test_engine_gives_the_verdict_the_short_case_and_the_explanation_the_whole(self):
        cb, _, server = run_wave(td.EngineRules.RDP_HOP, "Remote Desktop chain", rdp_short=False)
        self.assertEqual(cb.alerts, [td.EngineRules.RDP_HOP[-1]["id"]])
        for slot, text in server.texts:
            if slot in (0, 2):
                self.assertFalse(text.startswith("Machine "), text)
        explain = [t for slot, t in server.texts if slot == 1]
        self.assertTrue(explain and explain[0].startswith("Machine ") and prompts.RDP_DECIDED in explain[0])


if __name__ == "__main__":
    unittest.main()
