"""Experts for known behaviours (research/sq1): code that recognises an attack pattern and says why.

They never decide. Here an expert's hit only moves its case to the front of the
model's queue and hands its reasons to the explanation call; every alert still
comes from the SLM's verdict (solution 1, within "detection decisions must come
from the SLM"). If the graders allowed other models to decide (Q-5), the same hit
could raise the alert at once (solution 2, research/DETECTION_APPROACH.md): set
DETECTOR_EXPERT_RAISES=1 (config.EXPERT_RAISES; off in the submission).

SQ-1 tested nine experts offline on the labelled cases. One survived
leave-one-attack-type-out: hidden PowerShell, written from three delivery types
(remote WMI, an Office macro, a downloaded batch file). It matches no benign case
among the 703, and putting its cases first lifted mean timeliness from 0.783 to
0.892 on dev and from 0.659 to 0.767 on holdout, with recall and false alarms
unchanged.
"""

from __future__ import annotations

import re

from .baseline import Candidate
from .cases import decode_ps
from .state import base

ENC_FLAG = re.compile(r"\s-e(c|n|nc|nco|ncod|ncode|ncoded|ncodedcommand)?\s", re.I)
HIDDEN = re.compile(r"\s-w(indowstyle|in|i)?\s+(hidden|1)\b", re.I)
NOPROFILE = re.compile(r"\s-nop(rofile)?\b", re.I)
CRADLE = re.compile(r"webclient|downloadstring|downloadfile|invoke-expression|\biex\b|invoke-webrequest|"
                    r"bitsadmin|urlcache|start-bitstransfer", re.I)


def hidden_powershell(cand: Candidate) -> tuple[str, ...]:
    """Reasons, when a new process runs PowerShell with at least two of four delivery markers; else ()."""
    if cand.kind != "process":
        return ()
    p = cand.event.get("properties") or {}
    cmd = p.get("command_line") or ""
    if base(p.get("image_path")) != "powershell.exe" and "powershell" not in cmd.lower():
        return ()
    decoded = decode_ps(cmd) or ""
    padded = " " + cmd + " "
    markers = [name for name, hit in (("-EncodedCommand", bool(decoded) or bool(ENC_FLAG.search(padded))),
                                      ("hidden window", bool(HIDDEN.search(padded))),
                                      ("-NoProfile", bool(NOPROFILE.search(padded))),
                                      ("download cradle", bool(CRADLE.search(cmd + " " + decoded)))) if hit]
    if len(markers) < 2:
        return ()
    return ("PowerShell started by {}".format(base(p.get("parent_image_path")) or "an unknown parent"),) + tuple(markers)
