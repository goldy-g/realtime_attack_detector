"""Every tunable of the detector in one place, each overridable by an environment variable.

Defaults are the values chosen in research (research/FINDINGS.md) and the approved
decisions: Gemma 4 E4B on llama.cpp's llama-server, CPU only, 4K context per slot.
"""

from __future__ import annotations

import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _env(name: str, default):
    raw = os.environ.get("DETECTOR_" + name)
    if raw is None:
        return default
    return type(default)(raw) if default is not None else raw


# --- model and runtime -------------------------------------------------------------------------
MODEL_FILE = _env("MODEL", "gemma-4-E4B_q4_0-it.gguf")
FALLBACK_MODEL_FILE = _env("FALLBACK_MODEL", "gemma-4-E2B_q4_0-it.gguf")
MODEL_DIRS = [d for d in (_env("MODEL_DIR", ""), os.path.join(HERE, "models"), os.path.join(ROOT, "models")) if d]
SERVER_NAMES = ("llama-server.exe", "llama-server") if sys.platform == "win32" else ("llama-server",)
SERVER_DIRS = [d for d in (_env("SERVER_DIR", ""), os.path.join(HERE, "bin"), os.path.join(HERE, "bin", "llama")) if d]
THREADS = _env("THREADS", min(8, os.cpu_count() or 8))      # the target has 8 cores; one model call at a time
SLOTS = 3                                                    # verdicts, explanations, Remote Desktop verdicts: own caches
CTX_PER_SLOT = _env("CTX_PER_SLOT", 8192 // SLOTS)           # 8,192 tokens in all, the assignment's limit, 2,730 each;
                                                             # a worst-case explanation with its reply needs 2,190
SERVER_START_TIMEOUT_S = _env("SERVER_START_TIMEOUT_S", 300.0)
CALL_TIMEOUT_S = _env("CALL_TIMEOUT_S", 120.0)

# --- start-up calibration (3.8) -----------------------------------------------------------------
# If the main model's verdict call is slower than this on this machine, switch to the fallback.
MAX_VERDICT_S = _env("MAX_VERDICT_S", 4.0)

# --- triage and queue (3.4) ---------------------------------------------------------------------
FLEET_FILE = os.path.join(HERE, "fleet_baseline.json")
QUEUE_MAX = _env("QUEUE_MAX", 40)                # beyond this, the most common pending cases are shed

# --- decisions (3.6) ----------------------------------------------------------------------------
ALERT_MIN_CONFIDENCE = _env("ALERT_MIN_CONFIDENCE", 50)
# v1.6: an outbound Remote Desktop connection from mstsc.exe is judged under the Remote Desktop specialist
# prompt (prompts.RDP_SYSTEM) in its own slot, only while the main model runs: the fallback E2B caught one
# of three hops under it and called a scripted connection an attack (research/out/specialist_rdp.md).
RDP_SPECIALIST = _env("RDP_SPECIALIST", 1) == 1
# Solution 2 (research/DETECTION_APPROACH.md, "Two solutions"), off in the submission, where every
# alert comes from an SLM verdict. On (DETECTOR_EXPERT_RAISES=1), a case an expert recognises
# (experts.py) raises its alert at once, with no model verdict; the SLM still writes the explanation.
EXPERT_RAISES = _env("EXPERT_RAISES", 0) == 1

# --- explanations (3.7) -------------------------------------------------------------------------
EXPLAIN = _env("EXPLAIN", 1) == 1
EXPLAIN_MAX_TOKENS = _env("EXPLAIN_MAX_TOKENS", 260)
EVIDENCE_MAX = _env("EVIDENCE_MAX", 40)

# --- case rendering (3.5) -----------------------------------------------------------------------
RECENT_S = 120.0                 # how far back the case looks
TREE_LINES_MAX = 6               # activity lines from the process tree
LOGON_LINES_MAX = 3              # remote logons on the machine, the usual prelude to remote execution
PER_PROCESS_EVENTS_MAX = 400     # kept per process for evidence; older ones drop off

LOG_FILE = _env("LOG", "")       # set to a path to keep the detector's own log
DECISIONS_FILE = _env("DECISIONS", "")   # set to a path to log every model decision as JSON lines (for analysis)


def find_model(name: str) -> str | None:
    for d in MODEL_DIRS:
        path = os.path.join(d, name)
        if os.path.isfile(path):
            return path
    return None


def find_server() -> str | None:
    explicit = _env("SERVER", "")
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for d in SERVER_DIRS:
        for name in SERVER_NAMES:
            path = os.path.join(d, name)
            if os.path.isfile(path):
                return path
    return shutil.which("llama-server")
