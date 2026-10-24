"""The model runtime: one llama-server subprocess on a free local port, called over HTTP (stdlib only).

Three slots, used one at a time: slot 0 for verdicts, slot 1 for explanations and
slot 2 for Remote Desktop verdicts (the specialist prompt), so each keeps its own
system prompt in the prompt cache and no call evicts another's cached prompt.
"""

from __future__ import annotations

import atexit
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

from . import config

VERDICT_SLOT, EXPLAIN_SLOT, RDP_SLOT = 0, 1, 2


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerError(RuntimeError):
    pass


def _die_with_this_process(proc: subprocess.Popen):
    """Windows: put the server in a job object that is killed when this process ends, however it ends.

    Without it a llama-server outlives a killed or crashed Python on Windows (seen on the test
    laptop: 2.5 GB left running). Returns the job handle, which must stay open; None elsewhere
    or if Windows refuses, in which case stop() is the only cleanup.
    """
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class IoCounters(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in ("read_ops", "write_ops", "other_ops",
                                                           "read_bytes", "write_bytes", "other_bytes")]

        class BasicLimits(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BasicLimits), ("IoInfo", IoCounters),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        k32.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
        k32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        job = k32.CreateJobObjectW(None, None)
        if not job:
            return None
        info = ExtendedLimits()
        info.BasicLimitInformation.LimitFlags = 0x2000          # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if (k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))   # extended limits
                and k32.AssignProcessToJobObject(job, int(proc._handle))):
            return job
        k32.CloseHandle(job)
    except Exception:  # noqa: BLE001 -- best effort; stop() still cleans up on a normal exit
        pass
    return None


class LlamaServer:
    def __init__(self, server: str, model: str, threads: int = config.THREADS,
                 ctx_per_slot: int = config.CTX_PER_SLOT) -> None:
        self.server, self.model, self.threads, self.ctx_per_slot = server, model, threads, ctx_per_slot
        self.port = 0
        self.proc: subprocess.Popen | None = None
        # one log per detector process, appended to: a restart or the fallback switch must not erase a crash
        self.log_path = os.path.join(tempfile.gettempdir(), "detector-llama-server-{}.log".format(os.getpid()))
        self.load_s = 0.0
        self.stopping = False       # set by stop(): no restart after it, even if a call fails during exit
        self._log = None
        self._job = None
        self._atexit = False

    @property
    def name(self) -> str:
        return os.path.basename(self.model)

    def start(self, timeout: float = config.SERVER_START_TIMEOUT_S) -> float:
        if self.stopping:
            raise ServerError("llama-server was stopped; not starting it again")
        self.port = free_port()
        args = [self.server, "-m", self.model, "--host", "127.0.0.1", "--port", str(self.port),
                "-c", str(config.SLOTS * self.ctx_per_slot), "-np", str(config.SLOTS),
                "-t", str(self.threads), "-tb", str(self.threads),
                "-ngl", "0", "--device", "none",          # CPU only, as on the target
                "--jinja", "--no-webui"]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        self._close_log()
        self._log = open(self.log_path, "a", encoding="utf-8")
        self._log.write("\n=== {} starting {} on port {}\n".format(time.strftime("%Y-%m-%d %H:%M:%S"), self.name, self.port))
        self._log.flush()
        t0 = time.perf_counter()
        self.proc = subprocess.Popen(args, stdout=self._log, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, creationflags=flags)
        self._job = _die_with_this_process(self.proc)
        if not self._atexit:
            atexit.register(self.stop)
            self._atexit = True
        while time.perf_counter() - t0 < timeout:
            if self.proc.poll() is not None:
                raise ServerError("llama-server exited with code {}; log: {}".format(self.proc.returncode, self.log_path))
            try:
                with urllib.request.urlopen("http://127.0.0.1:{}/health".format(self.port), timeout=2) as r:
                    if r.status == 200:
                        self.load_s = time.perf_counter() - t0
                        return self.load_s
            except Exception:  # noqa: BLE001 -- still loading
                pass
            time.sleep(0.2)
        self.stop()
        raise ServerError("llama-server not ready after {:.0f} s; log: {}".format(timeout, self.log_path))

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def chat(self, messages: list[dict], max_tokens: int, slot: int, grammar: str | None = None,
             timeout: float = config.CALL_TIMEOUT_S) -> dict:
        body = {"messages": messages, "temperature": 0, "max_tokens": max_tokens, "cache_prompt": True,
                "id_slot": slot, "chat_template_kwargs": {"enable_thinking": False, "thinking": False}}
        if grammar:
            body["grammar"] = grammar
        req = urllib.request.Request("http://127.0.0.1:{}/v1/chat/completions".format(self.port),
                                     data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        t = time.perf_counter()
        with urllib.request.urlopen(req, timeout=timeout) as r:
            out = json.load(r)
        tim = out.get("timings") or {}
        return {"text": out["choices"][0]["message"].get("content") or "", "wall_s": time.perf_counter() - t,
                "prompt_n": tim.get("prompt_n"), "cache_n": tim.get("cache_n"), "predicted_n": tim.get("predicted_n")}

    def stop(self) -> None:
        self.stopping = True
        proc, self.proc = self.proc, None
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        self._close_log()

    def _close_log(self) -> None:
        log_file, self._log = self._log, None
        if log_file is not None:
            log_file.close()
