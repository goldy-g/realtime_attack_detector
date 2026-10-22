"""The model runtime: one llama-server subprocess on a free local port, called over HTTP (stdlib only).

Two slots, used one at a time: slot 0 for verdicts and slot 1 for explanations,
so each keeps its own system prompt in the prompt cache and an explanation never
evicts the cached verdict prompt.
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

VERDICT_SLOT, EXPLAIN_SLOT = 0, 1


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerError(RuntimeError):
    pass


class LlamaServer:
    def __init__(self, server: str, model: str, threads: int = config.THREADS,
                 ctx_per_slot: int = config.CTX_PER_SLOT) -> None:
        self.server, self.model, self.threads, self.ctx_per_slot = server, model, threads, ctx_per_slot
        self.port = 0
        self.proc: subprocess.Popen | None = None
        self.log_path = os.path.join(tempfile.gettempdir(), "detector-llama-server-{}.log".format(os.getpid()))
        self.load_s = 0.0

    @property
    def name(self) -> str:
        return os.path.basename(self.model)

    def start(self, timeout: float = config.SERVER_START_TIMEOUT_S) -> float:
        self.port = free_port()
        args = [self.server, "-m", self.model, "--host", "127.0.0.1", "--port", str(self.port),
                "-c", str(2 * self.ctx_per_slot), "-np", "2", "-t", str(self.threads), "-tb", str(self.threads),
                "-ngl", "0", "--device", "none",          # CPU only, as on the target
                "--jinja", "--no-webui"]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        t0 = time.perf_counter()
        self.proc = subprocess.Popen(args, stdout=open(self.log_path, "w"), stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, creationflags=flags)
        atexit.register(self.stop)
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
        proc, self.proc = self.proc, None
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
