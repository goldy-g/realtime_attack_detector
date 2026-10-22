"""A llama-server process for one model, and chat calls with a JSON schema (stdlib only)."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.request

from common import ROOT

MODELS = os.path.join(ROOT, "models")
LOGS = os.path.join(ROOT, "data", "cache", "research", "server-logs")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    """llama-server for one GGUF. cpu=True keeps every layer on the CPU (no Metal, no BLAS device)."""

    def __init__(self, gguf: str, cpu: bool, threads: int = 8, ctx: int = 8192) -> None:
        self.gguf, self.port = gguf, free_port()
        os.makedirs(LOGS, exist_ok=True)
        self.log_path = os.path.join(LOGS, "{}-{}.log".format(os.path.basename(gguf), "cpu" if cpu else "gpu"))
        args = ["llama-server", "-m", os.path.join(MODELS, gguf), "--port", str(self.port), "--host", "127.0.0.1",
                "-c", str(ctx), "-t", str(threads), "-np", "1", "--jinja", "--no-webui"]
        # Thinking is switched off per request (chat_template_kwargs) and by the grammar, which must start
        # with "{". The server flag --reasoning-budget 0 is not used: with a grammar it breaks Granite 4.2.
        args += ["-ngl", "0", "--device", "none"] if cpu else ["-ngl", "99"]
        self.t0 = time.perf_counter()
        self.proc = subprocess.Popen(args, stdout=open(self.log_path, "w"), stderr=subprocess.STDOUT)
        self.load_s = None

    def wait(self, timeout: float = 600) -> float:
        while time.perf_counter() - self.t0 < timeout:
            if self.proc.poll() is not None:
                raise RuntimeError("llama-server exited, see " + self.log_path)
            try:
                with urllib.request.urlopen("http://127.0.0.1:{}/health".format(self.port), timeout=2) as r:
                    if r.status == 200:
                        self.load_s = time.perf_counter() - self.t0
                        return self.load_s
            except Exception:  # noqa: BLE001 -- still loading
                pass
            time.sleep(0.25)
        raise TimeoutError("llama-server did not become ready")

    def rss_mb(self) -> float:
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(self.proc.pid)], capture_output=True, text=True).stdout
        return int(out.strip() or 0) / 1024

    def chat(self, messages: list[dict], schema: dict | None = None, max_tokens: int = 96,
             grammar: str | None = None) -> dict:
        """One reply, constrained by a GBNF grammar (preferred) or a JSON schema."""
        body = {"messages": messages, "temperature": 0, "max_tokens": max_tokens, "cache_prompt": True,
                "chat_template_kwargs": {"enable_thinking": False, "thinking": False}}
        if grammar:
            body["grammar"] = grammar
        else:
            body["response_format"] = {"type": "json_schema", "json_schema": {"name": "verdict", "schema": schema}}
        req = urllib.request.Request("http://127.0.0.1:{}/v1/chat/completions".format(self.port),
                                     data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        t = time.perf_counter()
        with urllib.request.urlopen(req, timeout=600) as r:
            out = json.load(r)
        wall = time.perf_counter() - t
        text = out["choices"][0]["message"].get("content") or ""
        try:
            parsed = json.loads(text)
        except Exception:  # noqa: BLE001 -- counted as an invalid verdict
            parsed = None
        tim = out.get("timings") or {}
        return {"text": text, "parsed": parsed, "wall_s": wall, "prompt_n": tim.get("prompt_n"),
                "prompt_ms": tim.get("prompt_ms"), "predicted_n": tim.get("predicted_n"),
                "predicted_ms": tim.get("predicted_ms"), "cache_n": tim.get("cache_n"),
                "prompt_tokens": (out.get("usage") or {}).get("prompt_tokens")}

    def tokens(self, text: str) -> int:
        req = urllib.request.Request("http://127.0.0.1:{}/tokenize".format(self.port),
                                     data=json.dumps({"content": text}).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            return len(json.load(r)["tokens"])

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
