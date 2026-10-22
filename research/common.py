"""Shared loaders for the research scripts: training days, eval and validation waves.

Events are streamed from the provided gzip JSONL files; nothing is cached here.
Scripts run from the repository root:

    .venv/bin/python research/<script>.py
"""

from __future__ import annotations

import gzip
import json
import os
import re
import sys
from concurrent.futures import ProcessPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAIN = os.path.join(ROOT, "data", "train")
EVAL = os.path.join(ROOT, "data", "eval")
VAL = os.path.join(ROOT, "data", "cache", "val")
EVAL_ANSWERS = os.path.join(ROOT, "data", "cache", "eval_answers.json")   # fixed copy, see tools/fix_eval_answers.py
OUT = os.path.join(ROOT, "research", "out")

sys.path.insert(0, os.path.join(ROOT, "evaluator"))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from metrics import parse_ts  # noqa: E402,F401  -- the scorer's own timestamp parsing
from build_val_set import split_of  # noqa: E402,F401  -- the dev / holdout split by machine

ID = re.compile(r'"id":"([^"]+)"')


def iter_events(path: str):
    """Events of one gzip JSONL stream, in file order."""
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            yield json.loads(line)


def machines() -> list[dict]:
    with open(os.path.join(TRAIN, "machines.jsonl"), encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


def day_events(machine: str) -> str:
    return os.path.join(TRAIN, machine + ".events.jsonl.stream")


def day_labels(machine: str) -> dict:
    with gzip.open(os.path.join(TRAIN, machine + ".labels.json.stream"), "rt", encoding="utf-8") as fh:
        return json.load(fh)


def waves(data_dir: str) -> list[dict]:
    with open(os.path.join(data_dir, "waves.json"), encoding="utf-8") as fh:
        return json.load(fh)["waves"]


def answers(data_dir: str) -> dict:
    path = EVAL_ANSWERS if os.path.abspath(data_dir) == os.path.abspath(EVAL) else os.path.join(data_dir, "answers.json")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)["waves"]


def wave_stream(data_dir: str, wave_id: str, part: str) -> list[dict]:
    """part = 'warmup' or 'live'."""
    return list(iter_events(os.path.join(data_dir, wave_id, part + ".stream")))


def kind(ev: dict) -> str:
    return ev["object"] + " " + ev["action"]


def props(ev: dict) -> dict:
    return ev.get("properties") or {}


def base(path: str | None) -> str:
    """Executable name from a path, lower-cased: '\\Device\\...\\WmiPrvSE.exe' -> 'wmiprvse.exe'."""
    if not path:
        return ""
    return re.split(r"[\\/]", path)[-1].lower()


def pmap(fn, items, workers: int = 12):
    """Map over items in worker processes, keeping order."""
    with ProcessPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(fn, items))


def save_json(name: str, obj) -> str:
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, ensure_ascii=False)
    return path


def save_text(name: str, text: str) -> str:
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path
