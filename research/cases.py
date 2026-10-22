"""2.6 + 2.7 Case format v0 and the labelled case set for offline model scoring.

A *case* is what the model would judge: one triage candidate (rule V2 in
triage_sim.py: a new parent -> child pair, or a new process -> port outbound
connection, against the warm-up hour) rendered as plain text with its process
ancestry, recent activity on the machine and baseline facts. Each case uses
only events delivered up to that moment, never later ones.

Sources
  wave    the 62 validation waves and the 7 eval waves (eval kept apart as a test)
  window  extra one-hour-warm-up + five-minute windows sampled from every training
          day, for more realistic negatives (and some late-stage attack positives)

Labels come from the answer keys: malicious (with its attack and the malicious
events delivered so far, the evidence an explanation should cite), context,
excused or benign. Splits follow the machine split of the validation set.

Writes data/cache/research/cases.jsonl and research/out/cases.md (stats + examples).
"""

from __future__ import annotations

import base64
import bisect
import gzip
import json
import os
import random
import re
import statistics
from collections import Counter, deque

from common import (EVAL, ROOT, VAL, answers, base, day_events, day_labels, machines, parse_ts, pmap, props,
                    save_text, split_of, wave_stream, waves)
from triage_sim import flow_key, proc_key

CACHE = os.path.join(ROOT, "data", "cache", "research")
WARMUP_S, WINDOW_S, WINDOWS_PER_DAY = 3600.0, 300.0, 6
RECENT_S, RECENT_MAX = 120.0, 8
ENC = re.compile(r"\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+([A-Za-z0-9+/=]{16,})", re.I)
PRIVATE = re.compile(r"^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fe80:|0\.0\.0\.0)")


def decode_ps(cmd: str) -> str | None:
    """The text of a PowerShell -EncodedCommand (base64 of UTF-16LE), if any."""
    m = ENC.search(" " + cmd + " ")
    if not m:
        return None
    blob = m.group(2).rstrip("=")
    blob = blob[: len(blob) // 4 * 4]                 # the sensor may cut long command lines mid-blob
    try:
        return base64.b64decode(blob).decode("utf-16le", errors="replace")
    except Exception:  # noqa: BLE001 -- not base64 after all
        return None


def clip(s: str | None, n: int) -> str:
    s = (s or "").replace("\r", " ").replace("\n", " ")
    return s if len(s) <= n else s[:n] + " …[+{} chars]".format(len(s) - n)


def hhmmss(ts: str) -> str:
    return ts[11:19]


class Replay:
    """What a detector knows at each moment: processes started so far and recent notable events."""

    def __init__(self) -> None:
        self.procs: dict[str, dict] = {}          # objectID of PROCESS CREATE -> event
        self.recent: deque = deque()              # (t, line, actor, object)

    def add(self, ev: dict) -> None:
        k = ev["object"] + " " + ev["action"]
        t = parse_ts(ev["timestamp"])
        if k == "PROCESS CREATE":
            self.procs[ev["objectID"]] = ev
        if ev["object"] in ("USER_SESSION",) or k in ("PROCESS CREATE", "FLOW START"):
            self.recent.append((t, self.line(ev), ev.get("actorID"), ev.get("objectID")))
        while self.recent and self.recent[0][0] < t - RECENT_S:
            self.recent.popleft()

    def proc_line(self, oid: str | None, fallback_image: str | None = None) -> str:
        ev = self.procs.get(oid or "")
        if not ev:
            return "{} (start not seen)".format(base(fallback_image) or "unknown")
        p = props(ev)
        return "{} started {} as {}: {}".format(base(p.get("image_path")), hhmmss(ev["timestamp"]),
                                              p.get("user") or ev.get("principal"), clip(p.get("command_line"), 220))

    @staticmethod
    def line(ev: dict) -> str:
        p = props(ev)
        k = ev["object"] + " " + ev["action"]
        if k == "PROCESS CREATE":
            return "{} {} ← {} : {}".format(hhmmss(ev["timestamp"]), base(p.get("image_path")),
                                           base(p.get("parent_image_path")), clip(p.get("command_line"), 120))
        if k == "FLOW START":
            return "{} {} {} {}:{} ({})".format(hhmmss(ev["timestamp"]), base(p.get("image_path")),
                                                "→" if p.get("direction") == "outbound" else "←",
                                                p.get("dest_ip") if p.get("direction") == "outbound" else p.get("src_ip"),
                                                p.get("dest_port") if p.get("direction") == "outbound" else p.get("src_port"),
                                                p.get("direction"))
        return "{} logon {} {} from {}".format(hhmmss(ev["timestamp"]), ev["action"].lower(), p.get("user") or "",
                                               p.get("src_ip") or "local")

    def render(self, ev: dict, machine: str, fleet: int, n_other: int) -> str:
        p = props(ev)
        lines = ["Machine {} · {}".format(machine, ev["timestamp"][:19].replace("T", " "))]
        if ev["object"] == "PROCESS":
            cmd = p.get("command_line") or ""
            decoded = decode_ps(cmd)
            lines += ["New process: {} as {}".format(base(p.get("image_path")), p.get("user") or ev.get("principal")),
                      "Command line: " + clip(cmd, 160 if decoded else 600)]
            if decoded:                                  # the raw base64 is unreadable; show its text instead
                lines.append("Decoded -EncodedCommand: " + clip(decoded, 500))
            parent = self.procs.get(ev["actorID"])
            lines.append("Parent: " + self.proc_line(ev["actorID"], p.get("parent_image_path")))
            if parent:
                lines.append("Grandparent: " + self.proc_line(parent["actorID"], props(parent).get("parent_image_path")))
            lines.append("Baseline: parent → child pair {} → {} not seen in this machine's last hour; "
                         "seen on {} of {} other machines.".format(base(p.get("parent_image_path")),
                                                                     base(p.get("image_path")), fleet, n_other))
        else:
            dest = p.get("dest_ip") or ""
            lines += ["Outbound connection: {} → {}:{} ({} address, protocol {})".format(
                          base(p.get("image_path")), dest, p.get("dest_port"),
                          "private" if PRIVATE.match(dest) else "public", p.get("l4protocol")),
                      "Process: " + self.proc_line(ev["actorID"], p.get("image_path"))]
            proc = self.procs.get(ev["actorID"])
            if proc:
                lines.append("Its parent: " + self.proc_line(proc["actorID"], props(proc).get("parent_image_path")))
            lines.append("Baseline: {} never used port {} in this machine's last hour; "
                         "seen on {} of {} other machines.".format(base(p.get("image_path")), p.get("dest_port"), fleet, n_other))
        recent = [r for r in self.recent if r[1] != self.line(ev)][-RECENT_MAX:]
        if recent:
            lines.append("Recent activity on this machine (last 2 min):")
            lines += ["- " + r[1] for r in recent]
        return "\n".join(lines)


def make_cases(source: str, split: str, machine: str, wave_id: str, warm: list[dict], live: list[dict],
               label: dict, pair_m: dict, flow_m: dict) -> list[dict]:
    rep = Replay()
    seen_pairs, seen_flows = set(), set()
    for ev in warm:
        rep.add(ev)
        if ev["object"] == "PROCESS" and ev["action"] == "CREATE":
            seen_pairs.add(proc_key(ev))
        elif ev["object"] == "FLOW":
            k = flow_key(ev)
            if k:
                seen_flows.add(k)
    mal, ctx = label["mal"], label["ctx"]
    delivered_mal: dict[str, list[str]] = {}
    out = []
    n_other = len({m for v in pair_m.values() for m in v} - {machine})
    for ev in live:
        rep.add(ev)
        eid = ev["id"]
        aid = label["event_attack"].get(eid)
        if eid in mal and aid:
            delivered_mal.setdefault(aid, []).append(eid)
        cand = None
        if ev["object"] == "PROCESS" and ev["action"] == "CREATE":
            k = proc_key(ev)
            if k not in seen_pairs:
                seen_pairs.add(k)
                cand = ("process", len(pair_m.get(k, set()) - {machine}))
        elif ev["object"] == "FLOW":
            k = flow_key(ev)
            if k and k not in seen_flows:
                seen_flows.add(k)
                cand = ("flow", len(flow_m.get(k, set()) - {machine}))
        if not cand:
            continue
        chain = label["event_chain"].get(eid)
        lab = ("malicious" if eid in mal else "context" if eid in ctx else
               "excused" if (chain is not None and chain in label["exc"]) or (chain is None and ev.get("actorID") in label["exa"])
               else "benign")
        text = rep.render(ev, machine, cand[1], n_other)
        out.append({"case_id": "{}:{}".format(wave_id, eid), "source": source, "split": split, "machine": machine,
                    "wave": wave_id, "event_id": eid, "ts": ev["timestamp"], "kind": cand[0], "fleet": cand[1],
                    "label": lab, "attack_id": aid if lab in ("malicious", "context") else None,
                    "is_alert_point": eid in label["alert_points"],
                    "evidence": list(delivered_mal.get(aid, [])) if lab == "malicious" else [],
                    "text": text, "chars": len(text)})
    return out


def wave_label(a: dict) -> dict:
    return {"mal": set(a["malicious_event_ids"]), "ctx": set(a.get("context_event_ids") or []),
            "event_attack": a.get("event_attack") or {}, "event_chain": a.get("event_chain") or {},
            "exc": set(a.get("excused_chains") or []), "exa": set(a.get("excused_actors") or []),
            "alert_points": {x["first_alertable_event_id"] for x in a.get("attacks") or []}}


def day_windows(task) -> list[dict]:
    row, pair_m, flow_m = task
    machine = row["machine"]
    labels = day_labels(machine)
    lab = wave_label({**labels, "event_attack": labels.get("event_attack") or {}})
    with gzip.open(day_events(machine), "rt", encoding="utf-8") as fh:
        events = [json.loads(line) for line in fh]
    times = [parse_ts(e["timestamp"]) for e in events]
    rng = random.Random("windows:" + machine)
    lo, hi = times[0] + WARMUP_S, times[-1] - WINDOW_S
    out = []
    for n in range(WINDOWS_PER_DAY):
        start = rng.uniform(lo, hi)
        i0, i1, i2 = (bisect.bisect_left(times, start - WARMUP_S), bisect.bisect_left(times, start),
                      bisect.bisect_left(times, start + WINDOW_S))
        warm, live = events[i0:i1], events[i1:i2]
        if any(e["id"] in lab["mal"] or e["id"] in lab["ctx"] for e in warm):
            continue                                       # an attack already running: not a clean warm-up
        out += make_cases("window", split_of(machine), machine, "win-{}-{}".format(machine[5:], n),
                          warm, live, lab, pair_m, flow_m)
    return out


def probe_windows(task) -> list[dict]:
    """Attacks with no validation wave (an earlier attack was still running in their warm-up hour): one window each."""
    machine, attack_ids, pair_m, flow_m = task
    labels = day_labels(machine)
    lab = wave_label({**labels, "event_attack": labels.get("event_attack") or {}})
    with gzip.open(day_events(machine), "rt", encoding="utf-8") as fh:
        events = [json.loads(line) for line in fh]
    times = [parse_ts(e["timestamp"]) for e in events]
    from build_val_set import first_attack_ts
    out = []
    for atk in labels.get("attacks") or []:
        if atk["attack_id"] not in attack_ids:
            continue
        start = first_attack_ts(atk) - 30
        end = parse_ts(atk["alert_from"]) + 120
        i0, i1, i2 = (bisect.bisect_left(times, start - WARMUP_S), bisect.bisect_left(times, start),
                      bisect.bisect_right(times, end))
        out += make_cases("probe", split_of(machine), machine, "probe-{}".format(atk["attack_id"]),
                          events[i0:i1], events[i1:i2], lab, pair_m, flow_m)
    return out


def main() -> None:
    from triage_sim import fleet_counts
    pair_m, flow_m, _, _ = fleet_counts()
    cases = []
    for data_dir in (VAL, EVAL):
        ans = answers(data_dir)
        for w in waves(data_dir):
            split = split_of(w["machine"]) if data_dir == VAL else "eval"
            cases += make_cases("wave", split, w["machine"], w["wave_id"], wave_stream(data_dir, w["wave_id"], "warmup"),
                                wave_stream(data_dir, w["wave_id"], "live"), wave_label(ans[w["wave_id"]]), pair_m, flow_m)
    for day in pmap(day_windows, [(m, pair_m, flow_m) for m in machines()], workers=10):
        cases += day
    in_val = {w.get("source_attack") for w in waves(VAL)}
    missing = {}
    for m in machines():
        for atk in day_labels(m["machine"]).get("attacks") or [] if m["attacked"] else []:
            if atk["attack_id"] not in in_val:
                missing.setdefault(m["machine"], set()).add(atk["attack_id"])
    for day in pmap(probe_windows, [(m, ids, pair_m, flow_m) for m, ids in missing.items()], workers=4):
        cases += day
    os.makedirs(CACHE, exist_ok=True)
    with open(os.path.join(CACHE, "cases.jsonl"), "w", encoding="utf-8") as fh:
        for c in cases:
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")

    by = Counter((c["split"], c["source"], c["label"]) for c in cases)
    chars = [c["chars"] for c in cases]
    lines = ["# Case set (2.6, 2.7)", "",
             "{} cases. Characters per case: median {}, p95 {}, max {} (≈ tokens at 3.5 chars/token: {}, {}, {}).".format(
                 len(cases), int(statistics.median(chars)), sorted(chars)[int(0.95 * len(chars))], max(chars),
                 int(statistics.median(chars) / 3.5), int(sorted(chars)[int(0.95 * len(chars))] / 3.5), int(max(chars) / 3.5)),
             "", "| Split | Source | Malicious | Context | Excused | Benign | Alert points |", "|---|---|---|---|---|---|---|"]
    for split in ("dev", "holdout", "eval"):
        for source in ("wave", "window", "probe"):
            n = lambda lab: by.get((split, source, lab), 0)  # noqa: E731
            if sum(n(x) for x in ("malicious", "context", "excused", "benign")):
                lines.append("| {} | {} | {} | {} | {} | {} | {} |".format(
                    split, source, n("malicious"), n("context"), n("excused"), n("benign"),
                    sum(1 for c in cases if c["split"] == split and c["source"] == source and c["is_alert_point"])))
    lines += ["", "## Examples", ""]
    for pick in (lambda c: c["is_alert_point"] and c["kind"] == "process",
                 lambda c: c["is_alert_point"] and c["kind"] == "flow",
                 lambda c: c["label"] == "benign" and c["fleet"] == 0 and c["kind"] == "process",
                 lambda c: c["label"] == "benign" and c["kind"] == "flow" and c["fleet"] == 0):
        ex = next((c for c in cases if pick(c)), None)
        if ex:
            lines += ["`{}` · {} · {}".format(ex["case_id"], ex["label"], ex["kind"]), "", "```", ex["text"], "```", ""]
    save_text("cases.md", "\n".join(lines) + "\n")
    print("\n".join(lines[:16]))


if __name__ == "__main__":
    main()
