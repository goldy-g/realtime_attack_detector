"""3.5 The case: one triage candidate written out for the model, about 250 tokens.

Reading the case is about 95% of a decision's time (research 2.6), so the case
carries only what an analyst needs for this one event: the event, three levels
of ancestry, the decoded PowerShell command (never the raw base64), the baseline
facts, this process tree's recent activity and the machine's remote logons.
"""

from __future__ import annotations

import base64
import re

from .baseline import Candidate
from .config import LOGON_LINES_MAX, RECENT_S, TREE_LINES_MAX
from .state import MachineState, base, clip, hhmmss, show_path, user_text
from .state import line as event_line

ENC = re.compile(r"\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+([A-Za-z0-9+/=]{16,})", re.I)
PRIVATE = re.compile(r"^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fe80:|0\.0\.0\.0)")


def decode_ps(cmd: str | None) -> str | None:
    """The text of a PowerShell -EncodedCommand (base64 of UTF-16LE), if any."""
    m = ENC.search(" " + (cmd or "") + " ")
    if not m:
        return None
    blob = m.group(2).rstrip("=")
    blob = blob[: len(blob) // 4 * 4]                 # the sensor may cut long command lines mid-blob
    try:
        text = base64.b64decode(blob).decode("utf-16le", errors="replace")
    except Exception:  # noqa: BLE001 -- not base64 after all
        return None
    return " ".join(text.split())


def proc_line(state: MachineState, oid: str | None, fallback_image: str = "") -> str:
    proc = state.procs.get(oid or "")
    if proc is None or not proc.start_ts:
        image = (proc.image if proc else "") or fallback_image or "unknown"
        return "{} (running before the stream began)".format(image)
    return "{}, started {} as {}: {}".format(proc.image, hhmmss(proc.start_ts), user_text(proc.user),
                                             clip(show_path(proc.cmd), 110))


def tree_lines(state: MachineState, oids: list[str], skip: str, ref: float) -> list[str]:
    """Notable activity of these processes in the RECENT_S before `ref`, oldest first, without the case's own event."""
    lines = []
    for oid in oids:
        proc = state.procs.get(oid)
        if proc:
            lines += [(t, ln) for t, ln in proc.notable if ref - RECENT_S <= t <= ref and ln != skip]
    lines.sort()
    return [ln for _, ln in lines[-TREE_LINES_MAX:]]


def render(state: MachineState, cand: Candidate) -> str:
    """The case as of its own event: nothing that happened later, however long it waited in the queue."""
    ev = cand.event
    ref = cand.t
    p = ev.get("properties") or {}
    own = event_line(ev)
    out = ["Machine {} · {}".format(state.machine, ev["timestamp"][:19].replace("T", " "))]
    if cand.kind == "process":
        cmd = show_path(p.get("command_line"))
        decoded = decode_ps(cmd)
        out.append("New process: {} as {}".format(base(p.get("image_path")), user_text(p.get("user") or ev.get("principal"))))
        out.append("Command line: " + clip(cmd, 120 if decoded else 300))
        if decoded:
            out.append("Decoded -EncodedCommand: " + clip(decoded, 300))
        parent = state.procs.get(ev.get("actorID") or "")
        out.append("Parent: " + proc_line(state, ev.get("actorID"), base(p.get("parent_image_path"))))
        if parent and parent.parent:
            out.append("Grandparent: " + proc_line(state, parent.parent, parent.parent_image))
        written = state.written_before(p.get("image_path"), ref)
        if written:
            out.append("Its program file was written {:.0f} s earlier by {}.".format(max(0.0, cand.t - written[0]), written[1]))
        out.append("Baseline: {} → {} is new for this machine (not in its last hour); seen on {} of {} other machines.".format(
            cand.pair[0] or "?", cand.pair[1] or "?", cand.fleet, cand.fleet_of))
        activity = tree_lines(state, state.ancestry(ev.get("actorID"), 2), own, ref)
    else:
        dest = p.get("dest_ip") or ""
        out.append("Outbound connection: {} → {}:{} ({} address, protocol {})".format(
            base(p.get("image_path")), dest, p.get("dest_port"), "private" if PRIVATE.match(dest) else "public",
            {"6": "TCP", "17": "UDP"}.get(p.get("l4protocol") or "", p.get("l4protocol"))))
        out.append("Process: " + proc_line(state, ev.get("actorID"), base(p.get("image_path"))))
        proc = state.procs.get(ev.get("actorID") or "")
        if proc and proc.parent:
            out.append("Its parent: " + proc_line(state, proc.parent, proc.parent_image))
        if proc:
            written = state.written_before(proc.image_path, ref)
            if written and proc.start_ts:
                out.append("Its program file was written by {} shortly before it started.".format(written[1]))
        out.append("Baseline: {} has not used port {} in this machine's last hour; seen on {} of {} other machines.".format(
            cand.pair[0] or "?", cand.pair[1] or "?", cand.fleet, cand.fleet_of))
        activity = tree_lines(state, state.ancestry(ev.get("actorID"), 2), own, ref)
    if activity:
        out.append("Recent activity of these processes:")
        out += ["- " + a for a in activity]
    logons = state.recent_logons(ref)[-LOGON_LINES_MAX:]
    if logons:
        out.append("Remote logons on this machine (last 2 min):")
        out += ["- " + a for a in logons]
    return "\n".join(out)
