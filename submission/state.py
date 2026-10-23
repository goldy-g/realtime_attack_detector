"""3.2 Intake and state: what the detector knows about one machine, updated per event in microseconds.

The process table is keyed by the sensor's process IDs: a PROCESS CREATE event's
`objectID` is the new process, and that ID is the `actorID` of everything the
process does afterwards. Processes that started before the stream began appear as
actors only; they get a stub entry with the image name the events carry.

Only what the case text and the evidence list need is kept, bounded per process,
so a long busy wave cannot grow memory without limit.
"""

from __future__ import annotations

import datetime as dt
import re
from collections import OrderedDict, deque
from dataclasses import dataclass, field

from .config import PER_PROCESS_EVENTS_MAX, RECENT_S

LOCAL_IPS = {None, "", "-", "::1", "127.0.0.1", "0.0.0.0"}
_DEVICE = re.compile(r"^\\device\\harddiskvolume\d+", re.I)
_FRAC = re.compile(r"\.(\d+)")
# Files whose later execution is worth noting in a case.
_RUNNABLE = (".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".scr", ".msi")
FILE_MEMORY = 5000
RDP_PORT = "3389"
SESSION_LINK_S = 10.0               # a desktop session's winlogon.exe starts within this long of the logon that opened it
RDP_LINK_S = 600.0                  # ... and that logon follows the inbound Remote Desktop connection by at most this
LOOPBACK = {"127.0.0.1", "::1"}      # a Remote Desktop logon from here came through a local tunnel (plink -R ...:3389)


def ts_seconds(ts: str) -> float:
    """ISO 8601 with any fraction length and an offset -> epoch seconds (Python 3.10 safe)."""
    s = ts.strip().replace("Z", "+00:00")
    m = _FRAC.search(s)
    if m:
        s = s[:m.start()] + "." + (m.group(1) + "000000")[:6] + s[m.end():]
    return dt.datetime.fromisoformat(s).timestamp()


def base(path: str | None) -> str:
    """Executable name from a path, lower-cased: '\\Device\\...\\WmiPrvSE.exe' -> 'wmiprvse.exe'."""
    if not path:
        return ""
    return re.split(r"[\\/]", path)[-1].lower()


def norm_path(path: str | None) -> str:
    """A comparable file path: device prefix and drive letter removed, lower-case."""
    p = _DEVICE.sub("", (path or "").strip().strip('"')).lower()
    return p[2:] if len(p) > 1 and p[1] == ":" else p


def show_path(text: str | None) -> str:
    """Paths as an analyst writes them: '\\Device\\HarddiskVolume1\\x' -> 'C:\\x'."""
    return re.sub(r"\\Device\\HarddiskVolume\d+", "C:", text or "", flags=re.I)


@dataclass
class Proc:
    oid: str
    image: str                          # executable name, lower-case
    image_path: str = ""
    cmd: str = ""
    user: str = ""
    start_ts: str = ""                  # empty when the start was not seen
    start_eid: str = ""
    parent: str | None = None           # parent's objectID
    parent_image: str = ""
    children: list[str] = field(default_factory=list)
    events: deque = field(default_factory=lambda: deque(maxlen=PER_PROCESS_EVENTS_MAX))   # (eid, t, kind)
    notable: deque = field(default_factory=lambda: deque(maxlen=24))                      # (t, line)
    session: dict | None = None         # winlogon.exe only: the Remote Desktop logon that opened its desktop session


class MachineState:
    """Everything known about the machine so far. Not thread-safe: the detector holds a lock around it."""

    def __init__(self, machine: str) -> None:
        self.machine = machine
        self.procs: dict[str, Proc] = {}
        self.logons: deque = deque()                     # (t, line) remote logons, last RECENT_S
        self.written: OrderedDict = OrderedDict()        # normalised path -> (t, writer image)
        self.rdp_in: OrderedDict = OrderedDict()         # source IP -> (t, ts) of its latest inbound Remote Desktop connection
        self.last_remote: tuple | None = None            # (t, ts, user, src_ip) of the latest remote logon
        self.last_tunnel: tuple | None = None            # (t, ts, user, src_ip) of the latest remote logon by a person from loopback
        self.now = 0.0                                   # stream time of the latest event

    # ------------------------------------------------------------------ intake
    def add(self, ev: dict) -> float:
        """Take in one event; returns its stream time in epoch seconds."""
        p = ev.get("properties") or {}
        kind = ev["object"] + " " + ev["action"]
        t = ts_seconds(ev["timestamp"])
        self.now = max(self.now, t)
        actor = ev.get("actorID")
        if kind == "PROCESS CREATE":
            child = self._proc(ev["objectID"], p.get("image_path"))
            child.image_path = p.get("image_path") or child.image_path
            child.image = base(child.image_path) or child.image
            child.cmd = p.get("command_line") or ""
            child.user = p.get("user") or ev.get("principal") or ""
            child.start_ts, child.start_eid = ev["timestamp"], ev["id"]
            child.parent, child.parent_image = actor, base(p.get("parent_image_path"))
            if child.image == "winlogon.exe":
                child.session = self._session_origin(t)
            child.events.append((ev["id"], t, kind))
            if actor:
                parent = self._proc(actor, p.get("parent_image_path"))
                parent.children.append(child.oid)
                parent.notable.append((t, line(ev)))
            return t
        if actor:
            proc = self._proc(actor, p.get("image_path"))
            proc.events.append((ev["id"], t, kind))
            if kind == "FLOW START" or kind == "SHELL COMMAND":
                proc.notable.append((t, line(ev)))
            elif kind in ("FILE CREATE", "FILE WRITE") and norm_path(p.get("file_path")).endswith(_RUNNABLE):
                path = norm_path(p.get("file_path"))
                if path not in self.written:
                    proc.notable.append((t, line(ev)))
                self.written[path] = (t, proc.image)
                self.written.move_to_end(path)
                if len(self.written) > FILE_MEMORY:
                    self.written.popitem(last=False)
        if kind == "FLOW START" and p.get("direction") == "inbound" and p.get("dest_port") == RDP_PORT \
                and p.get("src_ip") not in LOCAL_IPS:
            self.rdp_in[p["src_ip"]] = (t, ev["timestamp"])
            self.rdp_in.move_to_end(p["src_ip"])
            if len(self.rdp_in) > 64:
                self.rdp_in.popitem(last=False)
        if kind == "USER_SESSION REMOTE" and p.get("src_ip") not in LOCAL_IPS:
            self.logons.append((t, line(ev)))
            self.last_remote = (t, ev["timestamp"], p.get("user") or "", p["src_ip"])
        if kind == "USER_SESSION REMOTE" and p.get("src_ip") in LOOPBACK \
                and not (p.get("user") or "NT AUTHORITY").upper().startswith("NT AUTHORITY"):    # not the system's own logons
            self.last_tunnel = (t, ev["timestamp"], p.get("user") or "", p["src_ip"])
        while self.logons and self.logons[0][0] < t - 3 * RECENT_S:     # kept longer: a queued case looks back from its own time
            self.logons.popleft()
        return t

    def _session_origin(self, t: float) -> dict | None:
        """A new desktop session opened by a Remote Desktop logon moments before winlogon.exe: from an address
        that had just connected to this machine's port 3389, or, by a person rather than the system, from this
        machine itself, which only a local tunnel to port 3389 produces. Anything else stays unsaid."""
        if self.last_remote and 0 <= t - self.last_remote[0] <= SESSION_LINK_S:
            lt, lts, user, ip = self.last_remote
            rdp = self.rdp_in.get(ip)
            if rdp and 0 <= lt - rdp[0] <= RDP_LINK_S:
                return {"ts": lts, "user": user, "ip": ip, "rdp_ts": rdp[1]}
        if self.last_tunnel and 0 <= t - self.last_tunnel[0] <= SESSION_LINK_S:
            lt, lts, user, ip = self.last_tunnel
            return {"ts": lts, "user": user, "ip": ip, "rdp_ts": None, "tunnel": True}
        return None

    def _proc(self, oid: str, image_path: str | None) -> Proc:
        proc = self.procs.get(oid)
        if proc is None:
            proc = self.procs[oid] = Proc(oid=oid, image=base(image_path), image_path=image_path or "")
        elif not proc.image and image_path:
            proc.image, proc.image_path = base(image_path), image_path
        return proc

    # ------------------------------------------------------------------ queries
    def ancestry(self, oid: str | None, depth: int = 8) -> list[str]:
        """oid, its parent, grandparent, ... as far as the starts were seen."""
        out, seen = [], set()
        while oid and oid not in seen and len(out) < depth:
            seen.add(oid)
            out.append(oid)
            proc = self.procs.get(oid)
            oid = proc.parent if proc else None
        return out

    def subtree(self, oid: str, limit: int = 200) -> list[str]:
        """oid and its descendants, breadth first."""
        out, todo, seen = [], [oid], set()
        while todo and len(out) < limit:
            cur = todo.pop(0)
            if cur in seen:
                continue
            seen.add(cur)
            out.append(cur)
            proc = self.procs.get(cur)
            if proc:
                todo.extend(proc.children)
        return out

    def session_of(self, oid: str | None) -> dict | None:
        """The Remote Desktop logon that opened this process's desktop session (ts, user, ip, rdp_ts),
        if the session began that way while we watched; else None."""
        for a in self.ancestry(oid, 16):
            proc = self.procs.get(a)
            if proc and proc.image == "winlogon.exe":
                return proc.session
        return None

    def recent_logons(self, ref: float) -> list[str]:
        """Remote logons in the RECENT_S before stream time `ref`."""
        return [ln for t, ln in self.logons if ref - RECENT_S <= t <= ref]

    def written_before(self, image_path: str | None, ref: float) -> tuple[float, str] | None:
        """When and by whom the file of this image was created or written before stream time `ref`, if seen."""
        hit = self.written.get(norm_path(image_path))
        return hit if hit and hit[0] <= ref else None


def hhmmss(ts: str) -> str:
    return ts[11:19]


def clip(s: str | None, n: int) -> str:
    s = (s or "").replace("\r", " ").replace("\n", " ")
    return s if len(s) <= n else s[:n] + "…"


def user_text(user: str | None) -> str:
    """'SYSTEMIACOM\\Administrator' -> 'Administrator (domain SYSTEMIACOM)'. A domain is not the SYSTEM account."""
    user = user or "unknown"
    if "\\" in user:
        dom, name = user.split("\\", 1)
        if dom.upper() == "NT AUTHORITY":
            return name
        return "{} (domain {})".format(name, dom)
    return user


def line(ev: dict) -> str:
    """One readable line for an event in a case."""
    p = ev.get("properties") or {}
    kind = ev["object"] + " " + ev["action"]
    t = hhmmss(ev["timestamp"])
    if kind == "PROCESS CREATE":
        return "{} {} started {}: {}".format(t, base(p.get("parent_image_path")) or "?", base(p.get("image_path")),
                                             clip(show_path(p.get("command_line")), 110))
    if kind == "FLOW START":
        out = p.get("direction") == "outbound"
        return "{} {} {} {}:{}".format(t, base(p.get("image_path")), "connected to" if out else "accepted from",
                                       p.get("dest_ip") if out else p.get("src_ip"),
                                       p.get("dest_port") if out else p.get("src_port"))
    if kind == "SHELL COMMAND":
        return "{} PowerShell ran: {}".format(t, clip(p.get("payload"), 100))
    if kind.startswith("FILE"):
        return "{} {} wrote {}".format(t, base(p.get("image_path")), clip(show_path(p.get("file_path")), 90))
    if kind == "USER_SESSION REMOTE":
        return "{} network logon by {} from {}".format(t, user_text(p.get("user")), p.get("src_ip"))
    return "{} {}".format(t, kind.lower())
