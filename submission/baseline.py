"""3.3 Baselines and 3.4 triage: which live events are new enough to show the model.

Two baselines:
- the machine's own warm-up hour: parent -> child process pairs and process ->
  destination-port pairs it already showed (no attack starts in the warm-up);
- the fleet: on how many training machines each pair occurs in benign activity,
  precomputed by tools/build_fleet_baseline.py into fleet_baseline.json.

Triage (rule V2 in research/triage_sim.py) makes a case of the first live
occurrence of a pair the machine has not shown. It keeps all 25 labelled alert
points at about one case a minute on a normal machine. Fleet rarity orders the
queue; it never removes a case (removing common pairs lost one alert point).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from .state import base

UDP = "17"
EPHEMERAL = 49152


def proc_key(ev: dict) -> tuple[str, str]:
    p = ev.get("properties") or {}
    return base(p.get("parent_image_path")), base(p.get("image_path"))


def flow_key(ev: dict) -> tuple[str, str] | None:
    p = ev.get("properties") or {}
    if p.get("direction") != "outbound":
        return None
    return base(p.get("image_path")), p.get("dest_port") or ""


def is_noise_flow(ev: dict) -> bool:
    """svchost.exe on ephemeral UDP ports: service traffic, new on every machine every hour (2.5)."""
    p = ev.get("properties") or {}
    port = p.get("dest_port") or ""
    return (base(p.get("image_path")) == "svchost.exe" and p.get("l4protocol") == UDP
            and port.isdigit() and int(port) >= EPHEMERAL)


class Fleet:
    """Benign pairs of the training machines, with the machines each occurs on."""

    def __init__(self, path: str | None) -> None:
        self.machines: list[str] = []
        self.pairs: dict[str, list[int]] = {}
        self.flows: dict[str, list[int]] = {}
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.machines, self.pairs, self.flows = data["machines"], data["pairs"], data["flows"]

    def count(self, table: dict, key: tuple[str, str], machine: str) -> int:
        """Other machines with this pair (the machine itself is left out, as for an unseen machine)."""
        idx = table.get("|".join(key), ())
        me = self.machines.index(machine) if machine in self.machines else -1
        return sum(1 for i in idx if i != me)

    def others(self, machine: str) -> int:
        return len(self.machines) - (1 if machine in self.machines else 0)


@dataclass
class Candidate:
    event: dict
    kind: str              # "process" or "flow"
    pair: tuple[str, str]
    fleet: int             # other machines that show the pair
    fleet_of: int          # out of how many
    t: float


class Triage:
    """Per machine: learns the warm-up, then turns new live pairs into candidates."""

    def __init__(self, machine: str, fleet: Fleet) -> None:
        self.machine, self.fleet = machine, fleet
        self.pairs: set[tuple[str, str]] = set()
        self.flows: set[tuple[str, str]] = set()
        self.live = False

    def observe(self, ev: dict, t: float) -> Candidate | None:
        kind = ev["object"] + " " + ev["action"]
        if kind == "PROCESS CREATE":
            key = proc_key(ev)
            if key in self.pairs:
                return None
            self.pairs.add(key)                     # only the first occurrence is new
            if not self.live:
                return None
            return Candidate(ev, "process", key, self.fleet.count(self.fleet.pairs, key, self.machine),
                             self.fleet.others(self.machine), t)
        if kind == "FLOW START":
            key = flow_key(ev)
            if key is None or key in self.flows:
                return None
            self.flows.add(key)
            if not self.live or is_noise_flow(ev):
                return None
            return Candidate(ev, "flow", key, self.fleet.count(self.fleet.flows, key, self.machine),
                             self.fleet.others(self.machine), t)
        return None
