"""SQ-1 experts: a router hands each triage case to an expert for a behaviour it knows.

An expert *claims* a case when the case is inside its behaviour (WMI started a
process, an Office program started a process, ...) and then gives its own
verdict with the reasons behind it. Cases no expert claims go to the SLM only.

The experts read the case as the detector renders it (research/cases.py), so the
offline numbers use exactly what the SLM saw. In the detector they would read the
same fields from the process table instead of from text.

`SOURCES` records which attack types each rule was written from. The
leave-one-attack-type-out test uses it: an expert written only from type T does
not exist when T is held out.
"""

from __future__ import annotations

import math
import re

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe",
          "visio.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe"}
LOLBINS = {"wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
           "msbuild.exe", "installutil.exe"}
RECON = {"whoami.exe", "net.exe", "net1.exe", "nltest.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe",
         "netstat.exe", "quser.exe", "arp.exe", "route.exe", "nslookup.exe"}
BROWSERS = {"firefox.exe", "chrome.exe", "msedge.exe", "iexplore.exe"}
UPDATER = re.compile(r"^(gup|.*update.*|.*updater.*)\.exe$")
USER_DIR = re.compile(r"\\(temp|tmp|downloads)\\|\\appdata\\local\\temp\\|\\users\\public\\", re.I)
ENC_FLAG = re.compile(r"\s-e(c|n|nc|nco|ncod|ncode|ncoded|ncodedcommand)?\s", re.I)
HIDDEN = re.compile(r"\s-w(indowstyle|in|i)?\s+(hidden|1)\b", re.I)
NOPROFILE = re.compile(r"\s-nop(rofile)?\b", re.I)
CRADLE = re.compile(r"webclient|downloadstring|downloadfile|invoke-expression|\biex\b|invoke-webrequest|"
                    r"bitsadmin|urlcache|start-bitstransfer", re.I)
B64 = re.compile(r"[A-Za-z0-9+/=]{80,}")
PROC_LINE = re.compile(r"^(?P<img>\S+?)(?: started (?P<t>\S+) as (?P<user>.*?): (?P<cmd>.*)| \(start not seen\))$")


def _proc(s: str) -> dict:
    m = PROC_LINE.match(s.strip())
    if not m:
        return {"img": s.split(" ")[0].lower(), "cmd": "", "user": "", "seen": False}
    return {"img": m.group("img").lower(), "cmd": m.group("cmd") or "", "user": m.group("user") or "",
            "seen": m.group("t") is not None}


def parse(case: dict) -> dict:
    """The fields of a rendered case: the event, its ancestry, the baseline and recent activity."""
    f = {"kind": case["kind"], "fleet": case["fleet"], "image": "", "user": "", "cmd": "", "decoded": "",
         "parent": {}, "grand": {}, "dest": "", "port": None, "public": False, "proto": "", "recent": 0}
    for line in case["text"].split("\n"):
        if line.startswith("New process: "):
            img, _, user = line[len("New process: "):].partition(" as ")
            f["image"], f["user"] = img.lower(), user
        elif line.startswith("Command line: "):
            f["cmd"] = line[len("Command line: "):]
        elif line.startswith("Decoded -EncodedCommand: "):
            f["decoded"] = line[len("Decoded -EncodedCommand: "):]
        elif line.startswith("Parent: ") or line.startswith("Its parent: "):
            f["parent"] = _proc(line.split(": ", 1)[1])
        elif line.startswith("Grandparent: "):
            f["grand"] = _proc(line[len("Grandparent: "):])
        elif line.startswith("Process: "):
            p = _proc(line[len("Process: "):])
            f["user"], f["cmd"] = p["user"], p["cmd"]
        elif line.startswith("Outbound connection: "):
            m = re.match(r"Outbound connection: (\S+) → (\S*):(\S+) \((public|private) address, protocol (\S+)\)", line)
            if m:
                f["image"], f["dest"], f["public"], f["proto"] = m.group(1).lower(), m.group(2), m.group(4) == "public", m.group(5)
                f["port"] = int(m.group(3)) if m.group(3).isdigit() else None
        elif line.startswith("- "):
            f["recent"] += 1
    return f


def flags(f: dict) -> dict:
    """Named facts about a case. Experts, the trained models and the evidence lists share them."""
    cmd = " " + f["cmd"] + " "
    parent = f["parent"].get("img", "")
    child = f["image"]
    ps_text = cmd if ("powershell" in cmd.lower() or child == "powershell.exe") else ""
    return {
        "is_flow": f["kind"] == "flow",
        "fleet0": f["fleet"] == 0,
        "fleet_log": math.log1p(f["fleet"]),
        "parent_wmi": parent == "wmiprvse.exe",
        "parent_office": parent in OFFICE,
        "parent_shell": parent in SHELLS,
        "parent_browser": parent in BROWSERS,
        "parent_explorer": parent == "explorer.exe",
        "parent_services": parent in ("svchost.exe", "services.exe"),
        "parent_updater": bool(UPDATER.match(parent)) and not f["kind"] == "flow",
        "parent_unseen": bool(f["parent"]) and not f["parent"].get("seen"),
        "child_shell": child in SHELLS,
        "child_lolbin": child in LOLBINS,
        "child_recon": child in RECON,
        "child_powershell": child == "powershell.exe" or "powershell" in cmd.lower(),
        "ps_encoded": bool(f["decoded"]) or bool(ps_text and ENC_FLAG.search(ps_text)),
        "ps_hidden": bool(ps_text and HIDDEN.search(ps_text)),
        "ps_noprofile": bool(ps_text and NOPROFILE.search(ps_text)),
        "cradle": bool(CRADLE.search(cmd + " " + f["decoded"])),
        "long_b64": bool(B64.search(cmd)),
        "user_dir": bool(USER_DIR.search(cmd)),
        "user_system": f["user"].upper().startswith("NT AUTHORITY"),
        "user_admin": "administrator" in f["user"].lower(),
        "dest_public": f["public"],
        "port_web": f["port"] in (80, 443),
        "port_high": (f["port"] or 0) >= 1024,
        "udp": f["proto"] == "17",
        "cmd_len_log": math.log1p(len(f["cmd"])),
        "recent": f["recent"],
    }


# --- the deterministic experts ------------------------------------------------------------------------
# Each returns None (not my behaviour) or (attack: bool, reasons: list[str]).

def wmi_child(f: dict, g: dict):
    if f["kind"] != "process" or not g["parent_wmi"]:
        return None
    why = ["parent wmiprvse.exe → {}".format(f["image"])]
    hits = [n for n, k in (("a shell", "child_shell"), ("a script host / LOLBin", "child_lolbin"),
                           ("-EncodedCommand", "ps_encoded"), ("hidden window", "ps_hidden")) if g[k]]
    return bool(hits), why + hits


def office_child(f: dict, g: dict):
    if f["kind"] != "process" or not g["parent_office"]:
        return None
    why = ["parent {} → {}".format(f["parent"]["img"], f["image"])]
    hits = [n for n, k in (("a shell", "child_shell"), ("a script host / LOLBin", "child_lolbin"),
                           ("download cradle", "cradle")) if g[k]]
    return bool(hits), why + hits


def updater_temp(f: dict, g: dict):
    if f["kind"] != "process" or not g["parent_updater"]:
        return None
    why = ["updater {} → {}".format(f["parent"]["img"], f["image"])]
    return g["user_dir"], why + (["runs from a Temp / Downloads folder"] if g["user_dir"] else [])


def hidden_powershell(f: dict, g: dict):
    if f["kind"] != "process" or not g["child_powershell"]:
        return None
    hits = [n for n, k in (("-EncodedCommand", "ps_encoded"), ("hidden window", "ps_hidden"),
                           ("-NoProfile", "ps_noprofile"), ("download cradle", "cradle")) if g[k]]
    return len(hits) >= 2, ["PowerShell started by {}".format(f["parent"].get("img") or "?")] + hits


def dropped_beacon(f: dict, g: dict):
    if f["kind"] != "flow" or not g["dest_public"]:
        return None
    attack = g["user_dir"] and not g["port_web"]
    return attack, ["{} → public {}:{}".format(f["image"], f["dest"], f["port"])] + (
        ["program runs from a user folder", "non-web port"] if attack else [])


# Router order: most specific first. A case goes to the first expert that claims it.
EXPERTS = [("wmi_child", wmi_child), ("office_child", office_child), ("updater_temp", updater_temp),
           ("hidden_powershell", hidden_powershell), ("dropped_beacon", dropped_beacon)]

# Attack types each rule was written from (types: see run.py TYPE_OF).
SOURCES = {"wmi_child": {"wmi_ps"}, "office_child": {"office"}, "updater_temp": {"updater"},
           "hidden_powershell": {"wmi_ps", "batch", "office"}, "dropped_beacon": {"payload_flow"}}


def route(f: dict, g: dict, available=None):
    """(expert name, attack, reasons) from the first available expert that claims the case, else None."""
    for name, fn in EXPERTS:
        if available is not None and name not in available:
            continue
        out = fn(f, g)
        if out is not None:
            return name, out[0], out[1]
    return None
