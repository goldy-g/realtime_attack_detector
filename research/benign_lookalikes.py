"""2.4 Benign look-alikes: how often normal activity matches each attack pattern.

The patterns come from the 27 alert points (attack_catalogue.py). For each, it
counts matching events in all 62 training days split by label (benign,
malicious, context, excused), the machines where benign matches occur, and the
most common benign shapes. It also counts how many of the 27 alert points
match, so each pattern shows its hit rate on attacks next to its noise.

Writes research/out/benign_lookalikes.json and benign_lookalikes.md.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict

from common import base, day_events, day_labels, machines, pmap, props, save_json, save_text

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
          "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}
ENCODED = re.compile(r"\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s", re.I)
HIDDEN = re.compile(r"\s-(w|wi|win|wind\w*)\s+(1|h\w*)\b", re.I)
CRADLE = re.compile(r"net\.webclient|downloadstring|downloadfile|invoke-webrequest|\biwr\b|\biex\b|invoke-expression|bitstransfer", re.I)
USERDIR = re.compile(r"\\(downloads|temp|tmp|appdata\\local\\temp)\\", re.I)
PRIVATE = re.compile(r"^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fe80:|0\.0\.0\.0)")

# Generic techniques an analyst watches for, beyond the 27 alert points: how common are they on normal machines?
GENERIC = [
    ("recon command (whoami, net, nltest, ipconfig, systeminfo, tasklist, netstat, …)",
     lambda image, cmd: image in {"whoami.exe", "nltest.exe", "systeminfo.exe", "tasklist.exe", "netstat.exe",
                                  "quser.exe", "arp.exe", "route.exe", "nslookup.exe", "ipconfig.exe"}
     or (image in {"net.exe", "net1.exe"} and re.search(r"\b(user|group|localgroup|view|session|share|accounts)\b", cmd, re.I))),
    ("scheduled task or service created (schtasks /create, sc create)",
     lambda image, cmd: (image == "schtasks.exe" and "/create" in cmd.lower()) or (image == "sc.exe" and " create " in cmd.lower())),
    ("Run key written with reg.exe",
     lambda image, cmd: image == "reg.exe" and " add " in cmd.lower() and "\\run" in cmd.lower()),
    ("LOLBin download or script run (certutil, bitsadmin, mshta, regsvr32 /i, rundll32 script)",
     lambda image, cmd: (image == "certutil.exe" and re.search(r"urlcache|decode|-f\b", cmd, re.I))
     or image in {"bitsadmin.exe", "mshta.exe"}
     or (image == "regsvr32.exe" and "/i:" in cmd.lower())
     or (image == "rundll32.exe" and re.search(r"javascript:|http|vbscript:", cmd, re.I))),
    ("remote execution or tunnelling tool (psexec, wmic /node, winrs, plink)",
     lambda image, cmd: image in {"psexec.exe", "psexesvc.exe", "winrs.exe", "plink.exe"}
     or (image == "wmic.exe" and "/node" in cmd.lower())),
    ("credential tool or lsass dump (mimikatz, procdump, comsvcs MiniDump)",
     lambda image, cmd: image in {"mimikatz.exe", "procdump.exe", "procdump64.exe"}
     or re.search(r"sekurlsa|minidump|lsass", cmd, re.I) is not None),
    ("user or group change (net user /add, net localgroup /add)",
     lambda image, cmd: image in {"net.exe", "net1.exe"} and "/add" in cmd.lower()),
]


def process_patterns(ev: dict) -> list[str]:
    p = props(ev)
    image, parent = base(p.get("image_path")), base(p.get("parent_image_path"))
    cmd = " " + (p.get("command_line") or "") + " "
    hits = []
    if parent == "wmiprvse.exe":
        hits.append("child of WMI (wmiprvse.exe)")
        if image in ("powershell.exe", "pwsh.exe"):
            hits.append("WMI starts PowerShell")
    if image in ("powershell.exe", "pwsh.exe") or "powershell" in cmd.lower():
        if ENCODED.search(cmd):
            hits.append("PowerShell with an encoded command")
        if HIDDEN.search(cmd):
            hits.append("PowerShell with a hidden window")
        if CRADLE.search(cmd):
            hits.append("PowerShell download cradle")
    if parent in OFFICE and image in SHELLS:
        hits.append("Office app starts a shell")
    if image in SHELLS and USERDIR.search(cmd) and re.search(r"\.(bat|cmd|vbs|js|ps1|hta)\b", cmd, re.I):
        hits.append("script from Downloads/Temp")
    if image.endswith(".exe") and USERDIR.search((p.get("image_path") or "") + cmd) and image not in SHELLS:
        hits.append("program run from Downloads/Temp")
    hits += [name for name, test in GENERIC if test(image, cmd)]
    return hits


def flow_patterns(ev: dict) -> list[str]:
    p = props(ev)
    hits = []
    if p.get("direction") == "outbound":
        if not PRIVATE.match(p.get("dest_ip") or ""):
            hits.append("outbound to a non-private address")
        if p.get("dest_port") == "3389" and base(p.get("image_path")) == "mstsc.exe":
            hits.append("outbound RDP (mstsc.exe to 3389)")
    return hits


def shape(ev: dict) -> str:
    p = props(ev)
    if ev["object"] == "PROCESS":
        cmd = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27}", "<guid>", (p.get("command_line") or ""), flags=re.I)
        cmd = re.sub(r"\d+", "#", cmd)
        return "{} ← {} :: {}".format(base(p.get("image_path")), base(p.get("parent_image_path")), cmd[:140])
    return "{} → {}:{}".format(base(p.get("image_path")), p.get("dest_ip"), p.get("dest_port"))


def scan_day(row: dict) -> dict:
    machine = row["machine"]
    labels = day_labels(machine)
    mal = set(labels["malicious_event_ids"])
    ctx = set(labels.get("context_event_ids") or [])
    chain = labels["event_chain"]
    ex_chains, ex_actors = set(labels.get("excused_chains") or []), set(labels.get("excused_actors") or [])
    alert_points = {a["first_alertable_event_id"] for a in labels.get("attacks") or []}
    counts = defaultdict(Counter)            # pattern -> label -> n
    shapes = defaultdict(Counter)            # pattern -> benign shape -> n
    ap_hits = defaultdict(list)              # pattern -> alert-point ids
    totals = Counter()
    with __import__("gzip").open(day_events(machine), "rt", encoding="utf-8") as fh:
        for line in fh:
            is_proc = '"object":"PROCESS"' in line and '"action":"CREATE"' in line
            is_flow = '"object":"FLOW"' in line
            if not (is_proc or is_flow):
                continue
            ev = json.loads(line)
            eid = ev["id"]
            label = ("malicious" if eid in mal else "context" if eid in ctx else
                     "excused" if chain.get(eid) in ex_chains or ev.get("actorID") in ex_actors else "benign")
            totals[ev["object"] + " " + label] += 1
            for pat in (process_patterns(ev) if is_proc else flow_patterns(ev)):
                counts[pat][label] += 1
                if label == "benign":
                    shapes[pat][shape(ev)] += 1
                if eid in alert_points:
                    ap_hits[pat].append(eid)
    return {"machine": machine, "attacked": row["attacked"], "counts": {k: dict(v) for k, v in counts.items()},
            "shapes": {k: dict(v.most_common(30)) for k, v in shapes.items()},
            "alert_points": dict(ap_hits), "totals": dict(totals)}


def main() -> None:
    days = pmap(scan_day, machines())
    patterns = sorted({p for d in days for p in d["counts"]})
    out = {}
    for pat in patterns:
        lab = Counter()
        machines_benign = set()
        shapes = Counter()
        for d in days:
            c = d["counts"].get(pat, {})
            lab.update(c)
            if c.get("benign"):
                machines_benign.add(d["machine"])
            shapes.update(d["shapes"].get(pat, {}))
        out[pat] = {"by_label": dict(lab), "benign_machines": len(machines_benign),
                    "alert_points_matched_train": sum(len(d["alert_points"].get(pat, [])) for d in days),
                    "top_benign_shapes": shapes.most_common(12)}
    totals = Counter()
    for d in days:
        totals.update(d["totals"])
    save_json("benign_lookalikes.json", {"patterns": out, "totals": dict(totals)})

    lines = ["# Benign look-alikes (2.4)", "",
             "Matches per attack pattern over the 62 training days (24 training alert points).", "",
             "| Pattern | Alert points matched | Benign events | Benign machines | Malicious · context · excused |",
             "|---|---|---|---|---|"]
    for pat, o in sorted(out.items(), key=lambda kv: -kv[1]["alert_points_matched_train"]):
        b = o["by_label"]
        lines.append("| {} | {} / 24 | {} | {} / 62 | {} · {} · {} |".format(
            pat, o["alert_points_matched_train"], b.get("benign", 0), o["benign_machines"],
            b.get("malicious", 0), b.get("context", 0), b.get("excused", 0)))
    lines += ["", "## Most common benign matches", ""]
    for pat, o in out.items():
        if not o["top_benign_shapes"]:
            continue
        lines.append("**{}**".format(pat))
        lines += ["- {}× `{}`".format(n, s.replace("`", "'")) for s, n in o["top_benign_shapes"][:6]]
        lines.append("")
    lines += ["Totals: " + ", ".join("{} {}".format(k, v) for k, v in sorted(totals.items()))]
    save_text("benign_lookalikes.md", "\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
