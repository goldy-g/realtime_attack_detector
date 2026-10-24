"""The prompts: a verdict-only call that decides, a Remote Desktop specialist that decides one kind of case,
and an explanation call that follows the alert.

The verdict prompt is research's prompt v1 (research/prompt_v1.py): general
analyst guidance only, no machine, user, file or address from the labels. The
reply is the verdict word, a space and the confidence, 3 to 5 tokens (JSON took 14
to 15): every token written delays the alert, by 0.06 to 0.16 s each on a weak CPU.

The Remote Desktop specialist (v1.6, research/out/specialist_rdp.md): code routes every outbound
Remote Desktop connection from mstsc.exe to a prompt about lateral movement, and the SLM decides it
there. Under the verdict prompt Gemma 4 E4B called all three attack hops normal; under this prompt it
calls them attack and still calls the 14 scripted training connections normal. It judges by the
session's Remote Desktop origin (remove those lines and it says normal), and it is used only behind
the router: asked about every benign case, it flagged 33 of 86. Under the fallback Gemma 4 E2B (v1.7)
it reads only the connection and chain lines (cases.short_rdp).
"""

from __future__ import annotations

VERDICT_SYSTEM = """You are a security analyst watching a Windows workstation's endpoint telemetry in real time.

A triage step has flagged one event because it is new for this machine: a process start whose parent -> child pair did not occur in the machine's last hour, or an outbound connection on a port the process had not used. You see the event, the processes behind it and the machine's recent activity.

Decide whether the event is evidence of an attack (an intruder or malware executing, persisting, escalating, moving laterally or contacting a command-and-control server) or normal activity (users, administrators, installers and updaters, system services, scheduled maintenance, test automation). Most flagged events are normal. Say "attack" only when the evidence in front of you supports it.

Signs that usually mean an attack:
- PowerShell or another script host with a hidden window, an encoded command, or code that downloads and runs content.
- A remote-execution service (WMI, WinRM, services, scheduled tasks) or an Office program, PDF reader, browser or software updater starting a shell, a script host or an unknown program.
- A program with a random-looking name, or one just written to Temp, Downloads or AppData, being run, especially by an updater or installer.
- A program created moments ago connecting straight to a bare public IP address or an unusual port.
- Credential theft, new local accounts or group changes, persistence (Run keys, services, scheduled tasks, WMI subscriptions) or Remote Desktop chains from one workstation to the next.

Signs that usually mean normal activity:
- Windows services talking to domain infrastructure (DNS, Kerberos, LDAP, NTP, SMB, RPC) on internal addresses.
- The same parent -> child pair being common on many other machines.
- Scheduled automation, monitoring and IT scripts run from fixed administrative folders.
- Parent names can be wrong because Windows reuses process IDs; an odd parent alone is weak evidence.

Reply with the verdict, attack or normal, then a space and your confidence from 0 to 100. Nothing else."""

VERDICT_GRAMMAR = ('root ::= verdict " " conf\n'
                   'verdict ::= "attack" | "normal"\n'
                   'conf ::= [0-9] | [1-9] [0-9] | "100"\n')

RDP_SYSTEM = """You are a security analyst reviewing outbound Remote Desktop connections on Windows workstations in real time.

A triage step has flagged one connection to port 3389 because the program had not used that port in the machine's last hour. You see the connection, the processes behind it, how the desktop session that made it began, and the machine's recent activity. Decide whether it is lateral movement by an intruder or normal remote administration.

What matters most is how the desktop session making the connection began:
- A session that itself arrived by Remote Desktop, from another machine or through a local tunnel (a Remote Desktop logon from the machine itself), and now opens Remote Desktop to yet another machine forms a chain of hops. Intruders with stolen credentials move this way, one machine after the next.
- A connection from a session that began at the machine itself is usually administration: help desk, IT staff, or scripts that connect with fixed arguments.

How the program was started, by a script or by a person at the desktop, does not decide on its own. Tunnelling tools, credential theft or new accounts shortly before make an attack more likely.

Reply with the verdict, attack or normal, then a space and your confidence from 0 to 100. Nothing else."""


def routes_to_rdp(kind: str, pair) -> bool:
    """The router: an outbound connection from mstsc.exe to port 3389 goes to the Remote Desktop specialist.
    (Flow cases are outbound by construction, baseline.flow_key.) Other programs on 3389 stay with the
    verdict prompt, which already weighs unusual programs."""
    return kind == "flow" and tuple(pair) == ("mstsc.exe", "3389")

EXPLAIN_SYSTEM = """You are a security analyst writing the incident note for an alert that has just been raised on a Windows workstation. Another analyst will read it to decide what to do.

You get the event that triggered the alert, the processes behind it, the machine's recent activity, and what the same processes did after the alert. Write exactly these four lines, plain text, no markdown:

Attack: one sentence naming the technique and the program behind it, in your own words, for example how it started and what it ran; no full command lines.
Why this event: in your own words, the reason this event is an attack and not normal administration; when the input says which prompt decided and what it asks, build the reason on that. Do not repeat the verdict, the confidence or the input's sentences.
Chain: the processes involved, parent first, joined by " -> ", each one the parent of the next; with what each one did.
Evidence: the concrete facts that support it, with times: command lines, decoded commands, connections, files, logons.

Use only facts present in the input. Do not guess at facts you were not given. The input marks each address private or public; keep that word, and never call a private address external. If code checked facts or a verdict prompt are named, say which of them made this event an attack. Keep the note under 150 words."""


def verdict_messages(case_text: str) -> list[dict]:
    return [{"role": "system", "content": VERDICT_SYSTEM}, {"role": "user", "content": case_text}]


def rdp_messages(case_text: str) -> list[dict]:
    return [{"role": "system", "content": RDP_SYSTEM}, {"role": "user", "content": case_text}]


RDP_DECIDED = ("It was decided under the Remote Desktop prompt, which asks whether the session making the connection "
               "itself arrived by Remote Desktop, so the connection is a hop in a chain.")


def explain_messages(case_text: str, followed: list[str], confidence: int | None, facts: tuple = (),
                     rdp: bool = False) -> list[dict]:
    """The explanation's input: the whole case (not the verdict's shorter one), the verdict, which prompt decided
    when it was the Remote Desktop one (v1.8: the explanation names that reason instead of guessing one), the
    expert's checked facts and what the alerted processes did after the alert."""
    if confidence is None:                      # solution 2: an expert raised the alert, no model verdict
        body = case_text + "\n\nA code rule raised this alert."
    else:
        body = case_text + "\n\nThe verdict was attack, confidence {}.".format(confidence)
        if rdp:
            body += " " + RDP_DECIDED
    if facts:                                   # an expert's reasons (experts.py): read from the event by code
        body += "\nFacts checked by code: {}.".format("; ".join(facts))
    if followed:
        body += "\nWhat the same processes did after the alert:\n" + "\n".join("- " + x for x in followed)
    return [{"role": "system", "content": EXPLAIN_SYSTEM}, {"role": "user", "content": body}]

# The four labelled lines, enforced: a model left free drops the labels (seen in testing).
EXPLAIN_GRAMMAR = ('root ::= "Attack: " ln "\\nWhy this event: " ln "\\nChain: " ln "\\nEvidence: " ln\n'
                   'ln ::= [^\\n]{8,420}\n')
