"""The two prompts: a verdict-only call that decides, and an explanation call that follows the alert.

The verdict prompt is research's prompt v1 (research/prompt_v1.py): general
analyst guidance only, no machine, user, file or address from the labels. The
reply is the verdict word, a space and the confidence, 3 to 5 tokens (JSON took 14
to 15): every token written delays the alert, by 0.06 to 0.16 s each on a weak CPU.
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

EXPLAIN_SYSTEM = """You are a security analyst writing the incident note for an alert that has just been raised on a Windows workstation. Another analyst will read it to decide what to do.

You get the event that triggered the alert, the processes behind it, the machine's recent activity, and what the same processes did after the alert. Write exactly these four lines, plain text, no markdown:

Attack: one sentence naming what is happening, e.g. "Remote WMI launch of an encoded PowerShell agent".
Why this event: why this event is the point where the activity becomes an attack, not normal administration.
Chain: the processes involved, parent first, joined by " -> ", with what each one did.
Evidence: the concrete facts that support it, with times: command lines, decoded commands, connections, files, logons.

Use only facts present in the input. Do not guess at facts you were not given. Keep the note under 150 words."""


def verdict_messages(case_text: str) -> list[dict]:
    return [{"role": "system", "content": VERDICT_SYSTEM}, {"role": "user", "content": case_text}]


def explain_messages(case_text: str, followed: list[str], confidence: int | None, facts: tuple = ()) -> list[dict]:
    if confidence is None:                      # solution 2: an expert raised the alert, no model verdict
        body = case_text + "\n\nA code rule raised this alert."
    else:
        body = case_text + "\n\nThe verdict was attack, confidence {}.".format(confidence)
    if facts:                                   # an expert's reasons (experts.py): read from the event by code
        body += "\nFacts checked by code: {}.".format("; ".join(facts))
    if followed:
        body += "\nWhat the same processes did after the alert:\n" + "\n".join("- " + x for x in followed)
    return [{"role": "system", "content": EXPLAIN_SYSTEM}, {"role": "user", "content": body}]

# The four labelled lines, enforced: a model left free drops the labels (seen in testing).
EXPLAIN_GRAMMAR = ('root ::= "Attack: " ln "\\nWhy this event: " ln "\\nChain: " ln "\\nEvidence: " ln\n'
                   'ln ::= [^\\n]{8,420}\n')
