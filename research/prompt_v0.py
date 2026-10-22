"""The fixed, dataset-neutral prompt used to compare models (2.9, 2.10).

It holds general security guidance only: no examples, names or patterns taken
from the training labels, so a model's score reflects what it knows rather than
what we told it. The verdict comes first in the JSON so it can be acted on as
soon as it is generated.
"""

SYSTEM = """You are a security analyst watching a Windows workstation's endpoint telemetry in real time.

A triage step has flagged one event because it is new for this machine: a process start whose parent -> child pair did not occur in the machine's last hour, or an outbound connection on a port the process had not used. You see the event, the processes behind it and the machine's recent activity.

Decide whether the event is evidence of an attack (an intruder or malware executing, persisting, escalating, moving laterally or contacting a command-and-control server) or normal activity (users, administrators, installers and updaters, system services, scheduled maintenance, test automation). Most flagged events are normal. Say "attack" only when the evidence in front of you supports it.

Reply with JSON only: {"verdict": "attack" or "normal", "confidence": 0-100, "reason": "one short sentence"}."""

SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["attack", "normal"]},
        "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
        "reason": {"type": "string", "maxLength": 200},
    },
    "required": ["verdict", "confidence", "reason"],
}

# The verdict alone, for latency measurements: what an alert needs before the explanation.
VERDICT_SCHEMA = {
    "type": "object",
    "properties": {"verdict": {"type": "string", "enum": ["attack", "normal"]}},
    "required": ["verdict"],
}


def messages(case_text: str) -> list[dict]:
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": case_text}]


# The same shapes as explicit grammars. Some tokenizers emit a token that runs past the closing
# brace (for example "}\n"); llama.cpp's JSON-schema grammar then fails with "empty grammar
# stack" (seen on Granite 4.2). Allowing trailing whitespace makes every model behave alike.
_WS = 'ws ::= [ \\t\\n\\r]{0,8}\n'
_VERDICT = 'verdict ::= "\\"attack\\"" | "\\"normal\\""\n'
GRAMMAR_VERDICT = ('root ::= "{" ws "\\"verdict\\"" ws ":" ws verdict ws "}" ws\n' + _VERDICT + _WS)
GRAMMAR_QUICK = ('root ::= "{" ws "\\"verdict\\"" ws ":" ws verdict ws "," ws "\\"confidence\\"" ws ":" ws conf ws "}" ws\n'
                 + _VERDICT + 'conf ::= [0-9] | [1-9] [0-9] | "100"\n' + _WS)
GRAMMAR_FULL = ('root ::= "{" ws "\\"verdict\\"" ws ":" ws verdict ws "," ws "\\"confidence\\"" ws ":" ws conf ws "," ws '
                '"\\"reason\\"" ws ":" ws "\\"" char{1,240} "\\"" ws "}" ws\n'
                + _VERDICT + 'conf ::= [0-9] | [1-9] [0-9] | "100"\n'
                + 'char ::= [^"\\\\\\n] | "\\\\" ["\\\\/bfnrt]\n' + _WS)

