# Data guide

The data contains Windows security events from DARPA OpTC. Machine names, IP
addresses, dates and IDs are anonymized. Event order and time intervals are preserved.

## Files

| Location | Contents |
|---|---|
| `train/machines.jsonl` | One record per machine-day: machine name, event file and whether it contains an attack |
| `train/<machine>.events.jsonl.stream` | That machine-day's events, in time order |
| `train/<machine>.labels.json.stream` | Labels and attack descriptions for those events |
| `eval/waves.json` | Evaluation wave IDs, machines, live windows, event counts and sets |
| `eval/w01/` through `eval/w07/` | Each wave's `warmup.stream` and `live.stream` |
| `eval/answers.json` | Evaluation labels, under `{"waves": {"w01": {...}, ...}}` |
| `cache/` | Optional local caches; ignored by Git |

Paths above are relative to this directory.

## Reading the files

Files ending in `.stream` are **gzip-compressed JSON**:

- Event files, `warmup.stream` and `live.stream`: one JSON object per line (JSONL).
- Label files: one JSON object for the whole file.
- `machines.jsonl` is uncompressed JSONL; `waves.json` and `answers.json` are ordinary JSON.

Python examples, with paths relative to the repository root:

```python
import gzip
import json

machine = "host-0494"
with gzip.open(f"data/train/{machine}.events.jsonl.stream", "rt", encoding="utf-8") as stream:
    first_event = json.loads(next(stream))

with gzip.open(f"data/train/{machine}.labels.json.stream", "rt", encoding="utf-8") as stream:
    labels = json.load(stream)
```

The evaluator reads the evaluation streams itself and supplies events to the detector.

## Events

Each event is a dictionary. Its main fields are:

| Field | Meaning |
|---|---|
| `id` | Unique event ID, used by labels and alert callbacks |
| `timestamp` | Event time in ISO 8601 format, including time-zone offset |
| `hostname` | Machine name |
| `object`, `action` | Event type, such as `PROCESS CREATE`, `FILE WRITE` or `FLOW START` |
| `actorID` | Process performing the action |
| `objectID` | Entity the action affects |
| `pid`, `ppid`, `principal` | Process ID, parent process ID and account |
| `properties` | Event-specific details, such as command line, file path or network address |

For `PROCESS CREATE`, `objectID` identifies the new process. That process appears
as `actorID` in events it later performs. Available properties depend on the event type.

## Training labels

A label file refers to events by ID; it does not repeat the raw events.

| Field | Meaning |
|---|---|
| `machine` | Machine name |
| `malicious_event_ids` | Attack events at or after the attack's alert point |
| `context_event_ids` | Attack events before the alert point |
| `event_attack` | Maps malicious and context event IDs to their attack ID |
| `attacks` | Attack descriptions and ordered activities |
| `event_chain` | Maps every event ID to a process-chain ID, or `null` when no chain applies |
| `chains` | Process chains containing malicious events |
| `excused_chains`, `excused_actors` | Additional documented activity excluded from false-alarm counts |

**On benign days**, `malicious_event_ids` and `chains` are empty.
`attacks`, `context_event_ids` and `event_attack` are absent.
These optional fields can be read with `labels.get("attacks", [])` and
`labels.get("event_attack", {})`.

### Attack descriptions

Each entry in `attacks` contains:

| Field | Meaning |
|---|---|
| `attack_id`, `name`, `description` | Attack identity and plain-language summary |
| `alert_from`, `first_alertable_event_id` | Time and event ID where the evidence first supports identifying an attack |
| `why_alert_from` | Explanation of why this is the alert point |
| `lead_up` | Attack activities before the alert point |
| `steps` | Attack activities from the alert point onward |

Activities include a `name`, `explanation`, first `event_id` and `ts`, event count
(`n_events`), and `events` groups. Each group lists event `ids` and a `what`
description, with timing and count fields where applicable. Entries in `steps`
also have a `step` number. Together, these activities describe the malicious and
context events.

A process chain is a process tree, identified by its root process ID.
Each entry in `chains` has `chain_id`, `onset_event_id`, `onset_ts`, `malicious`
and `n_events`. Events outside a chain, such as service activity, may have a
`null` value in `event_chain`.

### Event labels

- **Malicious:** attack activity at or after `alert_from`.
- **Context:** attack activity before `alert_from`; an alert on it is neutral.
- **Benign:** events in neither list. There is no separate benign-event list.

During the live phase, an alert on an excused chain or actor is also neutral
unless it qualifies as a detection. Excused actors are matched against `actorID`.

## Evaluation labels

A wave contains one machine's warm-up and live events. `waves.json` describes its
timing; the [assignment README](../README.md) explains delivery and callback limits.

`answers.json` stores one label record per wave:

```python
with open("data/eval/answers.json", encoding="utf-8") as stream:
    wave_labels = json.load(stream)["waves"]["w02"]
```

Evaluation labels use the same attack descriptions and event-label meanings as
training labels, with these differences:

| Field | Difference from training |
|---|---|
| `attack` | Boolean indicating whether the wave contains an attack |
| `attack_onset_ts` | First attack's alert point, or `null` for a benign wave |
| `malicious_chains` | Replaces `chains`; entries have `chain_id`, `onset_event_id` and `onset_ts` |
| `event_chain` | Covers the wave's warm-up and live events |
| `steps[].in_window` | Indicates whether an activity falls within the wave's live window |

Benign waves omit `attacks`, `context_event_ids` and `event_attack`, as benign
training days do. Evaluation records do not contain the training `machine` field;
the machine name is in `waves.json`.

Attack steps describe the sequence; **timeliness scoring uses malicious-event
progress, not step numbers**. The exact rules are in
[evaluator/metrics.py](../evaluator/metrics.py).

The answer key is for evaluation, not detector input.
