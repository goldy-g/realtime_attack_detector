# OpTC real-time attack detector

<!-- Skeleton: stage 5 (Ship) writes the sections marked "To write". The future
optimization is written already (research/DETECTION_APPROACH.md, "Two competing
solutions", has the full version). -->

## Approach

_To write in stage 5._

## Setup

_To write in stage 5: the model file and its download link, the llama-server build,
context size, thread count and the other model settings, requirements._

## Results

_To write in stage 5, from the real-time `--set full` scorecard._

## What did not work

_To write in stage 5._

## Known limitations

_To write in stage 5._

## Future optimization: a panel of specialist experts

The submitted detector keeps the rule that detection decisions come from the SLM. If
other models could decide, we would build a panel of specialists. Each specialist is
built for one family of attack behaviour and judges only cases inside it, in
microseconds. Any specialist that recognises a case raises the alert at once; the
SLM judges whatever no specialist claims and writes every explanation.

| Specialist | Strong side | Learns from | Status |
|---|---|---|---|
| Script delivery | PowerShell started hidden, encoded or downloading code | a rule now (`experts.py`); public attack recordings next | built and measured |
| Execution chain | an updater, installer, Office program or WMI starting a program it never starts, from a user folder | public attack recordings | next; target: the Notepad++ updater attack |
| Network | a program seconds old calling a bare public IP, or calling out at a steady rhythm | timing statistics | next; target: the payload connection |
| Lateral movement | Remote Desktop and remote-service hops | public attack recordings | next; target: the Remote Desktop hop |
| The SLM | anything no specialist claims; every explanation | – | built: the submitted model |

The first specialist is in the code behind a switch that is off in the submission
(`DETECTOR_EXPERT_RAISES=1`). On the same 15 dev attack waves in real time it caught
every attack at its first malicious event: timeliness 1.000 against 0.852 for the
submitted detector, median delay 0.00 s against 3.11 s. Recall (15 of 15), false alarms
(1, the same one) and evidence precision (1.00) were unchanged.

Each specialist has to learn from recordings of its own attack family, from public
datasets such as OTRF Security-Datasets and Splunk attack_data, whose Sysmon fields
map onto OpTC's process-start and connection events. It cannot learn from OpTC's
labels: they hold three attack types, almost all of them WMI starting hidden
PowerShell, and every model we trained on them learned "PowerShell means attack".
OpTC's attacks then stay a pure test set. The limits: an attack family no specialist
knows still waits for the SLM, and the specialists' false alarms add up, so each one
must raise nothing on benign days.
