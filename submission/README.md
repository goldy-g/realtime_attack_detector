# OpTC real-time attack detector

<!-- Draft, 23 Oct. Results is filled from the final real-time --set full run (stage 5).
Numbers that the speed work on the Windows laptop may change are kept out of the text. -->

Code tracks each machine and picks out the few events that are new for it. A local small
language model (Gemma 4 E4B, 4-bit, on llama.cpp's CPU server) decides whether each one is
an attack, and the alert goes out the moment it says so. A second model call then writes
the explanation, citing event IDs that code has checked. Every detection decision comes
from the SLM; code only selects, orders and feeds the cases.

## Approach

- **State and baselines.** `on_event()` only updates in-memory state and returns: a process
  table, each process's recent events, its files and its connections. Two baselines say
  what is normal: the machine's own warm-up hour, and on how many of the 62 training
  machines each parent→child pair occurs (`fleet_baseline.json`, built once).
- **Triage selects, never alerts.** A case is a live process start whose parent→child pair
  is new for the machine, or an outbound connection on a port the process had not used.
  On the labelled days this kept every alert point while producing about one case a minute
  on a normal machine. Cases wait in a queue, rarest across the fleet first. A PowerShell start
  with two of an encoded command, a hidden window, `-NoProfile` and a download cradle goes
  to the front, because an attack's own case otherwise waits behind its lead-up cases.
- **The SLM decides.** Each case shows the event, three levels of ancestry, the decoded
  `-EncodedCommand`, the baseline facts and its process tree's last two minutes, as of the
  event itself. A verdict-only call, held to `{"verdict", "confidence"}` by a grammar,
  judges it; "attack" at confidence 50 or more raises the alert at once on the case's own
  event. One model call runs at a time with all threads, and the system prompt stays cached.
- **One alert per process.** A process already alerted on is not judged again; its
  children still are, because an early alert on a context event earns nothing.
- **Explanation second.** When no verdict is waiting, a second call writes four labelled
  lines: Attack, Why this event, Chain, Evidence. Code picks the cited event IDs from the
  alerted process tree, events delivered by the alert first, so evidence holds only
  checked IDs.
- **Start-up.** The detector starts `llama-server` on a free local port, caches both prompts
  and times a probe case. If Gemma 4 E4B needs more than 4 s per verdict on the machine,
  it switches to Gemma 4 E2B.

## Setup

- **Python 3.10+, standard library only.** `requirements.txt` lists no packages.
- **Model:** Gemma 4 E4B, Google's quantization-aware 4-bit file `gemma-4-E4B_q4_0-it.gguf`
  (5.15 GB) from <https://huggingface.co/google/gemma-4-E4B-it-qat-q4_0-gguf>. Fallback:
  `gemma-4-E2B_q4_0-it.gguf` from <https://huggingface.co/google/gemma-4-E2B-it-qat-q4_0-gguf>.
  Put both in `submission/models/`, or point `DETECTOR_MODEL_DIR` at their folder.
- **Runtime:** llama.cpp build b11669, the official Windows CPU build
  <https://github.com/ggml-org/llama.cpp/releases/download/b11669/llama-b11669-bin-win-cpu-x64.zip>.
  Unzip it into `submission/bin/`, or point `DETECTOR_SERVER` at `llama-server.exe`. No
  compiler and no GPU (`-ngl 0 --device none`).
- **Model settings**, set by the detector in `submission/config.py`; each can be overridden
  with a `DETECTOR_*` environment variable: 8,192 tokens of context as two slots of 4,096
  (verdicts and explanations keep separate caches), threads = min(8, CPU count) for prompt
  and generation, `--jinja` chat template, one request at a time, alert at confidence 50,
  fallback model when a verdict takes more than 4 s at start-up.
- **Run:** `python evaluator/evaluate.py --detector submission.my_detector:MyDetector --set full --report scorecard.json`

## Results

_To fill from the final real-time `--set full` run (stage 5)._

## What did not work

- **Silencing a process tree after its first alert.** On the batch-file attack the model
  flagged `cmd.exe` one second before the alert point. That alert earned nothing, and the
  hidden PowerShell it started next, the real alert point, was never judged. Now only the
  alerted process itself is skipped (14 → 15 of 15 dev attacks).
- **Rendering a case when the model got to it.** Queued cases showed events that happened
  after them, and two benign cases became false alarms. Each case now shows the machine as
  of its own event.
- **Most small models.** We timed 14 recent models of up to 8B parameters on the CPU and
  scored them on up to 703 labelled cases. Most gave the same answer to every case, a
  security-tuned 8B called nearly everything normal, and Laya (a zero-shot encoder) flagged
  88% of benign cases. Only the Gemma 4 pair was both fast enough and able to separate
  attacks from normal activity.
- **Trained models to order the queue or decide.** A decision tree, boosted trees, an
  n-gram model and Laya, trained on the dev labels, learned "PowerShell means attack":
  almost every labelled attack is one type. None caught the Notepad++ updater attack, and
  14 better training setups did not change that. A hand-written rule that holds up when
  each attack type is left out orders the queue instead.
- **The main model on a 4-core laptop.** Below the target hardware, E4B needed about 8 s per
  verdict, so the detector fell back to E2B, which missed the Remote Desktop hop.

## Known limitations

- **What triage cannot see.** Only new process starts and new outbound connections become
  cases. An attack step that reuses pairs the machine already had, such as persistence
  firing later, never reaches the model.
- **Attack types barely in the labels.** The labelled attacks are almost all remote WMI
  starting hidden PowerShell. The updater attack, a program run from a user's Temp folder
  by the Notepad++ updater, is missed by the model.
- **A known false alarm.** The testbed's own logon script (`explorer.exe` → `wscript.exe`)
  is called an attack on one dev wave.
- **Speed decides accuracy on slow CPUs.** Measured on an Apple M5 Pro and a 4-core
  i7-1165G7 laptop, not on the 8-core target. Where E4B is too slow, the detector runs E2B,
  which is less accurate.
- **Explanations wait for verdicts.** During a burst, explanations queue behind verdicts:
  about 90 s after the alert at the 95th percentile on the Mac and up to 124 s on the
  laptop, inside the 5 minutes allowed.
- **Admin PowerShell.** Tools such as Ansible and SCCM run `powershell -NoProfile
  -EncodedCommand` legitimately. The queue rule moves such cases forward, but the model
  still decides, so this costs model time, not false alarms.
- **The public eval answers.** The benign eval waves w04–w07 have no `event_attack` entry in
  `answers.json`, so `metrics.py` raises a ValueError on `--set fast` and `--set full`. We
  scored with a copy of the answers that adds the empty entries.

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
