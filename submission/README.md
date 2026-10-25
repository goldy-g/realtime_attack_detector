# OpTC real-time attack detector

Code tracks each machine and picks out the few events that are new for it. A local small
language model (Gemma 4 E4B, 4-bit, on llama.cpp's CPU server) decides whether each one is
an attack, and the alert goes out the moment it says so. Each verdict reads a short case:
the event, its ancestry and the facts code checked about them. Outbound Remote Desktop
connections are judged under a second prompt, written for lateral movement, on the fallback
model too. A further model call then writes the explanation from the whole case, citing
event IDs that code has checked. Every detection
decision comes from the SLM; code only selects, orders, routes and feeds the cases.

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
  to the front, because an attack's own case otherwise waits behind its lead-up cases, and
  so does Remote Desktop opened from a desktop session that itself arrived by Remote Desktop.
- **The SLM decides, on a short case.** Each case records the event, three levels of
  ancestry, the decoded `-EncodedCommand`, the baseline facts, how the process's desktop
  session began when that was a Remote Desktop logon, and its process tree's last two
  minutes, as of the event itself. The verdict reads all of it except the recent activity
  and the machine's remote logons, about 150 new tokens instead of 350. One piece of history
  is kept as a checked fact: when a new program's file was written by a process that had
  just connected to a public address, the case says so (download, write, run). A
  verdict-only call judges it; a grammar holds the reply to a word and a
  confidence, such as `attack 85`, so the model writes about 5 tokens. "attack" at
  confidence 50 or more raises the alert at once on the case's own event. One model call runs at a time with all threads, and the system prompts stay cached.
- **A specialist prompt for Remote Desktop.** An outbound connection from `mstsc.exe` to
  port 3389 is judged under a second system prompt about lateral movement: a session that
  arrived by Remote Desktop and opens Remote Desktop onward forms a chain of hops. The SLM
  still decides; code only picks the prompt. Under the main prompt Gemma 4 E4B called all
  three Remote Desktop attack hops in the data normal; under this one it calls them attack
  and still calls the 14 scripted training connections normal. With the fallback model it
  reads only the connection line and the chain line: E2B judged the whole case unreliably
  (1 of 3 hops) and the two lines correctly (3 of 3, none of the 14 scripted connections).
- **One alert per process.** A process already alerted on is not judged again; its
  children still are, because an early alert on a context event earns nothing.
- **Explanation second.** When no verdict is waiting, a second call writes four labelled
  lines: Attack, Why this event, Chain, Evidence. Code picks the cited event IDs from the
  alerted process tree, events delivered by the alert first, so evidence holds only
  checked IDs. The explanation reads the whole case, recent activity included, and is told
  when the Remote Desktop prompt made the decision, so it names that reason.
- **Start-up.** The detector starts `llama-server` on a free local port, caches its prompts
  and times a probe as long as a median verdict case. Real verdicts run about 1.2 times the
  probe (1.15 on the Mac, 1.20 on the 4-core laptop), so the probe is scaled by 1.2 first:
  if Gemma 4 E4B is then expected to need more than 4 s per verdict on the machine, it
  switches to Gemma 4 E2B. A probe above 3.33 s switches.

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
  with a `DETECTOR_*` environment variable: 8,192 tokens of context as three slots of 2,730
  (verdicts, explanations and Remote Desktop verdicts keep separate caches; the longest
  prompt with its reply needs about 2,200), threads = min(8, CPU count) for prompt
  and generation, `--jinja` chat template, one request at a time, alert at confidence 50,
  fallback model when the start-up probe times 1.2 exceeds 4 s.
- **Run:** `python evaluator/evaluate.py --detector submission.my_detector:MyDetector --set full --report scorecard.json`

## Results

Real-time `--set full`, the 7 public eval waves (3 attack, 4 benign), on an Apple M5 Pro
with 8 threads and Gemma 4 E4B, which the start-up check keeps here (1.4 s probe; run
v1.8.1-full-mac):

| | |
|---|---|
| Attacks caught | 3 of 3: both PowerShell attacks and the Remote Desktop hop |
| Timeliness | 0.924 (0.978 on the Remote Desktop hop, 0.952 and 0.842 on the PowerShell attacks) |
| Delay, median · max | 1.7 s · 1.9 s |
| False alarms | 0 in 7 waves |
| Evidence precision | 1.00 |
| Explanations | 6 of 6 alerts, median 11 s after the alert |

How it got there, on the same waves: without the Remote Desktop prompt (v1.5) 2 of 3,
timeliness 0.563; with it (v1.6) 3 of 3, 0.870; with the short verdict case (v1.8 and
v1.8.1) 0.924, the median delay down from 3.2 s to 1.7 s. With the fallback model forced on the same
machine (run v1.8-full-mac-e2b): 3 of 3, timeliness 0.933, median delay 1.0 s, no false
alarm.

On a 4-core i7-1165G7 laptop, below the target, v1.8.1's start-up check switched to E2B
(probe 3.98 s × 1.2 = 4.78 s expected): 3 of 3, no false alarm, timeliness 0.916, median
delay 2.4 s (run win-v1.8.1). v1.8 had kept E4B there after a 3.88 s probe and scored 0.841
(run win-v1.8); v1.7 on E2B scored 0.873 (run win-v1.7).

On the 17 holdout waves, from machines never used for tuning, v1.8 caught 7 of 7 attacks
with no false alarm, timeliness 0.850, median delay 1.6 s (run v1.8-holdout; v1.4 scored
0.814 there). On the 15 dev attack waves v1.8.1 caught 15 of 15 with no false alarm,
timeliness 0.914, median delay 2.2 s (run v1.8.1-dev-attacks; v1.4 scored 0.867 there with
one false alarm).

Offline, on the 25 labelled attack starts and 510 benign cases (86 from the validation
waves, 424 from extra windows sampled from the training days), the short verdict case kept
25 of 25 attacks and flagged 2 benign cases with E4B (6 with the whole case), and 3 with E2B
(28 with the whole case).

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
- **Giving the verdict the whole case.** Most recent-activity lines are other programs the
  same parent started, and they misled the model, the smaller one most: on 510 benign cases
  E2B flagged 28 with the whole case and 3 without the activity, E4B 6 and 2, with the
  same 25 of 25 attacks. Dropping them also halved each verdict's reading. Raw download
  lines did not help either: the model caught the updater attack only once they were folded
  into one checked fact.
- **The main model on a 4-core laptop.** Below the target hardware, E4B needed about 8 s per
  verdict with the whole case, so the detector fell back to E2B, which then missed the
  Remote Desktop hop (v1.6). With the short case its start-up probe took 3.88 s, under the
  4 s budget, but real verdicts took a median 4.6 s, and timeliness fell from 0.873 to
  0.841 (v1.8). The check now scales the probe to real verdict time (v1.8.1), and the
  laptop runs E2B at 0.916.
- **Teaching the main prompt about Remote Desktop chains.** The case names the session's
  Remote Desktop origin and the chain it makes, and the prompt lists Remote Desktop chains
  among the signs of an attack; E4B still called the hop normal (85, or 70 with an extra
  hint). Four worked examples from the training days added to the main prompt missed it
  too, and raised false alarms on 9 of 86 benign cases instead of 2. What worked was a
  separate prompt that judges only Remote Desktop connections.
- **The Remote Desktop prompt anywhere else.** Asked about every benign case, it flagged 33
  of 86, so it judges only the connections the router sends it. Under E2B with the whole
  case it caught 1 of 3 hops and called a scripted connection an attack; with only the
  connection and chain lines it catches 3 of 3 and none.
- **An example in the explanation prompt.** The model copied it into 18 of 52 notes, and
  it called a private address external. Asking for its own words, keeping the private or
  public label, and telling it which prompt decided removed both on the same 52 alerts.

## Known limitations

- **What triage cannot see.** Only new process starts and new outbound connections become
  cases. An attack step that reuses pairs the machine already had, such as persistence
  firing later, never reaches the model. The same holds for a Remote Desktop hop on a
  machine whose own scripts already ran `mstsc.exe` to port 3389 earlier in the wave (seen
  in training on host-339f).
- **Attack types barely in the labels.** The labelled attacks are almost all remote WMI
  starting hidden PowerShell. The updater attack, a program run from a user's Temp folder
  by the Notepad++ updater, flips between attack and normal on small changes to its case;
  with the download folded into one fact both models call it attack offline, but it is one
  example, so treat it as borderline.
- **The Remote Desktop hop rests on little data.** The specialist prompt was tested on 3
  attack hops from 2 machines and 14 scripted benign connections, all from local sessions.
  The data holds no legitimate chain, such as an administrator hopping through a jump host,
  and the prompt would call one an attack. The fallback's two-line case leaves the call
  close to code's chain check: E2B confirms what the chain line states.
- **The testbed's logon script.** Up to v1.4 the model called `explorer.exe` →
  `wscript.exe` an attack on one dev wave. With the short verdict case it calls it normal
  (95), but that rests on one machine's script.
- **Speed decides accuracy on slow CPUs.** Measured on an Apple M5 Pro and a 4-core
  i7-1165G7 laptop, not on the 8-core target. Where E4B is too slow, the detector runs E2B,
  which flags more benign cases and also flags `rdpclip.exe` starting in a session that
  arrived by Remote Desktop (context here, a false alarm on a legitimate session).
- **The remote WMI attack's ceiling.** Its own events arrive in a burst: 27 in the first
  0.57 s, then none until 3.2 s. A model verdict cannot land inside the burst on a CPU, so
  its timeliness stays 0.842 at any model speed; only code raising the alert itself (the
  future option below) reaches 1.000.
- **Explanation chains.** The Chain line sometimes joins sibling processes as if one started
  the other (2 of 6 notes on the eval waves). The cited event IDs come from code and are
  unaffected.
- **Explanations wait for verdicts.** During a burst, explanations queue behind verdicts:
  19 s after the alert at the 95th percentile on the eval waves on the Mac, 49 s with E2B
  on the 4-core laptop (run win-v1.8.1), inside the 5 minutes allowed.
- **Admin PowerShell.** Tools such as Ansible and SCCM run `powershell -NoProfile
  -EncodedCommand` legitimately. The queue rule moves such cases forward, but the model
  still decides, so this costs model time, not false alarms.
- **The public eval answers.** The benign eval waves w04–w07 have no `event_attack` entry in
  `answers.json`, so `metrics.py` raises a ValueError on `--set fast` and `--set full`. We
  scored with a copy of the answers that adds the empty entries.

## Future optimization: a panel of specialist experts

This detector keeps the rule that detection decisions come from the SLM. If
other models could decide, we would build a panel of specialists. Each specialist is
built for one family of attack behaviour and judges only cases inside it, in
microseconds. Any specialist that recognises a case raises the alert at once; the
SLM judges whatever no specialist claims and writes every explanation.

| Specialist | Strong side | Learns from | Status |
|---|---|---|---|
| Script delivery | PowerShell started hidden, encoded or downloading code | a rule now (`experts.py`); public attack recordings next | built and measured |
| Execution chain | an updater, installer, Office program or WMI starting a program it never starts, from a user folder | public attack recordings | next; target: the Notepad++ updater attack |
| Network | a program seconds old calling a bare public IP, or calling out at a steady rhythm | timing statistics | next; target: the payload connection |
| Lateral movement | Remote Desktop and remote-service hops | a rule now (`rdp_chain`); public attack recordings next | built for Remote Desktop and measured |
| The SLM | anything no specialist claims; every explanation | – | built: this detector's model |

The two built specialists are in the code behind a switch that is off by default
(`DETECTOR_EXPERT_RAISES=1`). On the 15 dev attack waves in real time, script delivery
caught every attack at its first malicious event: timeliness 1.000 against 0.867 (run
v1.4-dev-attacks), median delay 0.00 s against 3.1 s, with recall (15 of 15), false alarms
(1, the same one) and evidence precision (1.00) unchanged. On the 7 public eval waves the
two together caught all 3 attacks at their first malicious event: timeliness 1.000 against
0.924 for this detector, and no false alarm (run v2.1-full-mac). Within the SLM rule, the
detector already routes one family this way: code sends Remote Desktop
connections to a specialist prompt, and the SLM decides.

Each specialist has to learn from recordings of its own attack family, from public
datasets such as OTRF Security-Datasets and Splunk attack_data, whose Sysmon fields
map onto OpTC's process-start and connection events. It cannot learn from OpTC's
labels: they hold three attack types, almost all of them WMI starting hidden
PowerShell, and every model we trained on them learned "PowerShell means attack".
OpTC's attacks then stay a pure test set. The limits: an attack family no specialist
knows still waits for the SLM, and the specialists' false alarms add up, so each one
must raise nothing on benign days.

**Held back on purpose: the rest of OpTC.** The corrected OpTC release this data comes
from is public (doi:10.57745/UXCWOC): 939 GB covering 16–25 September 2019, with the red
team on the last three days. It would add the same attacks on more machines and a week of
benign activity. We did not use it. The final evaluation includes machines not provided
here, which very likely come from that release, and the anonymized names give no way to
tell which machines those are, so tuning on it could mean tuning on the hidden test. With
the graders' permission we would build the fleet baseline from the benign week (16–22
September) and use the attack days only as an extra test set.
