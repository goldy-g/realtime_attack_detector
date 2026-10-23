# Detection approach (3.1, proposed)

The third decision, after Model (Gemma 4 E4B, fallback E2B) and Runtime
(`llama-server` b11669). Every number here comes from `FINDINGS.md`.

## The proposal in one line

Cheap code watches every event and picks out the few that are new for this
machine. The SLM judges each one in a short verdict-only call, and the alert goes
out the moment it says "attack". A second, slower call writes the explanation,
citing event IDs that code has already checked.

```
on_event ──► state (process tree, baseline) ──► triage: new? ──► priority queue
  (µs, never blocks)                              (selects, ranks,     │
                                                   never alerts)       ▼
                                        model worker: verdict call (~1.7–3.4 s)
                                                     │ attack
                                                     ▼
                                        callbacks.alert(event) at once
                                                     │
                                                     ▼
                                        explanation call (when idle) ──► callbacks.explain(text, checked IDs)
```

## The parts

| # | Part | What it does | Why |
|---|---|---|---|
| 3.2 | **Intake and state** | `on_event()` updates in-memory state and returns: a process table keyed by `objectID` (image, command line, parent, user, start time, event IDs), each process's recent events (bounded), file writes and outbound connections. | 1–32 events/s live; a slow `on_event()` delays every later event (2.3). |
| 3.3 | **Baselines** | Warm-up hour → the machine's own parent→child pairs and process→port pairs. Training days → fleet rarity: on how many of the 62 machines each pair occurs, precomputed once and shipped as a small file. | No attack starts in warm-up, so it is a clean picture of normal for this machine (2.5). |
| 3.4 | **Triage (V2)** | During live only: a case is a process start whose parent→child pair is new for the machine, or an outbound connection on a port the process had not used (`svchost.exe` on ephemeral UDP ports ignored). The queue is ordered by fleet rarity, then age. Identical pairs inside one process tree are merged into one case. Triage never alerts. | Keeps all 25 alert points at about 1 case/min on a normal machine (2.5). Fleet rarity ranks but never drops: dropping lost one alert point. |
| 3.5 | **Case and verdict call** | A compact case of about 250 tokens: the event, three levels of ancestry, the decoded `-EncodedCommand` text (never raw base64), the baseline facts, and only this process tree's activity in the last 2 minutes. The system prompt stays cached. The grammar forces `{"verdict","confidence"}`, about 10 tokens. One call at a time, all CPU threads to it. | Reading the case is 95% of the cost, so shorter cases buy time directly (2.6); the verdict must land within 2–5 s (2.3). |
| 3.6 | **Alerting rules** | Alert on the case's own event (the process start or connection) when the verdict is "attack" with confidence at or above a threshold set on dev in stage 4. At most one alert per process: once a process is alerted on, its later cases skip the model; its children are still judged (amended, see below). No alerts in warm-up. If the wave is cancelled, pending work is dropped. | Repeat detections earn nothing; false alarms count once per benign chain; skipping alerted processes saves model time during the attack's burst (up to 14 cases in 10 s). |
| 3.7 | **Explanation call** | Runs when no verdict is waiting, and for every open alert after the feed ends (5 minutes allowed). The prompt follows the label write-ups: what happened, why this event, the chain, the evidence. Code builds the candidate evidence list from the alerted process tree (its start, its children, its connections, the files it ran), the model picks from it, and code keeps only IDs that were delivered and belong to that tree. | Answers Q-2. Evidence precision is scored, and the model has misread fields before (2.10); citing only checked IDs keeps the evidence clean. |
| 3.8 | **Start-up and safety** | `__init__` starts `llama-server` on a free local port, loads the model, caches the system prompt, then times a few probe cases. If E4B is slower than the budget on this machine, it switches to E2B. Stops the server on exit; restarts it if it dies. If the queue backs up, the oldest low-rarity cases are shed first. | The target CPU is unknown (Q-4); the detector should adapt rather than guess. |

## Alternatives considered

- **The model reads every event, or fixed windows of the stream:** up to 32 events/s
  against 2–3 s per call. It cannot keep up.
- **One call for the verdict and the explanation together:** the explanation's
  50–100 tokens at 20–50 tokens/s add 2–5 s before the alert. Timeliness drops
  from about 0.90 to about 0.80.
- **Batching several cases into one prompt:** fewer calls, but every case waits for
  the batch and the prompt grows. Kept as a fallback under heavy backlog only, if
  stage 4 shows bursts overflowing the queue.
- **Rules or trained classifiers alerting directly (SQ-1):** fastest of all, but
  it breaks "Detection decisions must come from the SLM" under the strict reading.
  It is solution 2, a panel of specialist experts, under "Two competing solutions"
  below: built behind a switch that is off in the submission, measured, not shipped.
- **Wider triage (registry Run keys, new services and tasks, injection events):**
  would reach later attack stages, but the testbed's own automation creates
  thousands of benign tasks (2.4). Added in stage 4 only if the
  leave-one-attack-type-out test shows a gap.

## Set in stage 4, not now

The confidence threshold; case length (150 vs 250 tokens); the prompt (v1 is the
starting point); the thread count; the shedding rule; whether batching is needed.

## Risks

- **Attack types the labels barely have.** The triage only sees new process starts
  and new connections. An attack that only uses already-known pairs (WMI
  persistence firing later, for example) is invisible to it. The
  leave-one-attack-type-out test in stage 4 measures this.
- **Bursts.** 14 cases in 10 s at 1.7–3.4 s each is 24–48 s of model time. Ranking
  by rarity and skipping alerted trees are the answer; stage 4 measures whether
  they are enough.
- **Target speed.** Measured on the Mac only. The start-up timing and the E2B
  fallback cover a slow target; the Windows run in stage 5 confirms it.

## Amendment after run v1.1-dev (22 Oct)

The first design silenced a whole process tree after its first alert. On the
batch-file attack (dev wave atk-efdb) the model flagged `explorer.exe -> cmd.exe`
running the downloaded `runme.bat` one second before the alert point. That event
is labelled context, so the alert earned nothing, and the hidden PowerShell that
`cmd.exe` started next (the alert point) was never judged. Duplicates and repeat
false alarms are free under the scoring rules, so silencing a tree can only lose
detections. Now only the alerted process itself is skipped; its children are judged.

## Two competing solutions (23 Oct)

Two answers to the same task, kept apart and measured on the same attacks.
Solution 1 meets the assignment's rule ("detection decisions must come from the
SLM"), and its numbers are the result we submit. Solution 2 is what we would build
if the graders let other models decide (Q-5): a future optimization, built behind a
switch that is off in the submission (`DETECTOR_EXPERT_RAISES=1` turns it on).

| | Solution 1: the SLM decides (submitted) | Solution 2: specialist panel, first specialist only |
|---|---|---|
| Who raises the alert | the SLM, for every case | a specialist, the moment it recognises a case; the SLM for every other case |
| Who writes the explanation | the SLM | the SLM |
| Dev attack waves, live (15) | timeliness 0.867, delay median 3.05 s (run v1.4-dev-attacks; 0.852 at v1.3) | timeliness 1.000, delay median 0.00 s (run s2-dev-attacks) |
| Caught · false alarms, same run | 15 of 15 · 1 | 15 of 15 · 1, the same SLM false alarm |
| Holdout attacks, offline replay | timeliness 0.767 | 0.875 |
| Public eval waves, live (`--set full`: 3 attacks, 4 benign) | 2 of 3 caught, timeliness 0.563, no false alarm (run v1.4-full-mac) | about 0.667, an estimate: the specialist recognises both PowerShell attacks; both solutions miss the Remote Desktop hop |

The offline replay assumes 1.7 s per verdict and is pessimistic, so compare its two
columns with each other, not with the live rows.

**Solution 1, the result.** Every alert comes from an SLM verdict; code may select,
order and feed cases, nothing more. SQ-1's one surviving expert, hidden PowerShell
(a PowerShell start with at least two of: encoded command, hidden window,
`-NoProfile`, download cradle), puts its cases first in the model queue and passes
its reasons to the explanation call (`submission/experts.py`).
- Why: the SLM already catches every PowerShell-delivered attack, so an expert
  cannot add a catch, only time. The attack's own case used to wait behind its
  lead-up cases, which are just as rare and arrived first.
- Why this rule and not a trained ranker: the decision tree, boosted trees, n-gram
  model and Laya only tie it. The rule needs no training data, survives
  leave-one-attack-type-out, and gives reasons an explanation can use.
- Checked in production code (`tools/replay_cases.py`): it recognises the first
  case of 15 of 15 dev attacks, 6 of 7 holdout attacks (not the Notepad++
  updater) and 2 of 3 eval attacks (not the RDP hop), and no benign or context case.
- Live check, run v1.3-dev-attacks against v1.2-dev-attacks (the same 15 dev attack
  waves in real time, `results/v1.3-dev-attacks/compare_v1.2.md`): timeliness 0.839 →
  0.852 and median delay 3.41 → 3.11 s. Four attacks were caught earlier (one at its
  7th malicious event instead of its 19th) and none later; 15 of 15 caught, 1 false
  alarm and evidence precision 1.00, all unchanged. The gain is smaller than the
  offline replay's because the live queue was rarely long: 3 to 7 cases per wave
  (34 on one), so the attack's own case seldom had anyone to overtake.

**Solution 2, a panel of specialists (future optimization).** Each specialist is
built for one family of attack behaviour, its strong side. It judges only cases
inside that family, decides in microseconds, and stays silent everywhere else. Any
specialist that recognises a case raises the alert at once. Whatever no specialist
claims goes to the SLM, which also writes every explanation.
- Why a panel beats any single model, the SLM included:
  - speed: an attack a specialist knows is caught at its first malicious event; the
    SLM needs 1.9 to 3.6 s per verdict;
  - precision: a specialist that stays silent outside its family can be held to
    almost no false alarms; the first one raised no benign case in the 703-case set;
  - coverage: an attack passes several steps (delivery, execution, its first
    connection, the hop to the next machine), and each step is a chance for some
    specialist to catch it;
  - the SLM keeps its own strong side: the unfamiliar case and the explanation.
- The panel. Triage hands over only process starts and connections, so these are the
  specialists that count:

  | Specialist | Strong side | Learns from | On our data |
  |---|---|---|---|
  | Script delivery | PowerShell started hidden, encoded or downloading code | the `hidden_powershell` rule now; a model trained on public recordings next | built: recognises the first case of 15/15 dev, 6/7 holdout and 2/3 eval attacks, no benign case |
  | Execution chain | an updater, installer, Office program or WMI starting a program it never starts, from a user folder | public recordings; benign behaviour from OpTC's training days | to build; target: the Notepad++ updater, missed by every model so far |
  | Network | a program seconds old calling a bare public IP, or calling out at a steady rhythm | timing statistics, no attack labels needed | to build; target: the payload connection, caught today only at SLM speed |
  | Lateral movement | Remote Desktop and remote-service hops | public recordings | to build; target: the eval Remote Desktop hop |
  | Generalist: the SLM | anything no specialist claims; every explanation | n/a | built: solution 1's model and prompt |

- Measured: run s2-dev-attacks, the same 15 dev attack waves in real time
  (`results/s2-dev-attacks/compare_v1.3.md`). Every attack was caught at its first
  malicious event: timeliness 0.852 → 1.000 and delay median 3.11 → 0.00 s, better
  on all 15, worse on none. The specialist alerts 0.3 ms after the event arrives (at
  most 4 ms). Recall, the one false alarm (the SLM's, on the testbed's logon script)
  and evidence precision 1.00 are unchanged, and the SLM explained all 33 alerts
  (median 6.6 s after the alert). The gain is time only: the specialist caught no
  attack the SLM missed. Offline, holdout mean timeliness rises from 0.767 to 0.875;
  the gap left is the Notepad++ updater.
- Why each specialist must learn from its own family's data, not from OpTC's labels:
  SQ-1 trained a decision tree, boosted trees, a text model and 14 better setups on
  the dev labels. Dev holds three attack types, and one, WMI starting hidden
  PowerShell, is 42 of its 48 attack cases, so every model learned "PowerShell means
  attack" and none caught the updater (`research/sq1/training_conclusion.md`). So
  each specialist is trained on recorded attacks of its own family from public
  datasets (OTRF Security-Datasets, Splunk attack_data: Sysmon process-start and
  network-connection logs, whose fields map onto OpTC's PROCESS CREATE and FLOW START
  events), with benign behaviour from OpTC's training days. OpTC's attacks stay a
  pure test set: nothing in the panel is fitted to the attacks it is scored on.
- Bar for adding a specialist: it raises no benign case on the dev and holdout
  benign waves, it catches its own family on held-out OpTC attacks, and the whole
  panel is checked with each attack type left out.
- Limits: a family no specialist knows still waits for the SLM, so the SLM stays in
  the panel; any specialist can raise alone, so their false alarms add up; and each
  specialist is only as good as the recordings of its family.
- Risk: outside this testbed, admin tools such as Ansible and SCCM run `powershell
  -NoProfile -EncodedCommand`, which the rule would raise. A trained script
  specialist that reads the decoded command, not just its flags, is the answer.
- The switch: `DETECTOR_EXPERT_RAISES=1` (`config.EXPERT_RAISES`, commit 0463030). In
  `Engine.submit`, a recognised case raises its alert from the event thread, and only
  its explanation goes to the SLM; nothing else changes.
