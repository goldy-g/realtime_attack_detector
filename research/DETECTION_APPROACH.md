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
| 3.6 | **Alerting rules** | Alert on the case's own event (the process start or connection) when the verdict is "attack" with confidence at or above a threshold set on dev in stage 4. At most one alert per process tree: once a tree is alerted, its later cases skip the model. No alerts in warm-up. If the wave is cancelled, pending work is dropped. | Repeat detections earn nothing; false alarms count once per benign chain; skipping alerted trees saves model time during the attack's burst (up to 14 cases in 10 s). |
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
- **Rules or a trained classifier alerting directly (SQ-1):** fastest of all, but
  it breaks "Detection decisions must come from the SLM" under the strict reading.
  Parked until Q-5 is answered.
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
