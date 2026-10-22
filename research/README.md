# Stage 2 · Research the signal and the model

The research stage turns the open choices into evidence. It answers one question
per task, with a script whose output is saved under `research/out/`, and each
answer feeds a named decision or goal. Findings are collected in
[FINDINGS.md](FINDINGS.md) as they are measured.

## Principles

- **Criteria before measurements.** The decision criteria below were written
  before any model was run, so the pick cannot be fitted to the results.
- **Reproducible.** Every number comes from a script in this folder. Large
  intermediate files go to `data/cache/` (git-ignored); small results go to `research/out/`.
- **No tuning on the test.** Exploration and prompt work use the *dev* machines.
  Holdout machines and the seven public eval waves are only checked. The final
  evaluation adds machines and waves we have not seen.
- **Measure speed where it matters.** Speed is measured CPU-only with a thread cap
  and translated to the target (Windows x64, 8 cores, 16 GB, no GPU) with a stated
  factor. Accuracy does not depend on hardware, so it may be measured on the Mac GPU to save time.
- **Timebox.** About six hours. Two tracks run in parallel: the signal (data) and the model.

## Tasks

| # | Question | Method | Output | Feeds |
|---|---|---|---|---|
| 2.1 | What must research answer, and how will we choose? | This plan: questions, criteria, gates | This file | Every task below |
| 2.2 | What attack types exist, where is each alert point, and what makes it alertable? | Parse all 27 labelled attacks (24 training, 3 eval): alert-point event, lead-up, steps, write-up. Group by technique. Add the published OpTC red-team plan to anticipate types the hidden waves may hold. | Attack catalogue | Goal 2, Q-1, triage, prompt |
| 2.3 | How fast does an attack unfold after its alert point, and what does each second of decision delay cost? | Malicious events delivered over time after the alert point, per attack wave; the timeliness score for decision delays of 0.5–60 s. | Latency budget | Model size gate, queue design |
| 2.4 | Which benign activity looks like an attack, and what is excused? | Search benign activity for the alert-point patterns (encoded PowerShell, processes started by WMI or Office, remote logons, new outbound destinations). Describe the excused chains and actors. | Hard-negative families with counts | Case set, prompt, false-alarm risk |
| 2.5 | Can a cheap triage keep every alert point while leaving few cases for the model? | Novelty against the machine's warm-up hour, with and without a baseline built from the benign training days, simulated on the 62 validation waves and the 7 eval waves. | Cases per minute, alert-point coverage, best reachable timeliness, bursts | Detection approach (3.1), model throughput |
| 2.6 | How should a case be written for the model, and how many tokens does it take? | Render cases (event, process ancestry, recent chain activity, baseline facts), decode encoded commands, cut long fields; count tokens with the candidate tokenizers. | Case format v0, tokens per case, fixed prefix size | Latency estimate, 8,192-token limit |
| 2.7 | Is there a fair offline test for models? | Triage cases from the validation waves, labelled malicious / context / excused / benign, split by machine into dev and holdout, with the evidence IDs each positive should cite. | Labelled case set | 2.10 |
| 2.8 | Which models, architectures and runtimes are worth testing, and does each install on Windows without a compiler? | The newest releases up to ~8B from every major lab, checked on Hugging Face itself (not from memory). Architecture alternatives judged against the measured workload (long prompt, short answer): mixture-of-experts and hybrid decoders, encoder decision models such as Laya, diffusion and ternary (BitNet) models. CPU runtimes. | Shortlist with reasons | 2.9, 2.10 |
| 2.9 | How fast is each candidate on a CPU, and how fast would it be on the target? | CPU-only benchmark at 8 threads: prompt processing, generation, load time, memory, prefix-cache gain. Calibrate to an 8-core x86 desktop with published figures. | Seconds per decision on the target | Model, Runtime |
| 2.10 | Which model best separates attacks from look-alikes with a neutral prompt? | One fixed prompt with no dataset-specific examples, structured output, every model on the same cases. Two rounds: every candidate on a quick set (all attack cases, a sample of benign ones), then the leaders on the full dev and holdout cases. Eval-wave cases stay unseen. | Per-model scorecard | Model |
| 2.11 | What do we choose, over what, and why? | Decision matrix against the criteria; risks; findings note. | Proposed Model and Runtime decisions; Goal 2 and Q-1 | Decisions card |

## Decision criteria (fixed before measuring)

**Model**

- Gates: about 8B parameters or fewer; estimated decision time on the target within the
  latency budget from 2.3 for a 95th-percentile case; model plus context memory at most
  8 GB, leaving headroom in 16 GB; at least 99% valid structured verdicts.
- Ranked by: (1) attacks flagged at their earliest case, (2) false alarms on benign
  cases, (3) speed margin on the target, (4) explanation quality on a spot check,
  (5) licence and availability.

**Runtime**

- Gates: installs on Windows x64 under Python 3.10+ without a compiler (a prebuilt
  wheel or binary); runs CPU-only; supports the chosen model.
- Ranked by: (1) speed on an x86 CPU, (2) reuse of a fixed prompt prefix,
  (3) constrained (JSON) output, (4) control of threads and memory, (5) a setup the
  graders can follow in a few steps.

## Done when

The Goal 2 attack types are filled in and Q-1 is closed, the Model and Runtime
decisions are proposed with evidence and approved, and the findings note is committed.

## Risks and assumptions

| Risk | Handling |
|---|---|
| The Mac is not the target: Apple CPUs are faster per core and have more memory bandwidth | Calibrate with published x86 figures and a safety factor; the detector measures its own speed at start-up; verify on Windows x64 in stage 5, or earlier if a machine is available (Q-4). |
| The hidden waves hold attack types absent from training (w01's RDP hop has no training example) | Prefer general security reasoning over memorised patterns; neutral prompt in 2.10; leave-one-attack-type-out test in stage 4. |
| Bursts of cases outrun the model | Measure bursts in 2.5; queue priorities in stage 3. |
| The evaluator cannot score its own benign eval waves | Already worked around with a fixed answer key (Q-3). |
| A non-generative model (for example the Laya encoder) may not count as "the SLM" that must make detection decisions | Such a model may only rank cases for the SLM, never decide, unless the graders confirm otherwise. |
