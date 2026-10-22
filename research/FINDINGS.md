# Research findings (stage 2)

Every number below comes from a script in this folder; its output file is named
next to it. The plan, questions and decision criteria are in [README.md](README.md).

## Signal track

### 2.2 Attack types and alert points · `attack_catalogue.py` → `out/attack_catalogue.md`

27 labelled attacks: 24 on 22 training days, 3 in the eval waves. Every alert
point is a process start (25) or an outbound connection (2). Six types, named by
how the attacker first gets code running:

| Type | Attacks | Alert point |
|---|---|---|
| Remote WMI starts a hidden, encoded PowerShell (Empire agent) | 21 (20 training, w03) | `wmiprvse.exe` → `powershell.exe -noP -sta -w 1 -enc …` |
| Phishing Word document runs a hidden PowerShell download cradle | 2 (host-339f, w02) | `winword.exe` → `cmd.exe /k powershell.exe -NoP -sta -NonI -W Hidden … WebClient …` |
| Downloaded batch file starts a hidden, encoded PowerShell | 1 (host-efdb) | `cmd.exe` (running `Downloads\runme.bat`) → `powershell -noP -sta -w 1 -enc …` |
| Trojanised updater runs a random-named program from Temp | 1 (host-f3ac) | `gup.exe` (Notepad++ updater) → `…\AppData\Local\Temp\cKfGW.exe` |
| Second payload, run with elevation, calls a bare IP address | 1 (host-f3ac) | `update.exe` → `53.192.68.50:8080` (connection) |
| RDP hop: an admin session arrives by RDP and moves on by RDP | 1 (w01) | `mstsc.exe` → `10.47.35.74:3389` (connection) |

Many attacks go on to later stages after the alert point: credential theft in
memory, process listing, domain discovery, UAC bypass, WMI persistence, a plink
reverse tunnel, a new local admin account, RDP logons.

Correction to the plan page: WMI starting PowerShell is the alert point of
**20** of the 24 training attacks, not 17.

**What the hidden waves may hold** (the published OpTC red-team record,
`OpTCRedTeamGroundTruth.pdf` in github.com/FiveDirections/OpTC-data, summarised
by a research agent). The red team ran three scenarios: plain PowerShell Empire,
custom PowerShell Empire, and a malicious software upgrade that installed
Meterpreter. Techniques in that record but absent from or rare in our labels:
Meterpreter from the trojanised update, UAC bypass variants (eventvwr, fodhelper,
the `HKCU\Environment\windir` trick), WMI event-subscription persistence firing
later (WMI starting PowerShell again), Mimikatz and LSASS injection, a new local
admin account, RDP through a plink SSH tunnel, netcat exfiltration to unusual
ports, automated domain enumeration (DeathStar), timestomping. The corrected
labels' authors also report attacker activity the original record never
documented, so "not in the record" does not mean benign.

### 2.3 Attack tempo and the latency budget · `attack_tempo.py` → `out/attack_tempo.md`

The second malicious event arrives 10–60 ms after the alert point in 24 of 25
attack waves: the new process's own thread and library events. The timeliness
an alert would earn, by delay after the alert point (25 attack waves):

| Delay | 0.5 s | 1 s | 2 s | 3 s | 5 s | 10 s | 20 s | 30 s | 60 s |
|---|---|---|---|---|---|---|---|---|---|
| Mean timeliness | 0.93 | 0.91 | 0.90 | 0.86 | 0.80 | 0.63 | 0.50 | 0.42 | 0.27 |

**Budget:** a verdict within 2 s keeps about 0.90; within 5 s about 0.80. Past
10 s the score falls fast. The decision path (case → verdict → alert) has to
fit in 2–5 s on the target CPU; the explanation can follow later.

### 2.4 Benign look-alikes · `benign_lookalikes.py` → `out/benign_lookalikes.md`

- The training attacks' own markers never occur in benign activity across all
  62 days: PowerShell with a hidden window or an encoded command (22 of 24 alert
  points, 0 benign events), WMI starting PowerShell (20 of 24, 0 benign), an
  Office program starting a shell (0 benign). The training attacks are easy to
  separate; the risk is the attack types the training set lacks.
- Look-alikes of other techniques are common: outbound RDP from `mstsc.exe`
  (14 benign events on 2 machines), connections to public addresses (59 of 62
  machines, browsers), "recon" commands (769 events on 50 machines: `netstat -n`
  and `tasklist` loops from the testbed's automation), scheduled-task creation
  (2,654 events on 61 machines: the testbed's `kickoff.py` auto-login task),
  Firefox driven by `geckodriver`, `dismhost.exe` run from Temp by Disk Cleanup.
- The sensor sometimes names the wrong parent because Windows reuses process IDs
  (`lsass.exe` "started by" `ping.exe`, `schtasks.exe` by `bcdedit.exe`). An odd
  parent alone is weak evidence.
- Excused activity (attacker-related, outside the labels) exists only on the
  three attack days: 33 chains and 6 actors; w02 has one excused actor.

### 2.5 Triage volume and coverage · `triage_sim.py` → `out/triage_sim.md`

Rules replayed on the 62 validation waves and the 7 eval waves, each against
the wave's own warm-up hour:

| Rule | Benign waves: cases per minute (median · p95 · max) | Attack waves: per minute | Largest burst in 10 s | Alert points kept |
|---|---|---|---|---|
| V1 new parent→child pair | 0 · 0.76 · 0.96 | 0.89 median | 10 | 24 of 25 |
| V2 V1 + new process→port outbound connection | 0 · 1.11 · 1.93 | 3.3 median | 14 | 25 of 25 |
| V3 V2 minus pairs common on ≥3 other machines | 0 · 0 · 0 | 2.7 median | 8 | 24 of 25 |

- V2 keeps every alert point and leaves the model about one case a minute on a
  normal machine and 3–4 during an attack, with bursts of up to 14 in 10 s.
- The fleet baseline (V3) removes nearly every benign case but loses one alert
  point: `cmd.exe` → `powershell.exe` is a common pair. Use fleet rarity to
  rank the queue, not to drop cases.
- Best timeliness reachable if the model answers at the first malicious case:
  1.00 instantly, 0.89 after 2 s, 0.80 after 5 s.
- New-port connections from `svchost.exe` on ephemeral UDP ports are noise.

### 2.6 Case format and token budget · `cases.py` → `out/cases.md`, `bench_speed.py`

- Case format v0: the event, its process ancestry, the decoded
  `-EncodedCommand` text, baseline facts (new on this machine; how many other
  machines have it), and the machine's notable activity in the last 2 minutes.
- Measured with real tokenizers: **420–570 tokens per case**, plus a
  **200-token system prompt** that the server keeps cached between calls.
  Character counts underestimate tokens: paths and base64 tokenize poorly.
- Reading the case is about 95% of a decision's time (Qwen3.5-4B, 8 CPU
  threads: 5.2 s of 5.6 s). Cases should shrink to 150–250 tokens: keep only
  activity related to the process tree, shorten paths, never send raw base64.

### 2.7 Labelled case set · `cases.py` → `data/cache/research/cases.jsonl`

759 cases: every V2 triage case from the 62 validation waves and 7 eval waves;
372 extra windows (one-hour warm-up, five minutes live) sampled from all 62
training days for realistic negatives; and one probe window for each training
attack that has no validation wave (an earlier attack on the same machine was
still running in its warm-up hour). Each case uses only events delivered up to
that moment, and each malicious case lists the malicious events already
delivered: the evidence an explanation should cite.

| Split | Malicious | Context | Excused | Benign | Alert points |
|---|---|---|---|---|---|
| dev (waves · windows · probes) | 63 · 7 · 0 | 41 · 3 · 0 | 0 | 71 · 328 · 10 | 15 · 1 · 0 |
| holdout (waves · windows · probes) | 38 · 8 · 1 | 15 · 0 · 3 | 2 | 12 · 96 · 5 | 7 · 1 · 1 |
| eval (waves, kept unseen) | 14 | 33 | 0 | 9 | 3 |

Only four non-WMI attacks fall in dev and holdout (the phishing document, the
batch file, the Notepad++ updater, the update.exe payload), so the test of
attack types the training set barely covers is thin; the two eval attacks of
other types (phishing, RDP hop) stay unseen for the final check. The probe for
the second WMI attack on host-339f yields no case: its warm-up hour already
held WMI starting PowerShell from the first attack, which graded waves never do.

## Model track

### 2.8 Shortlist · `candidates.py`

The newest small releases, checked on each lab's Hugging Face listing on
2026-10-22:

| Family | Newest up to ~8B | Released | Tested |
|---|---|---|---|
| Qwen | Qwen3.5 2B, 4B (9B is over the limit; 3.6 and 3.8 come only in large sizes) | Feb 2026 | 2B, 4B |
| Google | Gemma 4 E2B, E4B (quantisation-aware Q4_0 from Google) | Mar 2026 | E2B, E4B |
| IBM | Granite 4.2 3B, 8B | Aug 2026 | both |
| Liquid | LFM2.5 1.2B, 2.6B, 8B-A1B (mixture of experts) | 2026 | all three |
| NVIDIA | Nemotron-Labs Dory 1.0 4B | 16 Oct 2026 | not runnable: llama.cpp build 11669 does not know its architecture |
| Mistral | Ministral 3 3B, 8B | Dec 2025 | both |
| Cisco | Foundation-Sec 1.1 8B Instruct (security-tuned Llama 3.1) | Nov 2025 | yes |
| Microsoft, Meta, OpenAI | nothing newer than Phi-4-mini, Llama 3.2; gpt-oss-20b is over the limit | – | – |

Previous-generation reference points: Qwen3-4B-Instruct-2507, Qwen3-1.7B.

Not tested, with reasons: Nemotron-3-Nano-4B (March 2026, Mamba2 hybrid) and
Granite 4.1 3B / 8B (April 2026, no thinking mode) are the same size classes as
tested models that miss the speed gate below; Granite-4.0-H-Tiny (7B, 1B
active) is superseded by LFM2.5-8B-A1B as the small mixture of experts; Qwen3.5-9B
is over the size limit. Licences: Apache-2.0 for Qwen3.5, Gemma 4, Granite and
Ministral 3; Llama 3.1 licence for Foundation-Sec; Liquid's LFM licence limits
commercial use to companies under $10M revenue.

**Runtimes on Windows x64** (shortlist agent; sources below):

| Runtime | Install without a compiler | Our models | Prefix cache | Constrained output | Risk |
|---|---|---|---|---|---|
| llama.cpp `llama-server` | Yes: `llama-b<build>-bin-win-cpu-x64.zip` (24 MB), picks AVX2/AVX-512 at runtime | All of them, newest first | Yes (hybrid and sliding-window models need checkpoints) | GBNF grammar, JSON schema | A subprocess to manage; default port changed in v0.7.0, always pass `--port` |
| llama-cpp-python 0.3.36 | Yes, from its own CPU wheel index (one wheel for Python 3.10–3.12) | Bundles llama.cpp from late September 2026 | Yes; hybrid models need save/load state | JSON schema | Lags llama.cpp; instruction-set targets of the Windows wheel undocumented |
| ONNX Runtime GenAI 0.18 | Yes, but **no Python 3.10 wheel** | Needs conversion with torch; ready-made only for Phi-4-mini and Qwen3-8B | System-prompt rewind, batch 1 | Guidance (JSON schema, regex) | Python 3.10 graders could not install it |
| OpenVINO GenAI 2026.4 | Yes, Python 3.10–3.14 | Ready int4 builds of Qwen3.5-4B, Gemma 4 E4B, LFM2.5-8B-A1B | On by default | JSON schema | Speed on AMD CPUs unverified |

**Other architectures**, judged against the measured workload (a long prompt
to read, a 5–20-token verdict to write):

- *Mixture of experts and hybrid decoders* (LFM2.5-8B-A1B, Qwen3.5, Granite
  4.2, LFM2.5): they cut the cost of reading the prompt, which dominates. In
  the shortlist.
- *Encoder decision models* (Laya: ModernBERT-large plus a decision head, 421M
  parameters, released 2026-09-18): one pass, calibrated probabilities, 193–464 ms
  per call on a CPU by its card, 512-token input. It cannot write explanations;
  its own card says base checkpoints are near chance on zero-shot typed decisions
  (0.36) and need fine-tuning; and an encoder classifier may not count as "the
  SLM" that must decide. Role: at most a ranker in front of the SLM (Q-5). Its
  zero-shot ranking power is measured in 2.10.
- *Diffusion language models* (LLaDA, Liquid d1) and *speculative or
  multi-token decoding*: they speed up writing, not reading, so they would help
  only the explanation step.
- *Ternary (BitNet) models*: fast on CPUs but weaker than 4-bit dense models of
  the same size, and they need their own runtime. Not pursued.

### 2.9 CPU speed · `bench_speed.py` → `out/bench_speed.md`

Apple M5 Pro CPU only (no Metal, no Accelerate device), 8 threads, llama.cpp
build 11669, Q4 files. A decision is a verdict-only JSON reply on a real case
(400–600 tokens in format v0) after the system prompt is cached.

| Model | Params (B) | Prompt reading (tokens/s) | Writing (tokens/s) | Decision, warm (s) | Memory at 8K context (GB) |
|---|---|---|---|---|---|
| LFM2.5-1.2B | 1.2 | 307 | 147 | 1.95 | 1.7 |
| Gemma-4-E2B | 4.6 (2 effective) | 344 | 97 | 2.01 | 5.1 |
| Qwen3.5-2B | 1.9 | 222 | 72 | 2.55 | 3.2 |
| Gemma-4-E4B | 7.5 (4 effective) | 178 | 51 | 3.59 | 8.4 |
| LFM2.5-8B-A1B | 8.5 (mixture of experts) | 163 | 90 | 3.75 | 8.6 |
| LFM2.5-2.6B | 2.7 | 132 | 64 | 4.56 | 3.6 |
| Granite-4.2-3B | 3.7 | 100 | 51 | 4.94 | 5.0 |
| Ministral-3-3B | 3.4 | 97 | 51 | 6.00 | 5.5 |
| Qwen3.5-4B | 4.2 | 93 | 34 | 6.42 | 6.6 |
| Foundation-Sec-1.1-8B | 8.0 | 43 | 22 | 10.33 | 8.5 |
| Granite-4.2-8B | 8.8 | 37 | 19 | 12.11 | 9.1 |
| Ministral-3-8B | 8.5 | 41 | 23 | 13.31 | 7.9 |
| *Qwen3-1.7B (previous generation)* | 1.7 | 442 | 101 | 1.67 | 4.9 |
| *Qwen3-4B-2507 (previous generation)* | 4.0 | 80 | 43 | 7.39 | 6.6 |

- Reading the case dominates every decision; writing a 10-token verdict takes
  0.1–0.5 s. Prompt-reading speed is the number that matters.
- Dense 8B models need 10–13 s per decision on the Mac CPU, more on the target:
  far outside the 2–5 s budget. A mixture of experts (LFM2.5-8B-A1B) or Gemma 4's
  per-layer embeddings bring 8B-class files down to 3.6–3.8 s.
- The cached system prompt is reused (201 tokens skipped on every warm call).
- Memory is well above the file size: llama.cpp keeps a repacked copy of the
  weights for the CPU kernels next to the mapped file, plus the 8K-token cache.
  The 8B-class files sit at 7.9–9.1 GB, at the edge of the 8 GB gate; a 4K
  context and smaller batches should cut this, to verify when building.
- Not runnable: Nemotron-Labs-Dory-4B (unknown architecture in this llama.cpp
  build). Granite 4.2 fails with a JSON-schema grammar while the server's
  thinking budget is set to 0; an explicit grammar without that flag works, and
  every model now runs that way.

**Prefix cache check:** warm calls reused the ~200-token system prompt for every
model except the LFM2.5 family (75–103 tokens reused: their hybrid layers need
cache checkpoints), so LFM2.5 timings include re-reading most of the system
prompt and would be about 20% lower with checkpoints. LFM2.5-2.6B always
reasons: its tokens went into a hidden reasoning block and no verdict came out
within the token limit, so it cannot meet the budget.

**Translation to the target.** Published llama.cpp figures for x86 CPUs
(shortlist agent): a 12-core Ryzen AI 9 HX 370 reads Ministral-3-3B Q4_K_M
prompts at 191 tokens/s and writes at 32 (our Mac CPU, 8 threads: 97 and 51);
Ministral-3-8B 82 and 15 (Mac: 41 and 23); Qwen3-1.7B Q8_0 354 and 37 (Mac: 442
and 101). A Core Ultra 7 355 laptop runs Llama-3.1-8B Q4_K_M at 26 and 7 (Mac,
same architecture via Foundation-Sec: 43 and 22). Apple CPUs are relatively slow
on Q4_K prompt reading and fast at writing, so the factor depends on the machine:

| Scenario | Prompt reading vs Mac CPU | Writing vs Mac CPU | Fits |
|---|---|---|---|
| Typical: modern 8-core desktop or laptop | about the same | 1.7× slower | Zen 4/5, recent Intel |
| Conservative: older chip, or 8 virtual CPUs on 4 physical cores | 2× slower | 3× slower | Cloud VMs, older desktops |

The speed gate uses the conservative scenario and a compact case (250 tokens).
The real figure gets measured on Windows in stage 5 (Q-4), and the detector
should time itself at start-up and adapt.

**Memory at deployment settings:** Gemma-4-E4B uses 7.1 GB after one call at an
8K context and 6.9 GB at 4K with smaller batches (8.4 GB after the full
benchmark); the 8B-class files sit at the 8 GB gate.

### 2.10 Accuracy on the case set · `score_models.py` → `out/score_models_quick.md`, `out/score_models_quickv1.md`

Quick set: 354 dev and holdout cases (117 malicious from 25 attacks, 62 context,
173 benign), eval cases unseen. Temperature 0, the verdict forced into JSON by a
grammar, no reasoning: the interface the detector needs. "First case" means the
attack's earliest malicious case was flagged, which is what timeliness rewards.

**Round 1, neutral prompt (v0), all runnable models:**

| Model | Attacks flagged at first case | Other attack types | Benign cases flagged | AUC |
|---|---|---|---|---|
| **Gemma-4-E4B** | 23/25 | 2/4 | **14/173 (8%)** | **0.909** |
| Ministral-3-8B | 23/25 | 3/4 | 41/173 (24%) | 0.837 |
| Gemma-4-E2B | 18/25 | 2/4 | 36/173 (21%) | 0.808 |
| Granite-4.2-8B | 25/25 | 4/4 | 138/173 (80%) | 0.739 |
| Qwen3.5-4B | 23/25 | 2/4 | 80/173 (46%) | 0.713 |
| Qwen3-4B-2507 (previous generation) | 23/25 | 2/4 | 35/173 (20%) | 0.696 |
| Ministral-3-3B | 6/25 | 1/4 | 9/173 | 0.655 |
| Foundation-Sec-1.1-8B | 0/25 | 2/4 | 6/173 | 0.580 |
| Qwen3-1.7B (previous generation) | 24/25 | 3/4 | 161/173 (93%) | 0.572 |
| Qwen3.5-2B | 24/25 | 3/4 | 107/173 (62%) | 0.565 |
| Granite-4.2-3B | 1/25 | 2/4 | 0/173 | 0.531 |
| LFM2.5-8B-A1B | 25/25 | 4/4 | 173/173 (100%) | 0.509 |
| LFM2.5-1.2B | 0/25 | 0/4 | 0/173 | 0.500 |
| LFM2.5-2.6B | no valid verdict (always reasons) | – | – | – |

- Most models collapse to one answer: "attack" for everything (LFM2.5-8B-A1B,
  Qwen3-1.7B, Granite-4.2-8B) or "normal" for everything (LFM2.5-1.2B,
  Granite-4.2-3B, Foundation-Sec). The LFM2.5 family is trained to reason before
  answering and fails when made to answer at once.
- The security-tuned Foundation-Sec-1.1-8B calls nearly everything normal: domain
  tuning did not transfer to judging single telemetry events.
- Gemma-4-E4B's two misses are both the "malicious upgrade" type (the Notepad++
  updater running a random-named program from Temp; a fresh download calling a
  bare IP on port 8080). Its false alarms are mostly the testbed's own automation
  and `svchost.exe` talking to domain infrastructure.

**Robustness check, prompt v1 (general analyst heuristics, `prompt_v1.py`), the
four leading candidates.** v1 was written after the round-1 error analysis, so its
dev and holdout scores are optimistic; it only tests whether the ranking holds:

| Model | Attacks at first case | Other types | Benign flagged | AUC (v0 → v1) |
|---|---|---|---|---|
| **Gemma-4-E4B** | 24/25 | 3/4 | **12/173 (7%)** | 0.909 → **0.956** |
| Gemma-4-E2B | 24/25 | 3/4 | 19/173 (11%) | 0.808 → 0.942 |
| Qwen3.5-4B | 24/25 | 3/4 | 23/173 (13%) | 0.713 → 0.902 |
| Qwen3.5-2B | 24/25 | 3/4 | 114/173 (66%) | 0.565 → 0.616 |

The ranking holds: Gemma-4-E4B is first under both prompts. The prompt matters as
much as the model (Qwen3.5-4B halves its false alarms), so prompt work in stages
3–4 is worth real time. Gemma-4-E2B nearly matches E4B once prompted well, at
half the cost per decision.

**Full dev and holdout set, Gemma-4-E4B, prompt v0, with a one-sentence reason**
(703 cases, `out/score_models_full.md`): 23 of 25 attacks flagged at their first
case; 47 of 522 benign cases flagged (9%), of which 7 in the 62 validation waves
and 36 in the 424 extra windows; AUC 0.913; 1 invalid reply in 703.

Explanation spot check (the reasons): on attacks they are specific and right
("Execution of an encoded PowerShell command by wmiprvse.exe … is highly
suspicious"). Two flaws to fix in stage 3: the model reads the domain
`SYSTEMIACOM\user` as the SYSTEM account, and on false alarms it blames the event
for unrelated scripts listed under recent activity. Both argue for compact,
chain-only context and explanations built from checked fields.

**Laya, zero-shot** (`score_laya.py` → `out/score_laya.md`, CPU): AUC 0.76 for the
yes/no question and 0.79 for the attack-or-normal choice. At its default
threshold it calls 153 of 173 benign cases attacks (88% false alarms). 0.75 s per
case. Not usable as a decider without fine-tuning; as a ranker it is weaker than
fleet rarity, which costs nothing. Not pursued.

### 2.11 Proposed decisions · `decide.py` → `out/decide.md`

Gates fixed in README.md: decision within the budget on a weak target, memory at
most 8 GB, at least 99% valid verdicts. Seven models pass the speed gate on a
weak target with compact cases; of those, only the Gemma 4 pair also separates
attacks from normal activity.

**Model (proposed): Gemma 4 E4B-it**, Google's quantisation-aware Q4_0 file
`gemma-4-E4B_q4_0-it.gguf` (5.15 GB, `google/gemma-4-E4B-it-qat-q4_0-gguf`),
thinking off, Apache-2.0.
- Best separation under both prompts (AUC 0.909 and 0.956), 23–24 of 25 attacks
  flagged at their first case, 7–8% of benign cases flagged.
- An estimated 1.7 s per decision on a typical 8-core target and 3.4 s on a weak
  one for a 250-token case: mean timeliness 0.90 and 0.85.
- Memory 6.9 GB with a 4K context after one call, up to 8.4 GB at 8K after many:
  at the edge of the 8 GB gate, well inside 16 GB. Plan for a 4K context.
- Alternatives: **Gemma 4 E2B** (same family and prompt format, AUC 0.942 with
  v1, about half the cost; the fallback if the target proves slow); Qwen3.5-4B
  (close with v1, but 6.3 s on a weak target); dense 8B models (13–15 s); the
  LFM2.5 family and Laya (see above); Nemotron-Labs-Dory (not runnable yet).
- Risks: the malicious-upgrade type is its weak spot (prompt work, the
  leave-one-attack-type-out test in stage 4); real target speed unknown (time
  itself at start-up and switch to E2B if needed; Windows test, Q-4).

**Runtime (proposed): llama.cpp `llama-server`**, the official Windows CPU build
(`llama-b<build>-bin-win-cpu-x64.zip`, pinned to the build we measured), started
by the detector as a subprocess on a free local port; the Python side needs only
the standard library.
- No compiler and no Python wheel to break; picks AVX2 or AVX-512 at runtime; runs
  every candidate (Gemma 4 included); prefix cache measured working for Gemma 4
  (about 200 tokens reused per call); GBNF grammar gives the verdict-first JSON.
- Alternatives: llama-cpp-python (in-process, but trails llama.cpp and its Windows
  wheel's CPU targets are undocumented); OpenVINO GenAI (ready Gemma 4 E4B int4
  build, worth a timing on Windows if llama.cpp is slow); ONNX Runtime GenAI (no
  Python 3.10 wheel, needs conversion).
- Risks: a subprocess to start, health-check and stop with the detector; pass
  `--port` (the default changed in v0.7.0); unsigned binaries.

**Inputs for the Detection approach (stage 3):** V2 triage with fleet rarity as the
queue order; cases cut to about 250 tokens; a verdict-only first call, then the
explanation; the decoded command text, never raw base64.

## Sources

External facts, checked on 2026-10-22. Everything else in this note is measured by the scripts in this folder.

- OpTC red-team record: [OpTCRedTeamGroundTruth.pdf](https://raw.githubusercontent.com/FiveDirections/OpTC-data/master/OpTCRedTeamGroundTruth.pdf), [errata](https://github.com/FiveDirections/OpTC-data/blob/master/errata.md); corrected labels: [correctedoptc.inria.fr](https://correctedoptc.inria.fr), [doi:10.57745/UXCWOC](https://doi.org/10.57745/UXCWOC), [CSET 2025 slides](https://cset25.isi.edu/slides/cset2025-slides-optc.pdf).
- Newest releases per lab: each lab's Hugging Face listing, e.g. [Qwen](https://huggingface.co/api/models?author=Qwen&sort=createdAt&direction=-1&limit=60), [Google](https://huggingface.co/api/models?author=google&search=gemma&sort=createdAt&direction=-1&limit=60), [IBM](https://huggingface.co/ibm-granite), [Liquid](https://huggingface.co/LiquidAI), [NVIDIA](https://huggingface.co/nvidia), [Mistral](https://huggingface.co/mistralai), [Cisco](https://huggingface.co/fdtn-ai).
- Model cards: [Qwen3.5-4B](https://huggingface.co/Qwen/Qwen3.5-4B), [Gemma 4 E4B](https://huggingface.co/google/gemma-4-E4B-it), [Gemma 4 QAT GGUF](https://huggingface.co/google/gemma-4-E4B-it-qat-q4_0-gguf), [Granite 4.2 8B](https://huggingface.co/ibm-granite/granite-4.2-8b), [LFM2.5-8B-A1B](https://huggingface.co/LiquidAI/LFM2.5-8B-A1B), [Ministral 3 8B](https://huggingface.co/mistralai/Ministral-3-8B-Instruct-2512), [Foundation-Sec 1.1 8B](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct), [Nemotron-Labs Dory](https://huggingface.co/nvidia/NVIDIA-Nemotron-Labs-Dory1.0-4B-BF16), [Laya](https://huggingface.co/convaiinnovations/laya).
- Runtimes: [llama.cpp releases](https://github.com/ggml-org/llama.cpp/releases), [llama-server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md), [llama-cpp-python CPU wheels](https://abetlen.github.io/llama-cpp-python/whl/cpu/llama-cpp-python/), [onnxruntime-genai on PyPI](https://pypi.org/project/onnxruntime-genai/), [openvino-genai on PyPI](https://pypi.org/project/openvino-genai/).
- x86 CPU figures: [Framework forum, Ryzen AI 9 HX 370](https://community.frame.work/t/framework-13-ryzen-ai-linux-distro-llm/69069?page=2), [LocalScore, Core Ultra 7 355](https://www.localscore.ai/result/4300), [ik_llama.cpp discussion #164](https://github.com/ikawrakow/ik_llama.cpp/discussions/164), [mgroeber, Ryzen AI 7 350](https://www.mgroeber.de/benchmarking-llamacpp-on-legacy-hardware-2.html).
