# Real-time attack detection with a small language model

## Assignment

Build a Python detector that receives a Windows machine's security events in real
time, uses a small language model (SLM) to identify attacks, and raises alerts with
explanations and supporting event IDs. 

we have two goals:
1. to detect attacks as early as possible (**real time**)
2. provide clear and correct text output explaining the attack (the reasoning behind the alert, as forensics). **this will be scored as bonus**


We provide the event stream, labelled data and evaluator. The data comes from
**DARPA OpTC**, a Windows network where a professional red team carried out attacks.

**We evaluate you on detection performance (accuracy and latency) but, most importantly,
your approach, reasoning and way of working.**

## Constraints

- **Machine:** Windows 10/11 x64, 8 CPU cores, 16 GB RAM, no GPU. optimize your solution work well on this machines specs.
- **Model:** local SLM, up to about 8B parameters and 8,192 context tokens. No hosted APIs.
  Detection decisions must come from the SLM.
- **Language:** Python 3.10+.

The model, runtime and detection approach are your choice within these limits.

## Provided data

| Location | Contents |
|---|---|
| `data/train/` | 62 labelled machine-days; 22 contain attacks |
| `data/eval/` | 7 evaluation waves and their answer key |
| [data/README.md](data/README.md) | File formats, event fields, labels and reading examples |

The evaluator reads the stream files and passes events to your detector as Python
dictionaries. The answer key is for evaluation, not detector input. Final evaluation
also includes machines and waves not provided here.

## Detector API

The entry point is `MyDetector`, a subclass of `Detector`, in `submission/my_detector.py`.
The interface is defined in [evaluator/detector_interface.py](evaluator/detector_interface.py).

| Method | Called by the evaluator |
|---|---|
| `__init__(train_dir)` | Once, with the training-data directory. Initialization time is measured separately from wave latency. |
| `start_wave(machine, callbacks)` | At the start of each wave, with its machine name and callback handle. |
| `on_live()` | When warm-up ends and real-time delivery starts. |
| `on_event(event)` | For each event, in stream order, during warm-up and live delivery. |

Training-data and warm-up usage are optional. Background processing is supported;
slow `on_event()` calls delay later events.

Alerts and explanations are sent through the wave's callbacks:

```python
alert_id = callbacks.alert(event_id)
if alert_id is not None:
    callbacks.explain(alert_id, explanation_text, relevant_event_ids)
```

`event_id` identifies an already-delivered event. The explanation is plain-language
text with a list of supporting event IDs; it may arrive immediately or later.
Alert time is when the callback arrives, not the event's timestamp.
Each callback handle belongs to one wave. `callbacks.cancelled` signals closure;
later callbacks are ignored.

## Evaluation

A **wave** is one machine's stream:

1. **Warm-up:** one hour of past events, delivered without pacing. No attack starts
   here. Compute is capped at 120 seconds; remaining warm-up events are dropped.
2. **Live:** about 2-11 minutes of events, delivered at their recorded pace.
   If the detector falls behind, it has up to 30 extra seconds to catch up.
   Events still undelivered after that are dropped.
3. **After delivery:** the evaluator waits 10 seconds for alerts, then closes if
   all alerts have explanations or none arrived. Missing explanations extend the
   wait until they arrive, up to five minutes after delivery ends.

The wave can close while model work is still running; callbacks after closure
are ignored. With `--no-explain`, only the ten-second post-stream wait applies.

Commands below are relative to the repository root in PowerShell. The evaluator
does not start a model server; model loading or connection is part of the submission.

**One wave:**
```powershell
python evaluator\evaluate.py --detector submission.my_detector:MyDetector --waves w02
```

**All seven waves, saving the scorecard:**
```powershell
python evaluator\evaluate.py --detector submission.my_detector:MyDetector --set full --report submission\scorecard.json
```

The default is two waves. `--mode instant` removes real-time pacing for debugging
and is not graded. Alerts are saved to `results/alerts.jsonl`; `--out` changes the path.

### Scoring

Each attack has an **alert point**, where the evidence first supports identifying
an attack. An alert on:

- A **malicious event** (attack activity from that point onward) counts as a detection.
- A **context event** (attack activity before that point) is neutral.
- A **benign event** counts as a false alarm, except explicitly excused activity.

Missed attacks count as false negatives. Repeated detections do not earn more
credit; false alarms are counted once per benign chain, or process without a chain.
Earlier detections earn more credit. Late detections can earn partial credit;
a missing explanation does not erase a valid detection.

The scorecard shows overall and per-wave detection counts, precision, recall, F1,
evidence quality, latency, dropped events and errors. Exact rules are in
[evaluator/metrics.py](evaluator/metrics.py).

## Submission

Send a zip of `submission/` containing:

- Your code.
- The model file, or an exact download link and file name.
- `requirements.txt` and setup instructions, including runtime, context size,
  thread count and other model settings.
- A JSON scorecard from a real-time `--set full` run.
- A short README describing your approach, what did not work and known limitations.

The submission must run in this repository without changes to the evaluator.
Afterward, we will spend about an hour discussing the results and improving the detector together.

---

Data: DARPA OpTC, Five Directions / DARPA; corrected release by F. Majorczyk,
B. Pilastre, F. Dijoud (Inria / DGA), doi:10.57745/UXCWOC, CC BY 4.0.
Filtered and anonymized.
