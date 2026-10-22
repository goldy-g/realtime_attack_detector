# SQ-1 follow-up · Can the trained experts be trained better?

Question: does better cleaning, feature engineering or a better model let a trained expert beat
the SLM? I ran 14 training setups (`research/sq1/train_better.py`), each adding one change, under
the same tests as `sq1_results.md`:

1. Train on dev.
2. Raise above the highest score any dev benign case got.
3. Check the 9 holdout attacks at their first case.
4. Leave each attack type out of training and check that type.

## Answer

**No. Better training improves how the unseen attack types rank, but no setup beats the SLM as an
alert raiser, and none catches the updater.** The limit is the data, not the training.

- **Dev holds three attack types, and one, WMI starting hidden PowerShell, is 42 of its 48
  attack cases after cleaning.** Any model separates all of them from benign activity with "it
  is PowerShell". General concepts that fit just as well add nothing in training, so the model
  never learns to weight them (G2 scores the same as G1). Examples: an application that never
  starts code starts a shell; a process a few seconds old calls a public address. This is
  shortcut learning, and more features cannot fix it while every attack example shares the
  shortcut.
- **Features suggested by the holdout attacks get no weight at all** (G3 = G2, G6 = G5). No dev
  attack has them, and a model cannot learn the weight of a pattern it has never seen labelled.
  This is why the updater stays missed: no dev attack looks anything like it.
- **Removing the shortcut helps ranking, not alerting.** G5 takes away program names and single
  PowerShell flags. Then only 1 of the 113 holdout benign cases ranks above the updater, against
  7 before. But the updater scores 0.033 against a threshold of 0.235: the model still calls it
  normal; it just calls the benign cases more normal.
- **Cleaning helped the text model most (N1).** N1 combines four changes:
  - it keeps only the event's own lines, not the two minutes of activity around it;
  - it drops base64 blobs;
  - it drops the 22 "malicious" cases that are svchost / lsass network traffic;
  - it weights attack types equally.

  It catches the payload connection without having seen that type: 8 of 9, the SLM's own result,
  and the same as the SLM on every held-out type. But the catch is fragile, and it adds a false
  alarm the SLM does not raise:
  - the payload case scores 0.274 against a threshold of 0.264;
  - with an honest threshold (out-of-fold, 0.41) the catch disappears (N1H: 7 of 9);
  - its false alarm is the testbed's own `powershell -c "Get-Service lwabeat"`, the same
    "PowerShell means attack" shortcut.
- **Monotonic boosting and honest thresholds made things worse.** With monotonic boosting (G4),
  the unseen types rank lower. The honest-threshold setups (·H) show that the in-sample threshold
  is optimistic: each loses a catch.
- **As pure rankers, every model separates holdout attacks from benign cases better than the
  SLM** (AUC 0.980–0.998 against 0.968 for prompt v1, plumbing cases left out). But that holdout is mostly the WMI
  type they were trained on, so it does not turn into catches.

## What would help

- **More attack types, not more cases.** More windows from the dev days would add benign variety
  and more WMI cases, but no new attack type: the dev days hold only those three. Training the
  final detector's experts on dev + holdout is legitimate, since holdout exists only to measure,
  and it adds the updater and the payload connection. After that, only leave-one-type-out and the
  eval waves can measure generalisation.
- **The updater is the SLM's miss, so the lever is the prompt.** A program starting a
  randomly named executable from a user's Temp folder is general security knowledge a prompt can
  carry. No model trained on these labels will learn it.
- **Variant A gains nothing either.** As queue rankers the trained models already tie the rule
  (`sq1_results.md`), so better training buys no time there.

## Results

Holdout: 9 attacks (7 WMI PowerShell, the updater, the payload connection) and 113 benign cases. "Benign above" = holdout benign cases scoring at or above that attack's first case: the false alarms it would cost to catch it by lowering the threshold. Leave-one-type-out: retrained on dev without the type, then T's attacks in dev + holdout at their first case. SLM rows: Gemma 4 E4B with prompt v1 (benign counted over the 29 holdout benign cases of the quick set) and prompt v0 (all 113). "Plumbing" = the svchost / lsass network cases labelled malicious, left out of the AUC so cleaned and uncleaned setups compare fairly.

| Setup | What changed | Holdout caught (of 9) | Holdout false alarms, of 113 (of them also flagged by SLM v0) | AUC without plumbing | Benign above: updater · payload | Leave-one-type-out caught: batch · office · payload_flow · updater · wmi_ps | Leave-one-type-out false alarms (worst T) | Threshold |
|---|---|---|---|---|---|---|---|---|
| SLM v1 | Gemma 4 E4B, prompt v1 | 8/9 | 1/29 | 0.968 | - · - | 1/1 · 1/1 · 1/1 · 0/1 · 21/21 | - | - |
| SLM v0 | Gemma 4 E4B, prompt v0 | 7/9 | 9/113 | 0.939 | - · - | 1/1 · 1/1 · 0/1 · 0/1 · 21/21 | - | - |
| G0 | gbt as in run.py | 7/9 (missed: payload_flow, updater) | 0 (0) | 0.996 | 7 · 5 | 1/1 · 1/1 · 0/1 · 0/1 · 21/21 | 0 | 0.61 |
| G1 | + cleaning, attack types weighted equally | 7/9 (missed: payload_flow, updater) | 1 (1) | 0.995 | 8 · 8 | 1/1 · 1/1 · 0/1 · 0/1 · 21/21 | 1 | 0.05 |
| G2 | + concept features from the dev attacks | 7/9 (missed: payload_flow, updater) | 1 (1) | 0.995 | 8 · 8 | 1/1 · 1/1 · 0/1 · 0/1 · 21/21 | 1 | 0.05 |
| G3 | + concept features from the holdout attacks (hindsight) | 7/9 (missed: payload_flow, updater) | 1 (1) | 0.995 | 8 · 8 | 1/1 · 1/1 · 0/1 · 0/1 · 21/21 | 1 | 0.05 |
| G4 | G3, monotonic boosting | 7/9 (missed: payload_flow, updater) | 0 (0) | 0.993 | 14 · 14 | 1/1 · 1/1 · 0/1 · 0/1 · 21/21 | 0 | 0.14 |
| G5 | concepts only, no program names | 7/9 (missed: payload_flow, updater) | 0 (0) | 0.997 | 1 · 9 | 1/1 · 1/1 · 0/1 · 0/1 · 21/21 | 0 | 0.23 |
| G6 | G5 + hindsight concepts | 7/9 (missed: payload_flow, updater) | 0 (0) | 0.997 | 1 · 9 | 1/1 · 1/1 · 0/1 · 0/1 · 21/21 | 0 | 0.23 |
| N0 | ngram as in run.py | 7/9 (missed: payload_flow, updater) | 0 (0) | 0.990 | 22 · 5 | 0/1 · 0/1 · 0/1 · 0/1 · 21/21 | 0 | 0.74 |
| N1 | ngram on cleaned text + cleaning | 8/9 (missed: updater) | 1 (0) | 0.998 | 3 · 1 | 1/1 · 1/1 · 1/1 · 0/1 · 21/21 | 1 | 0.26 |
| N2 | N1's text cleaning alone | 7/9 (missed: payload_flow, updater) | 0 (0) | 0.980 | 40 · 11 | 1/1 · 0/1 · 0/1 · 0/1 · 21/21 | 1 | 0.77 |
| N3 | G1's cleaning alone (full text) | 7/9 (missed: payload_flow, updater) | 0 (0) | 0.992 | 20 · 0 | 0/1 · 0/1 · 0/1 · 0/1 · 21/21 | 0 | 0.66 |
| G2H | G2 with an honest (out-of-fold) threshold | 7/9 (missed: payload_flow, updater) | 0 (0) | 0.995 | 8 · 8 | 0/1 · 1/1 · 0/1 · 0/1 · 21/21 | 0 | 0.46 |
| G5H | G5 with an honest (out-of-fold) threshold | 7/9 (missed: payload_flow, updater) | 0 (0) | 0.997 | 1 · 9 | 0/1 · 1/1 · 0/1 · 0/1 · 21/21 | 0 | 0.94 |
| N1H | N1 with an honest (out-of-fold) threshold | 7/9 (missed: payload_flow, updater) | 1 (0) | 0.998 | 3 · 1 | 1/1 · 1/1 · 0/1 · 0/1 · 21/21 | 1 | 0.41 |

Setups that catch at least the SLM's 8 of 9 holdout attacks and match it on every held-out type: **N1**. Of those, setups that would also add no false alarm the SLM does not raise already: **none**.

Cleaning removed 22 of 70 dev attack cases (svchost / lsass network traffic). Dev attack cases by type after cleaning: batch 2, office 4, wmi_ps 42.

