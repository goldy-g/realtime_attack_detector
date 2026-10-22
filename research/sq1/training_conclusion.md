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
