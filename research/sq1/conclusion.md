# SQ-1 · Experts for known behaviours, the SLM for the rest (offline)

Offline, on the labelled case set (dev 16 attacks, holdout 9) with the saved Gemma 4 E4B
verdicts; no model was run. Nine experts were tested:

- five rules behind a router;
- three small trained models, all trained on dev only: a depth-3 decision tree and
  gradient-boosted trees ("gbt") on the rules' named facts, and a character n-gram logistic
  regression ("ngram") on the case text the SLM reads, with account, machine, time and
  address names masked;
- Laya, the zero-shot encoder from 2.10, through its saved scores.

Each was tested as **A, feed and rank** (experts reorder the SLM's queue; the SLM makes every
decision) and **B, raise** (an expert may alert at once, never clear).

## Recommendation

**Adopt A with one expert, `hidden_powershell`; adopt B with that same expert only if Q-5
allows it; drop the other eight.** The SLM already catches every PowerShell-delivered attack
(dev 16/16, holdout 7/7 at the first case), so no expert adds a catch that counts. What an
expert adds is *time*. Today's queue serves cases by fleet rarity then age. The attack's own
case therefore waits behind the attack's earlier lead-up cases, which are just as rare and
arrived first. Ranking the cases the expert flags first lifts mean timeliness from 0.659 to
0.767 on holdout and from 0.783 to 0.892 on dev (1.7 s per verdict). Recall, false alarms and
AUC stay the same by construction. This is safe under any reading of "detection decisions must
come from the SLM".

Under B the same expert alerts as the case arrives, so its attacks score 1.00. The holdout
mean is 0.875; the remaining gap is the updater attack, which no surviving expert sees. It
raises no benign case among the 703. It needs two of four markers (encoded command, hidden
window, -NoProfile, download cradle), so every raise includes at least one of the three that
matched no benign event in all 62 training days (2.4, with that script's own patterns).

`hidden_powershell` survives because it was written from three delivery types (WMI, Office
macro, batch file) and still catches each one when that type is held out. The rules that gained
recall on holdout were written from those very holdout attacks: `updater_temp` (1/1 where the
SLM had 0/1) and `dropped_beacon` (1/1 where prompt v0 had 0/1). The card's updater example
*is* the holdout attack. That gain is not evidence, and leave-one-type-out removes both rules.

## Trained models and Laya

- **As raisers (B), none beats the SLM.** At zero dev false alarms:
  - the tree catches 0 of the 9 holdout attacks at their first case;
  - gbt and ngram catch 7 of 9 each, both missing the updater and the payload connection
    (the SLM with prompt v1 catches the connection);
  - Laya catches 0 of 9. Its threshold has to sit at 0.911, its highest score on a dev benign
    case.

  With each attack type held out of training, ngram and the tree miss the batch and Office
  attacks. gbt catches both but still misses the payload connection. Laya catches 1 of the 21
  WMI attacks.
- **As rankers (A), they add nothing over the rule.** gbt and ngram tie the rule exactly:
  holdout 0.767 and dev 0.892 at 1.7 s, and 0.88 on the WMI attacks when WMI is held out of
  training. On the wave cases it scored, ranking by Laya does almost as well: dev 0.888 against
  0.894 for the rule, holdout 0.753 for both. Its zero-shot AUC, 0.792, is still below plain
  fleet rarity's 0.924 on the same cases; what counts is the order within the attack's burst,
  not the global AUC.

  The rule needs no training data and passes leave-one-type-out. Its reasons can also go into
  the explanation, which a tree path, a probability or n-gram weights cannot.
- **What a text model learns from these 117 attack cases:** ngram's strongest features are
  fragments of the word "powershell". As a ranker it reaches holdout AUC 0.995, but it knows
  little more than "PowerShell means attack", a cruder version of what `hidden_powershell`
  says with reasons.
- **Training them better does not change this** (`sq1_training.md`, 14 setups: cleaning,
  attack types weighted equally, concept features, monotonic boosting, honest thresholds).
  Better training lifts how the unseen types rank, but no setup beats the SLM as a raiser and
  none catches the updater. Dev's attacks are almost all one type, so every model learns "it is
  PowerShell" and gives no weight to patterns no dev attack shows.
- **Not tried: fine-tuning Laya.** It needs PyTorch training on the CPU that is timing the
  detector, and the ngram model suggests what training on these 117 attack cases would teach
  it.

## What this does not measure, and the risks

- **Feeding expert facts into the prompt** (the other half of A) changes SLM verdicts and
  needs SLM calls. It was not run here because the Mac is timing the detector. The cheap
  version is safe now: pass the expert's reasons (for example "PowerShell started by
  wmiprvse.exe; -EncodedCommand; hidden window") to the explanation call as evidence.
- **Thin non-WMI sample.** Batch, Office, updater and the payload connection have one attack
  each, so the leave-one-type-out rows are single cases.
- **The replay is pessimistic.** It does no merging of identical pairs and does not skip
  alerted processes, so compare its rows with each other, not with the absolute numbers.
- **The detector's queue may differ by now.** "Today's queue" is the order in
  DETECTION_APPROACH.md 3.4 (fleet rarity, then age). If the detector session has changed it,
  rerun the replay against the new order.
- **B's false-alarm risk outside this testbed.** Legitimate tools such as Ansible and SCCM run
  `powershell -NoProfile -EncodedCommand`. That pair raises under B, so B relies on the hidden
  waves coming from the same testbed, where such commands never appear.
