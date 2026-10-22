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

## Headline · holdout, prompt v1 baseline

Kept experts: **hidden_powershell**.

| Variant | Attacks at first case | Benign flagged | AUC | Mean timeliness @ 1.7 s | @ 3.4 s |
|---|---|---|---|---|---|
| SLM alone, today's queue | 8/9 | 1/29 | 0.943 | 0.659 | 0.609 |
| A · kept experts rank the queue | 8/9 | 1/29 | 0.943 | 0.767 | 0.690 |
| A · trained gbt ranks the queue | 8/9 | 1/29 | 0.943 | 0.767 | 0.690 |
| A · trained ngram ranks the queue | 8/9 | 1/29 | 0.943 | 0.767 | 0.690 |
| B · kept experts may raise | 8/9 | 1/29 | 0.944 | 0.875 | 0.875 |
| B · all five rules may raise | 9/9 | 1/29 | 0.953 | 1.000 | 1.000 |

# Detail

Saved Gemma 4 E4B verdicts, no model calls. Baselines: **v1** = prompt v1 on the quick set (354 cases: all 117 malicious, 173 benign), the prompt the detector starts from; **v0** = prompt v0 on every dev + holdout case (703 cases, 522 benign). Eval cases unseen. Trained models learn on dev only. Script: `research/sq1/run.py` (rules in `research/sq1/experts.py`).

Detection columns: attacks flagged at their first case · at any case · malicious cases flagged · benign cases flagged (false alarms) · AUC malicious vs benign. Context cases are attack activity that earns nothing and costs nothing.

## 1 · Each expert alone, on the cases it claims

A rule claims the cases inside its behaviour (no router here); the trained models claim every case, Laya every quick-set case (the only ones it scored). "Caught" = attacks whose first malicious case the expert claims and calls an attack. The SLM columns are the same cases: v1 covers only the quick-set cases, v0 all of them.

| Expert | Written from | Split | Claimed: mal · ctx · benign | Expert: caught · benign raised | SLM v1: caught · benign flagged | SLM v0: caught · benign flagged |
|---|---|---|---|---|---|---|
| wmi_child | wmi_ps | dev | 14 · 0 · 0 | 14/14 · 0/0 | 14/14 · 0/0 | 14/14 · 0/0 |
| wmi_child | wmi_ps | holdout | 7 · 0 · 0 | 7/7 · 0/0 | 7/7 · 0/0 | 7/7 · 0/0 |
| office_child | office | dev | 1 · 2 · 1 | 1/1 · 0/1 | 1/1 · 0/1 | 1/1 · 0/1 |
| office_child | office | holdout | 0 · 0 · 1 | 0/0 · 0/1 | 0/0 · 0/0 | 0/0 · 0/1 |
| updater_temp | updater | dev | 0 · 0 · 9 | 0/0 · 0/9 | 0/0 · 0/2 | 0/0 · 0/9 |
| updater_temp | updater | holdout | 1 · 0 · 4 | 1/1 · 0/4 | 0/1 · 0/2 | 0/1 · 0/4 |
| hidden_powershell | batch, office, wmi_ps | dev | 17 · 0 · 2 | 16/16 · 0/2 | 16/16 · 0/0 | 16/16 · 0/2 |
| hidden_powershell | batch, office, wmi_ps | holdout | 7 · 0 · 3 | 7/7 · 0/3 | 7/7 · 0/2 | 7/7 · 0/3 |
| dropped_beacon | payload_flow | dev | 16 · 1 · 2 | 0/0 · 0/2 | 0/0 · 0/0 | 0/0 · 0/2 |
| dropped_beacon | payload_flow | holdout | 8 · 4 · 3 | 1/1 · 0/3 | 1/1 · 0/1 | 0/1 · 0/3 |
| tree | dev labels | dev | 70 · 44 · 409 | 1/16 · 0/409 | 16/16 · 11/144 | 16/16 · 38/409 |
| tree | dev labels | holdout | 47 · 18 · 113 | 0/9 · 0/113 | 8/9 · 1/29 | 7/9 · 9/113 |
| gbt | dev labels | dev | 70 · 44 · 409 | 16/16 · 0/409 | 16/16 · 11/144 | 16/16 · 38/409 |
| gbt | dev labels | holdout | 47 · 18 · 113 | 7/9 · 0/113 | 8/9 · 1/29 | 7/9 · 9/113 |
| ngram | dev labels | dev | 70 · 44 · 409 | 15/16 · 0/409 | 16/16 · 11/144 | 16/16 · 38/409 |
| ngram | dev labels | holdout | 47 · 18 · 113 | 7/9 · 0/113 | 8/9 · 1/29 | 7/9 · 9/113 |
| laya | zero-shot (never trained) | dev | 70 · 44 · 144 | 1/16 · 0/144 | 16/16 · 11/144 | 16/16 · 11/144 |
| laya | zero-shot (never trained) | holdout | 47 · 18 · 29 | 0/9 · 0/29 | 8/9 · 1/29 | 7/9 · 3/29 |

Raise thresholds (zero dev false alarms): tree 0.93, gbt 0.61, ngram 0.74, laya 0.911. Laya's zero-shot AUC on this set is 0.792 for this question (0.761 for its yes/no question; research/out/score_laya.md), against 0.956 for the SLM with prompt v1.

## 2 · Variants A and B: detection on dev and holdout

| Baseline | Variant | Split | First case | Any case | Malicious flagged | Benign flagged | AUC |
|---|---|---|---|---|---|---|---|
| v1 | SLM alone = variant A | dev | 16/16 | 16/16 | 68/70 | 11/144 | 0.965 |
| v1 | SLM alone = variant A | holdout | 8/9 | 8/9 | 40/47 | 1/29 | 0.943 |
| v1 | B · kept experts | dev | 16/16 | 16/16 | 68/70 | 11/144 | 0.968 |
| v1 | B · kept experts | holdout | 8/9 | 8/9 | 40/47 | 1/29 | 0.944 |
| v1 | B · all five rules | dev | 16/16 | 16/16 | 68/70 | 11/144 | 0.968 |
| v1 | B · all five rules | holdout | 9/9 | 9/9 | 41/47 | 1/29 | 0.953 |
| v1 | B · tree | dev | 16/16 | 16/16 | 68/70 | 11/144 | 0.965 |
| v1 | B · tree | holdout | 8/9 | 8/9 | 40/47 | 1/29 | 0.943 |
| v1 | B · gbt | dev | 16/16 | 16/16 | 68/70 | 11/144 | 0.975 |
| v1 | B · gbt | holdout | 8/9 | 8/9 | 40/47 | 1/29 | 0.949 |
| v1 | B · ngram | dev | 16/16 | 16/16 | 68/70 | 11/144 | 0.988 |
| v1 | B · ngram | holdout | 8/9 | 8/9 | 40/47 | 1/29 | 0.96 |
| v1 | B · laya | dev | 16/16 | 16/16 | 68/70 | 11/144 | 0.965 |
| v1 | B · laya | holdout | 8/9 | 8/9 | 40/47 | 1/29 | 0.944 |
| v1 | B · all rules + gbt | dev | 16/16 | 16/16 | 68/70 | 11/144 | 0.975 |
| v1 | B · all rules + gbt | holdout | 9/9 | 9/9 | 41/47 | 1/29 | 0.959 |
| v0 | SLM alone = variant A | dev | 16/16 | 16/16 | 55/70 | 38/409 | 0.924 |
| v0 | SLM alone = variant A | holdout | 7/9 | 7/9 | 36/47 | 9/113 | 0.897 |
| v0 | B · kept experts | dev | 16/16 | 16/16 | 55/70 | 38/409 | 0.927 |
| v0 | B · kept experts | holdout | 7/9 | 7/9 | 36/47 | 9/113 | 0.898 |
| v0 | B · all five rules | dev | 16/16 | 16/16 | 55/70 | 38/409 | 0.927 |
| v0 | B · all five rules | holdout | 9/9 | 9/9 | 38/47 | 9/113 | 0.923 |
| v0 | B · tree | dev | 16/16 | 16/16 | 55/70 | 38/409 | 0.924 |
| v0 | B · tree | holdout | 7/9 | 7/9 | 36/47 | 9/113 | 0.897 |
| v0 | B · gbt | dev | 16/16 | 16/16 | 55/70 | 38/409 | 0.937 |
| v0 | B · gbt | holdout | 7/9 | 7/9 | 36/47 | 9/113 | 0.901 |
| v0 | B · ngram | dev | 16/16 | 16/16 | 67/70 | 38/409 | 0.986 |
| v0 | B · ngram | holdout | 7/9 | 7/9 | 39/47 | 9/113 | 0.933 |
| v0 | B · all rules + gbt | dev | 16/16 | 16/16 | 55/70 | 38/409 | 0.937 |
| v0 | B · all rules + gbt | holdout | 9/9 | 9/9 | 38/47 | 9/113 | 0.927 |

Variant A never changes a verdict, so its rows are the SLM's. B can only add alerts; AUC under B gives an expert-raised case the top score.

## 3 · Alert time: the case queue replayed

Every dev / holdout triage case arrives at its own timestamp; one SLM worker takes the best waiting case and needs 1.7 s (typical 8-core target) or 3.4 s (weak target) per verdict; an expert alert under B goes out as the case arrives. Timeliness is the scorer's per-attack score at that delay after the alert point (2.3), for the attacks with a measured tempo curve (the validation waves plus training-day windows of the same attacks). v1 verdicts; v0 for benign window cases outside the quick set, which only occupy the worker. The replay has no merging of identical pairs and no skipping of alerted processes, so absolute delays are pessimistic; compare rows, not absolutes.

| Queue / alerting | Split | Mean timeliness @ 1.7 s | Median delay @ 1.7 s | Mean timeliness @ 3.4 s | Median delay @ 3.4 s |
|---|---|---|---|---|---|
| today: fleet rarity, then age | dev (16 attacks) | 0.783 | 6.6 s | 0.665 | 13.4 s |
| A · kept experts first | dev (16 attacks) | 0.892 | 2.9 s | 0.785 | 6.3 s |
| A · all rules first | dev (16 attacks) | 0.892 | 2.9 s | 0.785 | 6.3 s |
| A · all rules, then gbt score | dev (16 attacks) | 0.892 | 2.9 s | 0.785 | 6.3 s |
| A · gbt score first | dev (16 attacks) | 0.892 | 2.9 s | 0.785 | 6.3 s |
| A · ngram score first | dev (16 attacks) | 0.892 | 2.9 s | 0.785 | 6.3 s |
| B · kept experts raise | dev (16 attacks) | 1.000 | 0.0 s | 1.000 | 0.0 s |
| B · all five rules raise | dev (16 attacks) | 1.000 | 0.0 s | 1.000 | 0.0 s |
| today: fleet rarity, then age | holdout (8 attacks) | 0.659 | 1.7 s | 0.609 | 3.4 s |
| A · kept experts first | holdout (8 attacks) | 0.767 | 1.7 s | 0.690 | 3.4 s |
| A · all rules first | holdout (8 attacks) | 0.767 | 1.7 s | 0.690 | 3.4 s |
| A · all rules, then gbt score | holdout (8 attacks) | 0.767 | 1.7 s | 0.690 | 3.4 s |
| A · gbt score first | holdout (8 attacks) | 0.767 | 1.7 s | 0.690 | 3.4 s |
| A · ngram score first | holdout (8 attacks) | 0.767 | 1.7 s | 0.690 | 3.4 s |
| B · kept experts raise | holdout (8 attacks) | 0.875 | 0.0 s | 0.875 | 0.0 s |
| B · all five rules raise | holdout (8 attacks) | 1.000 | 0.0 s | 1.000 | 0.0 s |

Ranking quality of the queue key alone (AUC malicious vs benign). All dev + holdout cases: fleet rarity 0.929 · kept experts first 0.940 · all rules first 0.941 · all rules then gbt 0.992 · gbt 0.992 · ngram 0.998. Quick set (where Laya has scores): fleet rarity 0.924 · laya 0.792 · gbt 0.990 · ngram 0.997. The trained models' AUCs include their own dev training cases; the holdout-only AUCs are gbt 0.994 and ngram 0.995.

**Laya as a queue key.** Laya scored only the quick set, which holds every case of the validation waves, so these queues replay the wave cases alone (15 dev and 7 holdout attacks); the first two rows repeat the main table's queues on the same cases for a like-for-like comparison.

| Queue / alerting | Split | Mean timeliness @ 1.7 s | Median delay @ 1.7 s | Mean timeliness @ 3.4 s | Median delay @ 3.4 s |
|---|---|---|---|---|---|
| today: fleet rarity, then age | dev (15 attacks) | 0.783 | 6.6 s | 0.666 | 13.4 s |
| A · kept experts first | dev (15 attacks) | 0.894 | 2.9 s | 0.785 | 6.3 s |
| A · laya score first | dev (15 attacks) | 0.888 | 3.1 s | 0.770 | 6.5 s |
| A · kept experts, then laya score | dev (15 attacks) | 0.894 | 2.9 s | 0.785 | 6.3 s |
| B · laya raises | dev (15 attacks) | 0.795 | 6.6 s | 0.678 | 13.4 s |
| today: fleet rarity, then age | holdout (7 attacks) | 0.630 | 1.7 s | 0.574 | 3.4 s |
| A · kept experts first | holdout (7 attacks) | 0.753 | 1.7 s | 0.667 | 3.4 s |
| A · laya score first | holdout (7 attacks) | 0.753 | 1.7 s | 0.667 | 3.4 s |
| A · kept experts, then laya score | holdout (7 attacks) | 0.753 | 1.7 s | 0.667 | 3.4 s |
| B · laya raises | holdout (7 attacks) | 0.638 | 1.7 s | 0.584 | 3.4 s |

## 4 · Leave one attack type out

For each attack type T: rules written only from T are removed (a rule written from several types stays), and the three trained models are retrained on dev without T (threshold again at zero training false alarms). Laya was never trained on these labels and its threshold comes from dev benign cases only, so its row is already a held-out result. Measured on T's attacks in dev + holdout at their first case. Benign raised = holdout benign cases the T-less experts raise (Laya: quick-set holdout benign only). Timeliness @ 1.7 s on T's attacks with a tempo curve: today's queue · A with the T-less rules ranking · B with the T-less rules raising · A with the T-less gbt ranking · A with the T-less ngram ranking.

| Held out T | Attacks | SLM v1 | SLM v0 | Rules left | Rules caught (by) | tree | gbt | ngram | laya | Holdout benign raised: rules · tree · gbt · ngram · laya | Timeliness today · A rules · B rules · A gbt · A ngram |
|---|---|---|---|---|---|---|---|---|---|---|---|
| batch | 1 | 1/1 | 1/1 | 5 | 1/1 (hidden_powershell 1) | 0/1 | 1/1 | 0/1 | 0/1 | 0 · 0 · 0 · 0 · 0 | 0.99 · 0.99 · 1.00 · 0.99 · 0.99 |
| office | 1 | 1/1 | 1/1 | 4 | 1/1 (hidden_powershell 1) | 0/1 | 1/1 | 0/1 | 0/1 | 0 · 0 · 0 · 0 · 0 | 0.95 · 0.95 · 1.00 · 0.95 · 0.95 |
| payload_flow | 1 | 1/1 | 0/1 | 4 | 0/1 (-) | 0/1 | 0/1 | 0/1 | 0/1 | 0 · 0 · 0 · 0 · 0 | - · - · - · - · - |
| updater | 1 | 0/1 | 0/1 | 4 | 0/1 (-) | 0/1 | 0/1 | 0/1 | 0/1 | 0 · 0 · 0 · 0 · 0 | 0.00 · 0.00 · 0.00 · 0.00 · 0.00 |
| wmi_ps | 21 | 21/21 | 21/21 | 4 | 21/21 (hidden_powershell 21) | 21/21 | 21/21 | 21/21 | 1/21 | 0 · 0 · 0 · 0 · 0 | 0.76 · 0.88 · 1.00 · 0.88 · 0.88 |

## 5 · Which experts survive

| Expert | Holdout: beats SLM v1 on its own cases? | LOATO: with its own type held out, still at least the SLM there? | Verdict |
|---|---|---|---|
| wmi_child | yes: caught 7/7 vs SLM 7/7, benign raised 0 vs 0 (same catches, alert at arrival) | no: wmi_ps: removed (written only from it) | **drop** |
| office_child | no: no holdout attack in its behaviour | no: office: removed (written only from it) | **drop** |
| updater_temp | yes: caught 1/1 vs SLM 0/1, benign raised 0 vs 0 (catches more) | no: updater: removed (written only from it) | **drop** |
| hidden_powershell | yes: caught 7/7 vs SLM 7/7, benign raised 0 vs 0 (same catches, alert at arrival) | yes: batch: caught 1/1 (SLM 1); office: caught 1/1 (SLM 1); wmi_ps: caught 21/21 (SLM 21) | **keep** |
| dropped_beacon | yes: caught 1/1 vs SLM 1/1, benign raised 0 vs 0 (same catches, alert at arrival) | no: payload_flow: removed (written only from it) | **drop** |
| tree | no: caught 0/9 vs SLM 8/9, benign raised 0 vs 1 | no: batch 0/1 (SLM 1); office 0/1 (SLM 1); payload_flow 0/1 (SLM 1); updater 0/1 (SLM 0); wmi_ps 21/21 (SLM 21) | **drop** |
| gbt | no: caught 7/9 vs SLM 8/9, benign raised 0 vs 1 | no: batch 1/1 (SLM 1); office 1/1 (SLM 1); payload_flow 0/1 (SLM 1); updater 0/1 (SLM 0); wmi_ps 21/21 (SLM 21) | **drop** |
| ngram | no: caught 7/9 vs SLM 8/9, benign raised 0 vs 1 | no: batch 0/1 (SLM 1); office 0/1 (SLM 1); payload_flow 0/1 (SLM 1); updater 0/1 (SLM 0); wmi_ps 21/21 (SLM 21) | **drop** |
| laya | no: caught 0/9 vs SLM 8/9, benign raised 0 vs 1 | no: batch 0/1 (SLM 1); office 0/1 (SLM 1); payload_flow 0/1 (SLM 1); updater 0/1 (SLM 0); wmi_ps 1/21 (SLM 21) | **drop** |

## 6 · Evidence an expert hands the explanation

- `atk-9935:e09d8873-515c-cbd7-e4c5-5cb778c302cd` · wmi_child → parent wmiprvse.exe → powershell.exe; a shell; -EncodedCommand; hidden window
- `atk-9935:e09d8873-515c-cbd7-e4c5-5cb778c302cd` · hidden_powershell → PowerShell started by wmiprvse.exe; -EncodedCommand; hidden window; -NoProfile
- `atk-339f-1:3d8c05d2-1877-0e8f-2159-fb4ceca97516` · office_child → parent winword.exe → cmd.exe; a shell; download cradle
- `atk-f3ac-1:931d2292-1c6e-dd60-b496-153d3ffceb7c` · updater_temp → updater gup.exe → ckfgw.exe; runs from a Temp / Downloads folder
- `probe-atk-f3ac-2:f9e9f9dc-10a6-42f0-ed69-1bf7c77a0bfd` · dropped_beacon → update.exe → public 53.192.68.50:8080; program runs from a user folder; non-web port
- `atk-1038:b2c47595-a0e4-046c-7e07-39d249f86de0` · tree (p=0.93, raise threshold 0.93) → fleet_log ≤ 3.4 → user_system ≤ 0.5 → parent_services ≤ 0.5
- gbt: top features by importance: fleet_log 0.44, ps_hidden 0.20, ps_encoded 0.10, parent_shell 0.09, ps_noprofile 0.08, user_system 0.04
- ngram: the character n-grams that push hardest toward "attack": 'owers', 'rshel', 'rshe', 'rsh', 'wersh', 'ershe', 'ersh', 'owe', 'power', 'powe'
- laya: a probability only; it gives no reason a reader or the SLM could check.

