# SQ-1 · Experts for known behaviours, the SLM for the rest (offline)

Offline, on the labelled case set (dev 16 attacks, holdout 9) with the saved Gemma 4 E4B
verdicts; no model was run. Five rules behind a router and two small trained models
(a depth-3 decision tree and gradient-boosted trees, dev only) were tested as **A, feed and
rank** (experts reorder the SLM's queue; the SLM makes every decision) and **B, raise** (an
expert may alert at once, never clear).

## Recommendation

**Adopt A with one expert, `hidden_powershell`; adopt B with that same expert only if Q-5
allows it; drop the other six.** The SLM already catches every PowerShell-delivered attack
(dev 16/16, holdout 7/7 at the first case), so no expert adds a catch that counts. What an
expert adds is *time*. Today's queue serves cases by fleet rarity then age, so the attack's own
case often waits behind other rare cases. Ranking cases the expert flags first lifts mean
timeliness from 0.659 to 0.767 on holdout and from 0.783 to 0.892 on dev (1.7 s per verdict),
with recall, false alarms and AUC unchanged by construction. This is safe under any reading of
"detection decisions must come from the SLM". Under B the same expert alerts as the case
arrives, so its attacks score 1.00: holdout mean 0.875, where the remaining gap is the updater
attack that no surviving expert sees. It raises no benign case among the 703. It needs two of four markers (encoded command, hidden
window, -NoProfile, download cradle), so every raise includes at least one of the three that
matched no benign event in all 62 training days (2.4, with that script's own patterns). `hidden_powershell` survives because it was written from three
delivery types (WMI, Office macro, batch file) and still catches each one when that type is
held out. The rules that gained recall on holdout (`updater_temp` 1/1 where the SLM had 0/1;
`dropped_beacon` 1/1 where prompt v0 had 0/1) were written from those very holdout attacks: the card's updater example
*is* the holdout attack. That gain is not evidence, and leave-one-type-out removes them. The
trained models are dropped. At zero training false alarms the tree raises nothing, and gbt
misses the payload connection the SLM catches. As a queue key gbt ranks best (AUC 0.992), but
in the replay it buys no time over the rule.

## What this does not measure, and the risks

- **Feeding expert facts into the prompt** (the other half of A) changes SLM verdicts and
  needs SLM calls. It was not run here because the Mac is timing the detector. The cheap
  version is safe now: pass the expert's reasons (for example "PowerShell started by
  wmiprvse.exe; -EncodedCommand; hidden window") to the explanation call as evidence.
- **Thin non-WMI sample.** Batch, Office, updater and the payload connection have one attack
  each, so the leave-one-type-out rows are single cases.
- **The replay is pessimistic.** It does no merging of identical pairs and does not skip
  alerted processes, so compare its rows with each other, not with the absolute numbers.
- **B's false-alarm risk outside this testbed.** Legitimate tools such as Ansible and SCCM run
  `powershell -NoProfile -EncodedCommand`. That pair raises under B, so B relies on the hidden
  waves coming from the same testbed, where such commands never appear.

## Headline · holdout, prompt v1 baseline

Kept experts: **hidden_powershell**.

| Variant | Attacks at first case | Benign flagged | AUC | Mean timeliness @ 1.7 s | @ 3.4 s |
|---|---|---|---|---|---|
| SLM alone, today's queue | 8/9 | 1/29 | 0.943 | 0.659 | 0.609 |
| A · kept experts rank the queue | 8/9 | 1/29 | 0.943 | 0.767 | 0.690 |
| B · kept experts may raise | 8/9 | 1/29 | 0.944 | 0.875 | 0.875 |
| B · all five rules may raise | 9/9 | 1/29 | 0.953 | 1.000 | 1.000 |

# Detail

Saved Gemma 4 E4B verdicts, no model calls. Baselines: **v1** = prompt v1 on the quick set (354 cases: all 117 malicious, 173 benign), the prompt the detector starts from; **v0** = prompt v0 on every dev + holdout case (703 cases, 522 benign). Eval cases unseen. Trained models learn on dev only. Script: `research/sq1/run.py` (rules in `research/sq1/experts.py`).

Detection columns: attacks flagged at their first case · at any case · malicious cases flagged · benign cases flagged (false alarms) · AUC malicious vs benign. Context cases are attack activity that earns nothing and costs nothing.

## 1 · Each expert alone, on the cases it claims

A rule claims the cases inside its behaviour (no router here); the trained models claim every case. "Caught" = attacks whose first malicious case the expert claims and calls an attack. The SLM columns are the same cases: v1 covers only the quick-set cases, v0 all of them.

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

Raise thresholds of the trained models (zero dev false alarms): tree 0.93, gbt 0.61.

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
| B · kept experts raise | dev (16 attacks) | 1.000 | 0.0 s | 1.000 | 0.0 s |
| B · all five rules raise | dev (16 attacks) | 1.000 | 0.0 s | 1.000 | 0.0 s |
| today: fleet rarity, then age | holdout (8 attacks) | 0.659 | 1.7 s | 0.609 | 3.4 s |
| A · kept experts first | holdout (8 attacks) | 0.767 | 1.7 s | 0.690 | 3.4 s |
| A · all rules first | holdout (8 attacks) | 0.767 | 1.7 s | 0.690 | 3.4 s |
| A · all rules, then gbt score | holdout (8 attacks) | 0.767 | 1.7 s | 0.690 | 3.4 s |
| B · kept experts raise | holdout (8 attacks) | 0.875 | 0.0 s | 0.875 | 0.0 s |
| B · all five rules raise | holdout (8 attacks) | 1.000 | 0.0 s | 1.000 | 0.0 s |

Ranking quality of the queue key alone (AUC malicious vs benign, all dev + holdout cases): fleet rarity 0.929 · kept experts first 0.940 · all rules first 0.941 · all rules then gbt 0.992.

## 4 · Leave one attack type out

For each attack type T: rules written only from T are removed (a rule written from several types stays), and both trained models are retrained on dev without T (threshold again at zero training false alarms). Measured on T's attacks in dev + holdout at their first case. Benign raised = holdout benign cases the T-less experts raise. Timeliness @ 1.7 s on T's attacks with a tempo curve: today's queue · A with the T-less rules ranking · B with the T-less rules raising.

| Held out T | Attacks | SLM v1 | SLM v0 | Rules left | Rules caught (by) | tree | gbt | Holdout benign raised: rules · tree · gbt | Timeliness today · A · B |
|---|---|---|---|---|---|---|---|---|---|
| batch | 1 | 1/1 | 1/1 | 5 | 1/1 (hidden_powershell 1) | 0/1 | 1/1 | 0 · 0 · 0 | 0.99 · 0.99 · 1.00 |
| office | 1 | 1/1 | 1/1 | 4 | 1/1 (hidden_powershell 1) | 0/1 | 1/1 | 0 · 0 · 0 | 0.95 · 0.95 · 1.00 |
| payload_flow | 1 | 1/1 | 0/1 | 4 | 0/1 (-) | 0/1 | 0/1 | 0 · 0 · 0 | - · - · - |
| updater | 1 | 0/1 | 0/1 | 4 | 0/1 (-) | 0/1 | 0/1 | 0 · 0 · 0 | 0.00 · 0.00 · 0.00 |
| wmi_ps | 21 | 21/21 | 21/21 | 4 | 21/21 (hidden_powershell 21) | 21/21 | 21/21 | 0 · 0 · 0 | 0.76 · 0.88 · 1.00 |

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

## 6 · Evidence an expert hands the explanation

- `atk-9935:e09d8873-515c-cbd7-e4c5-5cb778c302cd` · wmi_child → parent wmiprvse.exe → powershell.exe; a shell; -EncodedCommand; hidden window
- `atk-9935:e09d8873-515c-cbd7-e4c5-5cb778c302cd` · hidden_powershell → PowerShell started by wmiprvse.exe; -EncodedCommand; hidden window; -NoProfile
- `atk-339f-1:3d8c05d2-1877-0e8f-2159-fb4ceca97516` · office_child → parent winword.exe → cmd.exe; a shell; download cradle
- `atk-f3ac-1:931d2292-1c6e-dd60-b496-153d3ffceb7c` · updater_temp → updater gup.exe → ckfgw.exe; runs from a Temp / Downloads folder
- `probe-atk-f3ac-2:f9e9f9dc-10a6-42f0-ed69-1bf7c77a0bfd` · dropped_beacon → update.exe → public 53.192.68.50:8080; program runs from a user folder; non-web port
- `atk-1038:b2c47595-a0e4-046c-7e07-39d249f86de0` · tree (p=0.93, raise threshold 0.93) → fleet_log ≤ 3.4 → user_system ≤ 0.5 → parent_services ≤ 0.5
- gbt: top features by importance: fleet_log 0.44, ps_hidden 0.20, ps_encoded 0.10, parent_shell 0.09, ps_noprofile 0.08, user_system 0.04

