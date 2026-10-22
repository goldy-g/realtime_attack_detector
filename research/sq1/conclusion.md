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
