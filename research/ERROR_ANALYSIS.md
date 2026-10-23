# Stage 4 · Every miss and false alarm, and every attack type (4.2, 4.4)

Live runs in real time on the Mac unless noted (`results/<run>/scorecard.json` and
`decisions.jsonl`). Solution 1 throughout: the SLM makes every decision.

## Every miss and false alarm (4.2)

| Run | What | Cause | Decision |
|---|---|---|---|
| v1-smoke, 4 validation waves | 2 false alarms | A queued case was rendered when the model got to it, so it showed events from after its own. | Fixed in stage 3: a case shows the machine as of its own event. None since. |
| v1.1-dev, 45 dev waves | Missed the batch-file attack (`atk-efdb`) | The model flagged `cmd.exe` running the downloaded `.bat` one second before the alert point. That is a context event and earns nothing, and the one-alert-per-tree rule then skipped the hidden PowerShell that was the alert point. | Fixed (`e71575c`): only the alerted process itself is skipped; its children are still judged. Caught in every run since. |
| Every dev run, v1.1 to v1.4 | 1 false alarm on `atk-2758`: `explorer.exe` → `wscript.exe` | The testbed's own logon script, a `.vbs` that `explorer.exe` starts at logon. The pair occurs on 61 of the 62 training machines and the case says so, yet the model calls it an attack at confidence 85. It is the only false alarm in 45 dev waves, and the 30 benign dev waves have none. | Accepted and listed under known limitations. The fixes on offer cost more than they save: dropping fleet-common cases lost an alert point in research (2.5), and a prompt rule written from this one case would be tuning on dev (4.3, skipped). |
| v1.4-full-mac and the Windows laptop, 7 public eval waves | Missed the Remote Desktop hop (w01) | The alert point is `mstsc.exe` opening port 3389 to an internal address, started from the desktop under the account `sysadmin`. Gemma 4 E4B on the Mac and E2B on the laptop both judge it normal at 85. One event like this looks like an administrator at work. | Accepted and listed under known limitations. It is the target of solution 2's lateral-movement specialist. |
| SQ-1 offline replay, holdout | Missed the trojanised Notepad++ updater (`host-f3ac`) | `gup.exe` starts a random-named program from the user's Temp folder; the model calls it normal. | Caught live in run v1.4-holdout at its alert point (`gup.exe` → `ckfgw.exe`, attack at 85, 4.0 s after the event; timeliness 0.50, because the wave holds only 12 malicious events). Offline the model had called the same step normal, so this is a borderline case: one case, one flip. Counted as caught, and the README says it is borderline. |

Two errors were fixed and two are accepted with a reason. The fifth, the updater, was caught in the live holdout run.

## Every attack type (4.4)

The SLM is not trained, so a strict leave-one-attack-type-out test applies only to the
parts fitted to labels. SQ-1 ran it there: the expert rule passes, the trained models fail.
For the detector as a whole, the honest test is how it does on attack types that played no
part in building it.

| Attack type | Attacks and where | Part in building the detector | Live result |
|---|---|---|---|
| Remote WMI starts a hidden PowerShell agent | 21: 14 dev (13 in dev waves), 6 holdout, eval w03 | The main case behind every design choice; the expert rule was written from it | Dev 13 of 13 (v1.4); eval w03 caught (0.842); holdout 6 of 6 (0.743 to 0.926, run v1.4-holdout) |
| Phishing document runs a PowerShell download cradle | 2: dev host-339f, eval w02 | One dev attack; the expert rule covers it | Both caught (eval w02: 0.847) |
| Downloaded batch file starts a hidden PowerShell agent | 1: dev host-efdb | Its miss led to the `e71575c` fix | Caught in every run since the fix |
| Trojanised updater runs a dropped program | 1: holdout host-f3ac | None: holdout; the prompt names the behaviour only as general guidance | Caught live at its alert point (run v1.4-holdout, 0.50). Missed offline with the research case format, so borderline |
| Downloaded payload calls a bare IP address | 1: holdout host-f3ac | None; named only as general guidance | Caught offline with prompt v1; it has no wave of its own, because the first attack on that machine was still running |
| Remote Desktop hop to the next workstation | 1: eval w01 | None: no training example; named only as general guidance | Missed on the Mac (E4B) and the laptop (E2B) |

**Reading.** The detector catches every type that shaped its design, all of them
PowerShell delivery. Three types had to be recognised from the prompt's general guidance
alone. It caught the payload connection offline and the updater live, though the updater
is borderline. It missed the Remote Desktop hop on both machines. So it reaches beyond the
PowerShell family it was built on only in part. SQ-1 found the same for trained models, and
it is why solution 2's panel needs specialists trained on recordings of other attack
families.

## What changes

- No code change: solution 1 is held, and 4.3 (prompt examples) is skipped.
- The holdout, never used for tuning, confirms the dev picture (run v1.4-holdout, 17 waves
  in real time):
  - 7 of 7 attacks caught;
  - no false alarm on the 10 benign waves;
  - timeliness 0.814 (dev 0.867), median delay 2.4 s;
  - evidence precision 1.00, and all 13 alerts explained.
- The README's known limitations list the logon-script false alarm and the Remote Desktop
  hop, and mark the updater as borderline.
