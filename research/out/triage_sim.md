# Triage feasibility (2.5)

V1 new parent→child pair · V2 + new process→port outbound · V3 = V2 minus pairs common on ≥3 other machines.

| Variant · waves | Waves | Cases/min median · p95 · max | Max in 10 s | Benign cases | Alert point is a case | Attack has a case | Best timeliness at +0 s · +2 s · +5 s |
|---|---|---|---|---|---|---|---|
| V1 · val benign | 40 | 0.0 · 0.76 · 0.96 | 2 | 14 | – | – | – |
| V1 · val attack | 22 | 0.89 · 2.03 · 13.59 | 10 | 41 | 22/22 | 22/22 | 1.0 · 0.894 · 0.798 |
| V1 · eval | 7 | 0.0 · 2.0 · 3.15 | 7 | 5 | 2/3 | 3/3 | 0.996 · 0.921 · 0.839 |
| V2 · val benign | 40 | 0.0 · 1.11 · 1.93 | 4 | 27 | – | – | – |
| V2 · val attack | 22 | 3.33 · 3.99 · 17.22 | 14 | 56 | 22/22 | 22/22 | 1.0 · 0.894 · 0.798 |
| V2 · eval | 7 | 0.97 · 4.27 · 5.0 | 8 | 9 | 3/3 | 3/3 | 1.0 · 0.924 · 0.839 |
| V3 · val benign | 40 | 0.0 · 0.0 · 0.0 | 0 | 0 | – | – | – |
| V3 · val attack | 22 | 2.67 · 3.09 · 3.47 | 7 | 10 | 21/22 | 22/22 | 0.994 · 0.887 · 0.793 |
| V3 · eval | 7 | 0.0 · 3.5 · 3.6 | 8 | 2 | 3/3 | 3/3 | 1.0 · 0.924 · 0.839 |

Attacks whose alert point is not a V3 case:

- atk-efdb atk-087660: first malicious case 7.727 s after the alert point
