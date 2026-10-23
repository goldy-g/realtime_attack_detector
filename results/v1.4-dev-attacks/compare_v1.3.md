# v1.3-dev-attacks → v1.4-dev-attacks

| | v1.3-dev-attacks | v1.4-dev-attacks |
|---|---|---|
| Recall | 1.000 | 1.000 |
| Timeliness | 0.852 | 0.867 |
| Delay p50 (s) | 3.11 | 3.05 |
| Delay max (s) | 4.54 | 4.64 |
| False alarms | 1 | 1 |
| Evidence precision | 1.000 | 1.000 |

| Wave | Attack | Delay (s) before → after | Caught at event before → after | Timeliness before → after | Change |
|---|---|---|---|---|---|
| atk-0dfa | atk-8cc8c6 | 1.87 → 1.70 | 23 → 23 of 217 | 0.899 → 0.899 | +0.000 |
| atk-2758 | atk-3c3aad | 2.09 → 4.64 | 24 → 24 of 134 | 0.828 → 0.828 | +0.000 |
| atk-339f-1 | atk-e8aecc | 3.07 → 2.91 | 22 → 22 of 202 | 0.896 → 0.896 | +0.000 |
| atk-5582 | atk-a4959a | 3.11 → 3.72 | 7 → 19 of 155 | 0.961 → 0.884 | -0.077 |
| atk-8329 | atk-00b186 | 3.35 → 3.05 | 15 → 8 of 77 | 0.818 → 0.909 | +0.091 |
| atk-875d | atk-36c5c6 | 3.37 → 3.35 | 18 → 18 of 170 | 0.900 → 0.900 | +0.000 |
| atk-8875 | atk-7adfe0 | 3.14 → 2.56 | 32 → 20 of 197 | 0.843 → 0.904 | +0.061 |
| atk-9935 | atk-5b535f | 3.26 → 3.30 | 19 → 19 of 209 | 0.914 → 0.914 | +0.000 |
| atk-9ba4 | atk-630671 | 2.50 → 2.16 | 28 → 27 of 188 | 0.856 → 0.862 | +0.005 |
| atk-a5ce | atk-b12a4d | 3.03 → 3.38 | 19 → 19 of 90 | 0.800 → 0.800 | +0.000 |
| atk-c8f1 | atk-c6c1b9 | 3.30 → 2.86 | 19 → 19 of 80 | 0.775 → 0.775 | +0.000 |
| atk-eaa4 | atk-d31c37 | 2.62 → 1.91 | 25 → 14 of 76 | 0.684 → 0.829 | +0.145 |
| atk-efdb | atk-087660 | 4.54 → 3.84 | 15 → 15 of 138 | 0.899 → 0.899 | +0.000 |
| atk-f890 | atk-7ee042 | 4.20 → 3.77 | 33 → 33 of 185 | 0.827 → 0.827 | +0.000 |
| atk-fdda | atk-a549ed | 2.78 → 2.10 | 23 → 23 of 179 | 0.877 → 0.877 | +0.000 |

Timeliness change per attack: mean +0.015, median +0.000; better on 4, worse on 1, same on 10 of 15.
