# v1.4-full-mac → s2-full-mac

| | v1.4-full-mac | s2-full-mac |
|---|---|---|
| Recall | 0.667 | 0.667 |
| Timeliness | 0.563 | 0.667 |
| Delay p50 (s) | 2.36 | 0.00 |
| Delay max (s) | 3.04 | 0.00 |
| False alarms | 0 | 0 |
| Evidence precision | 1.000 | 1.000 |

| Wave | Attack | Delay (s) before → after | Caught at event before → after | Timeliness before → after | Change |
|---|---|---|---|---|---|
| w01 | atk-1c3642 | – → – | – → – of 279 | 0.000 → 0.000 | +0.000 |
| w02 | atk-229bd8 | 3.04 → 0.00 | 36 → 1 of 229 | 0.847 → 1.000 | +0.153 |
| w03 | atk-82bc9c | 1.67 → 0.00 | 27 → 1 of 165 | 0.842 → 1.000 | +0.158 |

Timeliness change per attack: mean +0.103, median +0.153; better on 2, worse on 0, same on 1 of 3.
