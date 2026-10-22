# Decision matrix (2.11)

Decision on the target = reading the case + a 10-token verdict. Typical target: Mac CPU speed / 1.0 (prompt) and / 1.7 (writing); conservative: / 2.0 and / 3.0. Today's cases ≈ 480 tokens; compact = 250 tokens. Timeliness = mean tempo curve (2.3) at that delay.

| Model | Params (B) | Memory (MB) | Decision, compact case: typical · conservative (s) | Timeliness typical · conservative | Today's case, conservative (s) | Attacks any · first | Other types | Benign flagged | AUC | Prompt v1: first · benign · AUC | Gates speed · memory · valid |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Qwen3-1.7B (prev) | 1.72 | 4927 | 0.7 · 1.4 | 0.92 · 0.91 | 2.6 | 24/25 · 24/25 | 3/4 | 161/173 | 0.572 | – | pass · pass · pass |
| LFM2.5-1.2B | 1.17 | 1732 | 0.9 · 1.8 | 0.92 · 0.9 | 3.0 | 0/25 · 0/25 | 0/4 | 0/173 | 0.5 | – | pass · pass · pass |
| Gemma-4-E2B | 4.63 | 5098 | 0.9 · 1.8 | 0.92 · 0.9 | 3.3 | 22/25 · 18/25 | 2/4 | 36/173 | 0.808 | 24 · 19/173 · 0.942 | pass · pass · pass |
| Qwen3.5-2B | 1.88 | 3153 | 1.4 · 2.7 | 0.91 · 0.87 | 5.0 | 24/25 · 24/25 | 3/4 | 107/173 | 0.565 | 24 · 114/173 · 0.616 | pass · pass · pass |
| Gemma-4-E4B | 7.46 | 8358 | 1.7 · 3.4 | 0.9 · 0.85 | 6.4 | 23/25 · 23/25 | 2/4 | 14/173 | 0.909 | 24 · 12/173 · 0.956 | pass · FAIL · pass |
| LFM2.5-8B-A1B | 8.47 | 8569 | 1.7 · 3.4 | 0.9 · 0.85 | 5.3 | 25/25 · 25/25 | 4/4 | 173/173 | 0.509 | – | pass · FAIL · pass |
| LFM2.5-2.6B | 2.7 | 3625 | 2.2 · 4.3 | 0.89 · 0.82 | 6.7 | 0/25 · 0/25 | 0/4 | 0/173 | 0.5 | – | pass · pass · FAIL |
| Granite-4.2-3B | 3.66 | 4991 | 2.8 · 5.6 | 0.87 · 0.78 | 9.0 | 4/25 · 1/25 | 2/4 | 0/173 | 0.531 | – | FAIL · pass · pass |
| Ministral-3-3B | 3.43 | 5451 | 2.9 · 5.7 | 0.86 · 0.78 | 11.0 | 21/25 · 6/25 | 1/4 | 9/173 | 0.655 | – | FAIL · pass · pass |
| Qwen3.5-4B | 4.21 | 6636 | 3.2 · 6.3 | 0.85 · 0.76 | 11.8 | 23/25 · 23/25 | 2/4 | 80/173 | 0.713 | 24 · 23/173 · 0.902 | FAIL · pass · pass |
| Qwen3-4B-2507 (prev) | 4.02 | 6553 | 3.5 · 7.0 | 0.84 · 0.73 | 13.2 | 23/25 · 23/25 | 2/4 | 35/173 | 0.696 | – | FAIL · pass · pass |
| Foundation-Sec-1.1-8B | 8.03 | 8508 | 6.6 · 12.9 | 0.75 · 0.58 | 19.7 | 9/25 · 0/25 | 2/4 | 6/173 | 0.58 | – | FAIL · FAIL · pass |
| Ministral-3-8B | 8.49 | 7917 | 6.8 · 13.4 | 0.74 · 0.58 | 25.8 | 24/25 · 23/25 | 3/4 | 41/173 | 0.837 | – | FAIL · pass · pass |
| Granite-4.2-8B | 8.79 | 9118 | 7.7 · 15.1 | 0.71 · 0.56 | 24.5 | 25/25 · 25/25 | 4/4 | 138/173 | 0.739 | – | FAIL · FAIL · pass |
