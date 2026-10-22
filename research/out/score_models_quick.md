# Accuracy on labelled cases (2.10) · round: quick

Neutral prompt (prompt_v0.py), JSON verdict, temperature 0. Dev + holdout cases; eval cases unseen.

| Model | Attacks: first case flagged | Any case flagged | Other-type attacks (any) | Malicious cases flagged | Benign cases flagged | of them in waves | AUC | Invalid |
|---|---|---|---|---|---|---|---|---|
| Granite-4.2-8B | 25/25 | 25/25 | 4/4 | 117/117 | 138/173 | 68 | 0.739 | 0 |
| LFM2.5-8B-A1B | 25/25 | 25/25 | 4/4 | 117/117 | 173/173 | 83 | 0.509 | 0 |
| Qwen3.5-2B | 24/25 | 24/25 | 3/4 | 86/117 | 107/173 | 50 | 0.565 | 0 |
| Qwen3-1.7B (prev) | 24/25 | 24/25 | 3/4 | 114/117 | 161/173 | 80 | 0.572 | 0 |
| Gemma-4-E4B | 23/25 | 23/25 | 2/4 | 91/117 | 14/173 | 7 | 0.909 | 0 |
| Qwen3-4B-2507 (prev) | 23/25 | 23/25 | 2/4 | 63/117 | 35/173 | 20 | 0.696 | 0 |
| Ministral-3-8B | 23/25 | 24/25 | 3/4 | 103/117 | 41/173 | 21 | 0.837 | 0 |
| Qwen3.5-4B | 23/25 | 23/25 | 2/4 | 104/117 | 80/173 | 40 | 0.713 | 0 |
| Gemma-4-E2B | 18/25 | 22/25 | 2/4 | 68/117 | 36/173 | 18 | 0.808 | 0 |
| Ministral-3-3B | 6/25 | 21/25 | 1/4 | 42/117 | 9/173 | 3 | 0.655 | 0 |
| Granite-4.2-3B | 1/25 | 4/25 | 2/4 | 4/117 | 0/173 | 0 | 0.531 | 0 |
| LFM2.5-2.6B | 0/25 | 0/25 | 0/4 | 0/117 | 0/173 | 0 | 0.5 | 354 |
| LFM2.5-1.2B | 0/25 | 0/25 | 0/4 | 0/117 | 0/173 | 0 | 0.5 | 0 |
| Foundation-Sec-1.1-8B | 0/25 | 9/25 | 2/4 | 11/117 | 6/173 | 2 | 0.58 | 0 |
