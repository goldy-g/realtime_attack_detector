# Accuracy on labelled cases (2.10) · round: quickv1

Neutral prompt (prompt_v0.py), JSON verdict, temperature 0. Dev + holdout cases; eval cases unseen.

| Model | Attacks: first case flagged | Any case flagged | Other-type attacks (any) | Malicious cases flagged | Benign cases flagged | of them in waves | AUC | Invalid |
|---|---|---|---|---|---|---|---|---|
| Gemma-4-E4B | 24/25 | 24/25 | 3/4 | 108/117 | 12/173 | 4 | 0.956 | 0 |
| Gemma-4-E2B | 24/25 | 24/25 | 3/4 | 94/117 | 19/173 | 10 | 0.942 | 0 |
| Qwen3.5-4B | 24/25 | 24/25 | 3/4 | 110/117 | 23/173 | 13 | 0.902 | 0 |
| Qwen3.5-2B | 24/25 | 24/25 | 3/4 | 104/117 | 114/173 | 54 | 0.616 | 0 |
