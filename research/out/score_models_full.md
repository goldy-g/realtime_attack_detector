# Accuracy on labelled cases (2.10) · round: full

Neutral prompt (prompt_v0.py), JSON verdict, temperature 0. Dev + holdout cases; eval cases unseen.

| Model | Attacks: first case flagged | Any case flagged | Other-type attacks (any) | Malicious cases flagged | Benign cases flagged | of them in waves | AUC | Invalid |
|---|---|---|---|---|---|---|---|---|
| Gemma-4-E4B | 23/25 | 23/25 | 2/4 | 91/117 | 47/522 | 7 | 0.913 | 1 |
