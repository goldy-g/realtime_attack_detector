# Laya zero-shot on the quick case set (2.10)

Device cpu, load 33.9 s, 748 ms per case (median, two questions in one pass).

| Question | AUC malicious vs benign | Malicious ≥ 0.5 | Benign ≥ 0.5 |
|---|---|---|---|
| yes/no: is this an attack? | 0.761 | 106/117 | 130/173 |
| choice: attack or normal | 0.792 | 117/117 | 153/173 |
