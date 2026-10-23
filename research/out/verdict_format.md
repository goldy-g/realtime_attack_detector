# Verdict reply: JSON vs word + confidence (stage 4.5, 23 Oct)

Why: on the Windows test laptop (i7-1165G7, 4 cores) each written token costs
0.08–0.16 s, and the JSON reply `{"verdict": "attack", "confidence": 85}` is 14–15
tokens plus the end token. `attack 85` is 4.

How: `tools/replay_cases.py --score --split dev` on the same 117 dev cases (15
attacks, 65 benign), Mac CPU, 8 threads, once per model and format. The JSON run
used a frozen copy of commit d7764a7.

| Model | Reply | Attacks at first case | Benign flagged | AUC | Tokens written | Median s (Mac) |
|---|---|---|---|---|---|---|
| Gemma 4 E4B | JSON | 15/15 | 2/65 (1 wave) | 0.976 | 15 | 3.30 |
| Gemma 4 E4B | word | 15/15 | 2/65 (1 wave) | 0.966 | 5 | 3.11 |
| Gemma 4 E2B | JSON | 15/15 | 3/65 (3 waves) | 0.969 | 15 | 2.16 |
| Gemma 4 E2B | word | 15/15 | 4/65 (3 waves) | 0.966 | 6 | 2.04 |

E4B gives the same verdict on all 117 cases. E2B differs on 5 benign cases
(3 newly flagged, 2 no longer flagged). Expected saving on the laptop: about 10
tokens a verdict, roughly 0.8 s on E2B and 1.5 s on E4B at its measured write speeds
(12.6 and 6.8 tokens/s with 8 threads).

Start-up probe: lengthened from about 300 to 371 new tokens, the dev median
(375), so the E4B-or-E2B choice is timed on a typical case. E4B on the Mac: 2.98 s
probe against a 3.11 s median live verdict.
