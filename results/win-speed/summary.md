# Speed on the Windows laptop (step b)

HP Pavilion 15-eg0xxx · Intel i7-1165G7, 4 cores / 8 threads, AVX-512 · 15.8 GB · Windows 11 Home 26300
On AC, Best performance, Chrome closed (~7 GB free). llama.cpp b11669 win-cpu-x64; `--list-devices` → none.
Backend loaded: `ggml-cpu-icelake.dll` (AVX-512). Clock under load ~2.9 GHz (103% of base): power-limited, no turbo.

## llama-bench (pp256 = reading a 256-token prompt, tg16 = writing 16 tokens), t/s

| Model | Threads | Reading | Writing | Mac CPU, 8 threads (FINDINGS 2.9) |
|---|---|---|---|---|
| Gemma 4 E2B | 4 | 107.7 | 16.7 | 344 / 97 |
| Gemma 4 E2B | 8 | 109.9 | 12.6 | |
| Gemma 4 E4B | 4 | 46.6 (40.0 on a re-run) | 8.2 | 178 / 51 |
| Gemma 4 E4B | 8 | 42.2 | 6.8 | |

Reading is ~3–4× slower than the Mac and writing ~6–7× slower; the "weak target" scenario assumed 2× and 3×.
Hyper-threads do not help reading and cost 15–25% on writing.

## Detector start-up calibration (median of 3 warm verdicts on PROBE_CASE)

| Model | Threads | Verdict | Note |
|---|---|---|---|
| E4B | 8 (default) | 7.91 s | smoke run: > MAX_VERDICT_S 4.0 → switched to E2B |
| E2B | 8 (default) | 5.14 s | smoke run: kept (last fallback) though > 4.0 |
| E4B | 4 | 9.19 s | DETECTOR_THREADS=4, machine warmer by then |
| E2B | 4 | 5.22 s | |
| E2B | 8 | 5.24 s | |

## One verdict call, llama-server's own timings (server-timings.txt)

Each warm call: 444 tokens cached, **297 new**, **15 written** (grammar JSON).

| Model | Threads | Reading 297 new | Writing 15 | Wall |
|---|---|---|---|---|
| E2B | 8 | 73–91 t/s, 3.3–4.1 s | 10.3 t/s, 1.4 s | 4.6–5.4 s |
| E2B | 4 | 70 t/s, 4.2 s | 13 t/s, 1.1 s | 5.3–5.4 s |
| E4B | 8 | 36–37 t/s, 8.0–8.2 s | 6.3 t/s, 2.2 s | 10.1–10.5 s |

HTTP/Python overhead is 0.01–0.03 s. Cold first call (741 tokens, nothing cached): E2B 7.8 s, E4B 20.6 s.

## Against the research estimates (250-token case)

| Model | Typical | Weak | Measured here |
|---|---|---|---|
| E4B | 1.7 s | 3.4 s | 7.9–10.2 s |
| E2B | 0.9 s | 1.8 s | 4.4–5.4 s |
