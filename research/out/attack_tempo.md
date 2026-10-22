# Attack tempo (2.3)

Timeliness score an alert would earn d seconds after the alert point, over 25 attack waves (22 validation, 3 eval).

| Delay (s) | Mean | Median | Worst | Attacks ≥ 0.9 |
|---|---|---|---|---|
| 0 | 1.000 | 1.000 | 1.000 | 100% |
| 0.5 | 0.927 | 0.938 | 0.583 | 84% |
| 1 | 0.913 | 0.929 | 0.583 | 68% |
| 2 | 0.898 | 0.904 | 0.583 | 52% |
| 3 | 0.859 | 0.876 | 0.583 | 28% |
| 5 | 0.803 | 0.811 | 0.500 | 8% |
| 8 | 0.697 | 0.762 | 0.343 | 0% |
| 10 | 0.625 | 0.692 | 0.240 | 0% |
| 15 | 0.556 | 0.654 | 0.167 | 0% |
| 20 | 0.500 | 0.595 | 0.167 | 0% |
| 30 | 0.422 | 0.508 | 0.013 | 0% |
| 45 | 0.332 | 0.394 | 0.003 | 0% |
| 60 | 0.270 | 0.283 | 0.003 | 0% |
| 90 | 0.121 | 0.106 | 0.003 | 0% |
| 120 | 0.033 | 0.007 | 0.003 | 0% |

| Wave | Attack | n in window | 2nd event after | events in 1 s · 5 s · 10 s · 30 s | score at 2 s · 5 s · 10 s · 30 s |
|---|---|---|---|---|---|
| atk-f3ac-1 | Trojanised Notepad++ updater: SYSTEM payload, lsass injectio | 12 | 0.027 s | 6 · 7 · 7 · 11 | 0.5833 · 0.5 · 0.5 · 0.1667 |
| atk-eaa4 | Remote WMI launch of a PowerShell implant, C2 beaconing, pin | 76 | 0.014 s | 9 · 25 · 47 · 76 | 0.8289 · 0.6842 · 0.3947 · 0.0131 |
| atk-1038 | Remote WMI launch of a hidden PowerShell Empire agent that b | 70 | 0.026 s | 6 · 23 · 47 · 55 | 0.9143 · 0.6857 · 0.3429 · 0.2286 |
| atk-8329 | Remote WMI launch of an encoded PowerShell Empire agent that | 77 | 0.014 s | 7 · 22 · 43 · 56 | 0.9091 · 0.7273 · 0.4545 · 0.2857 |
| atk-c8f1 | Remote WMI launch of a hidden PowerShell Empire agent that b | 80 | 0.032 s | 7 · 20 · 45 · 57 | 0.925 · 0.7625 · 0.45 · 0.3 |
| w03 | Remote WMI launch of a hidden PowerShell Empire agent that b | 165 | 0.034 s | 27 · 40 · 66 · 102 | 0.8424 · 0.7636 · 0.6061 · 0.3879 |
| atk-f59c | Remote WMI launch of an encoded PowerShell Empire agent that | 81 | 0.048 s | 6 · 20 · 44 · 54 | 0.9259 · 0.7654 · 0.4691 · 0.3457 |
| atk-a5ce | Remote WMI launch of an encoded PowerShell Empire agent that | 90 | 0.044 s | 7 · 20 · 44 · 67 | 0.9333 · 0.7889 · 0.5222 · 0.2667 |
| atk-9ba4 | Remote WMI launch of a hidden PowerShell Empire agent that b | 188 | 0.047 s | 6 · 39 · 59 · 92 | 0.883 · 0.7979 · 0.6915 · 0.516 |
| atk-7f7a | Remote WMI launch of a hidden PowerShell Empire agent that b | 188 | 0.043 s | 26 · 39 · 65 · 92 | 0.867 · 0.7979 · 0.6596 · 0.516 |
| w02 | Phishing Word document: macro runs a hidden PowerShell downl | 229 | 0.015 s | 11 · 47 · 66 · 125 | 0.952 · 0.7991 · 0.7162 · 0.4585 |
| atk-fdda | Remote WMI launch of a hidden PowerShell Empire agent that b | 179 | 0.047 s | 23 · 36 · 59 · 89 | 0.8771 · 0.8045 · 0.676 · 0.5084 |
| atk-6d5d | Remote WMI launch of a hidden PowerShell Empire agent that b | 201 | 0.026 s | 26 · 39 · 56 · 91 | 0.8756 · 0.8109 · 0.7264 · 0.5522 |
| atk-2758 | Remote WMI launch of a hidden PowerShell Empire agent that b | 134 | 0.015 s | 24 · 25 · 26 · 72 | 0.8284 · 0.8209 · 0.8134 · 0.4701 |
| atk-f890 | Remote WMI launch of a hidden PowerShell Empire agent that b | 185 | 0.032 s | 20 · 33 · 58 · 91 | 0.8973 · 0.827 · 0.6919 · 0.5135 |
| atk-8875 | Remote WMI launch of a hidden PowerShell Empire agent that b | 197 | 0.05 s | 20 · 34 · 59 · 95 | 0.9036 · 0.8325 · 0.7056 · 0.5228 |
| atk-e7e0 | Remote WMI launch of a hidden PowerShell Empire agent that b | 230 | 0.041 s | 6 · 39 · 64 · 92 | 0.8913 · 0.8348 · 0.7261 · 0.6043 |
| atk-3c03 | Remote WMI launch of a hidden PowerShell Empire agent that b | 235 | 0.055 s | 6 · 38 · 64 · 97 | 0.8936 · 0.8426 · 0.7319 · 0.5915 |
| atk-0dfa | Remote WMI launch of a hidden PowerShell Empire agent that b | 217 | 0.025 s | 22 · 35 · 60 · 93 | 0.8986 · 0.8433 · 0.7281 · 0.576 |
| atk-339f-1 | Phishing Word document run by bantonio: PowerShell download  | 202 | 0.01 s | 11 · 30 · 65 · 112 | 0.9455 · 0.8564 · 0.6832 · 0.4505 |
| atk-5582 | Remote WMI launch of a hidden PowerShell Empire agent that b | 155 | 0.036 s | 7 · 20 · 44 · 77 | 0.9613 · 0.8774 · 0.7226 · 0.5097 |
| atk-875d | Remote WMI launch of an in-memory PowerShell agent, credenti | 170 | 0.034 s | 6 · 19 · 43 · 74 | 0.9706 · 0.8941 · 0.7529 · 0.5706 |
| atk-efdb | Downloaded batch file drops a hidden PowerShell Empire agent | 138 | 0.012 s | 3 · 15 · 26 · 64 | 0.9855 · 0.8986 · 0.8188 · 0.5435 |
| atk-9935 | Remote WMI launch of a hidden PowerShell Empire agent that b | 209 | 0.037 s | 6 · 21 · 45 · 81 | 0.9761 · 0.9043 · 0.7895 · 0.6172 |
| w01 | RDP hop: admin Remote Desktop session from another workstati | 279 | 0.56 s | 6 · 14 · 213 · 271 | 0.9785 · 0.9534 · 0.2401 · 0.0323 |
