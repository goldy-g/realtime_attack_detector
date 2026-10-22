# Benign look-alikes (2.4)

Matches per attack pattern over the 62 training days (24 training alert points).

| Pattern | Alert points matched | Benign events | Benign machines | Malicious · context · excused |
|---|---|---|---|---|
| PowerShell with a hidden window | 22 / 24 | 0 | 0 / 62 | 30 · 0 · 0 |
| PowerShell with an encoded command | 22 / 24 | 0 | 0 / 62 | 31 · 0 · 0 |
| WMI starts PowerShell | 20 / 24 | 0 | 0 / 62 | 21 · 0 · 0 |
| child of WMI (wmiprvse.exe) | 20 / 24 | 4 | 4 / 62 | 21 · 0 · 0 |
| Office app starts a shell | 1 / 24 | 0 | 0 / 62 | 1 · 0 · 0 |
| PowerShell download cradle | 1 / 24 | 0 | 0 / 62 | 2 · 0 · 0 |
| outbound to a non-private address | 1 / 24 | 18963 | 59 / 62 | 107 · 5 · 0 |
| program run from Downloads/Temp | 1 / 24 | 4459 | 62 / 62 | 47 · 2 · 1 |
| credential tool or lsass dump (mimikatz, procdump, comsvcs MiniDump) | 0 / 24 | 51 | 36 / 62 | 0 · 0 · 0 |
| outbound RDP (mstsc.exe to 3389) | 0 / 24 | 14 | 2 / 62 | 2 · 0 · 0 |
| recon command (whoami, net, nltest, ipconfig, systeminfo, tasklist, netstat, …) | 0 / 24 | 769 | 50 / 62 | 20 · 0 · 0 |
| remote execution or tunnelling tool (psexec, wmic /node, winrs, plink) | 0 / 24 | 0 | 0 / 62 | 1 · 0 · 0 |
| scheduled task or service created (schtasks /create, sc create) | 0 / 24 | 2654 | 61 / 62 | 0 · 0 · 4 |
| script from Downloads/Temp | 0 / 24 | 0 | 0 / 62 | 1 · 1 · 0 |
| user or group change (net user /add, net localgroup /add) | 0 / 24 | 0 | 0 / 62 | 8 · 0 · 0 |

## Most common benign matches

**child of WMI (wmiprvse.exe)**
- 4× `conhost.exe ← wmiprvse.exe :: \??\C:\Windows\system#\conhost.exe #xffffffff -ForceV#`

**credential tool or lsass dump (mimikatz, procdump, comsvcs MiniDump)**
- 41× `lsass.exe ← wininit.exe :: C:\Windows\system#\lsass.exe`
- 3× `lsass.exe ← conhost.exe :: C:\Windows\system#\lsass.exe`
- 2× `lsass.exe ← svchost.exe :: C:\Windows\system#\lsass.exe`
- 2× `lsass.exe ← cmd.exe :: C:\Windows\system#\lsass.exe`
- 2× `lsass.exe ←  :: C:\Windows\system#\lsass.exe`
- 1× `lsass.exe ← ping.exe :: C:\Windows\system#\lsass.exe`

**outbound RDP (mstsc.exe to 3389)**
- 4× `mstsc.exe → 10.149.2.131:3389`
- 2× `mstsc.exe → 10.192.86.5:3389`
- 1× `mstsc.exe → 10.85.23.168:3389`
- 1× `mstsc.exe → 10.146.30.55:3389`
- 1× `mstsc.exe → 10.76.80.16:3389`
- 1× `mstsc.exe → 10.52.255.113:3389`

**outbound to a non-private address**
- 1066× `firefox.exe → 5.221.97.162:80`
- 854× `firefox.exe → 98.61.14.5:80`
- 854× `firefox.exe → 98.61.14.5:443`
- 444× `firefox.exe → 86.62.223.5:443`
- 342× `firefox.exe → 212.215.32.5:443`
- 337× `firefox.exe → 212.215.32.5:80`

**program run from Downloads/Temp**
- 3052× `searchprotocolhost.exe ← searchindexer.exe :: "C:\Windows\system#\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe#_ Global\UsGthrCtrlFltPipeMssGthrPipe# # -# "Software\Microsoft\`
- 59× `searchprotocolhost.exe ←  :: "C:\Windows\system#\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe#_ Global\UsGthrCtrlFltPipeMssGthrPipe# # -# "Software\Microsoft\`
- 5× `chrome.exe ← chrome.exe :: "C:\Program Files (x#)\Google\Chrome\Application\chrome.exe" --type=utility --channel="#.#.#\#" --lang=en-US --utility-allowed-dir="C:\Users`
- 1× `firefox.exe ← geckodriver.exe :: "\\?\C:\Program Files (x#)\Mozilla Firefox\firefox.exe" -marionette -profile C:\Users\knilsson\AppData\Local\Temp\rust_mozprofile.SFd#Z#agl#`
- 1× `firefox.exe ← geckodriver.exe :: "\\?\C:\Program Files (x#)\Mozilla Firefox\firefox.exe" -marionette -profile C:\Users\knilsson\AppData\Local\Temp\rust_mozprofile.ksyy#i#m#R`
- 1× `firefox.exe ← geckodriver.exe :: "\\?\C:\Program Files (x#)\Mozilla Firefox\firefox.exe" -marionette -profile C:\Users\AKARPE~#\AppData\Local\Temp\rust_mozprofile.ZGBwnnGGZB`

**recon command (whoami, net, nltest, ipconfig, systeminfo, tasklist, netstat, …)**
- 351× `netstat.exe ← cmd.exe :: netstat  -n `
- 320× `tasklist.exe ← cmd.exe :: tasklist`
- 63× `tasklist.exe ← cmd.exe :: tasklist  /fi "IMAGENAME eq  mantra.exe"`
- 27× `tasklist.exe ← cmd.exe :: tasklist  /fi "IMAGENAME eq mantra.exe"`
- 3× `tasklist.exe ← conhost.exe :: tasklist`
- 1× `netstat.exe ← ping.exe :: netstat  -n `

**scheduled task or service created (schtasks /create, sc create)**
- 2630× `schtasks.exe ← cmd.exe :: schtasks  /create /tn KickoffAutoLoginRandom /tr "python C:/ncr/kickoff/kickoff.py -d C:/ncr/kickoff -m AUTOLOGIN" /sc MINUTE /mo # /ru "SYS`
- 16× `schtasks.exe ← conhost.exe :: schtasks  /create /tn KickoffAutoLoginRandom /tr "python C:/ncr/kickoff/kickoff.py -d C:/ncr/kickoff -m AUTOLOGIN" /sc MINUTE /mo # /ru "SYS`
- 2× `schtasks.exe ← bcdedit.exe :: schtasks  /create /tn KickoffAutoLoginRandom /tr "python C:/ncr/kickoff/kickoff.py -d C:/ncr/kickoff -m AUTOLOGIN" /sc MINUTE /mo # /ru "SYS`
- 1× `schtasks.exe ← dllhost.exe :: schtasks  /create /tn KickoffAutoLoginRandom /tr "python C:/ncr/kickoff/kickoff.py -d C:/ncr/kickoff -m AUTOLOGIN" /sc MINUTE /mo # /ru "SYS`
- 1× `schtasks.exe ← winlogon.exe :: schtasks  /create /tn KickoffAutoLoginRandom /tr "python C:/ncr/kickoff/kickoff.py -d C:/ncr/kickoff -m AUTOLOGIN" /sc MINUTE /mo # /ru "SYS`
- 1× `schtasks.exe ← googleupdate.exe :: schtasks  /create /tn KickoffAutoLoginRandom /tr "python C:/ncr/kickoff/kickoff.py -d C:/ncr/kickoff -m AUTOLOGIN" /sc MINUTE /mo # /ru "SYS`

Totals: FLOW benign 84461, FLOW context 64, FLOW excused 381, FLOW malicious 803, PROCESS benign 288742, PROCESS context 11, PROCESS excused 87, PROCESS malicious 878
