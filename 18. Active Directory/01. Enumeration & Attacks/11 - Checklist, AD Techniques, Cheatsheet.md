# Active Directory Enumeration & Attacks Checklist

A comprehensive checklist for AD penetration testing based on HTB's Active Directory Enumeration & Attacks module.

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

## Contributing

Feel free to submit issues or pull requests to improve this checklist.

## License

This checklist is based on HTB's Active Directory Enumeration & Attacks module.

---

## Disclaimer

This checklist is for educational purposes and authorized penetration testing only. Unauthorized access to computer systems is illegal.
