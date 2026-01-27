
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


