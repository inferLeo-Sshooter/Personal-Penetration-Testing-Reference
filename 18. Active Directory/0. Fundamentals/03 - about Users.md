
# User and Machine Accounts

User accounts are created on local systems and in Active Directory to allow people or programs (like system services) to log on and access resources based on their rights. When users log in, the system verifies their password and creates an access token describing their security identity and group membership. This token is presented whenever users interact with processes.

User accounts serve multiple purposes: enabling employees/contractors to log in and access resources, running programs under specific security contexts (e.g., highly privileged user vs. network service account), and managing access to objects like file shares, files, and applications.

Users can be assigned to groups containing one or more members, which simplifies administration by allowing administrators to assign privileges once to a group rather than individually to each user, making it easier to grant and revoke rights.

**Account Provisioning:**
User account management is a core AD function. Organizations typically provision at least one AD account per user, with some users having multiple accounts based on their role (e.g., IT admins, Help Desk). Service accounts also run applications or perform domain functions. A 1,000-employee organization might have 1,200+ active accounts.

Organizations often retain hundreds of disabled accounts from former employees for audit purposes, deactivating them (ideally removing all privileges) without deletion. Common practice includes an OU like `FORMER EMPLOYEES` containing many deactivated accounts.

<img width="1020" height="703" alt="image" src="https://github.com/user-attachments/assets/7104c6c8-dfdc-456c-a9f5-d86ce38d4ba6" />

**User Account Security Risks**

User accounts in Active Directory can be provisioned with varying rights—from read-only Domain Users to Enterprise Admins with complete domain control, and countless combinations between. This flexibility makes accounts susceptible to misconfigurations that grant unintended rights exploitable by attackers or penetration testers.

User accounts present an immense attack surface and are typically key targets for gaining footholds during penetration tests. Users are often the weakest link due to human behavior: choosing weak or shared passwords, installing unauthorized software, or admins making careless mistakes or being overly permissive with permissions.

Organizations must implement policies, procedures, and defense-in-depth strategies to mitigate the inherent risks users bring to the domain.

---

## Local Accounts

Local accounts are stored on individual servers or workstations and can be assigned rights on that specific host only—they don't work across the domain. While considered security principals, they can only manage access and secure resources on standalone hosts.

**Default Local Accounts:**

**Administrator** (SID `S-1-5-domain-500`)
- First account created with new Windows installations
- Full control over nearly all system resources
- Cannot be deleted or locked, but can be disabled or renamed
- Disabled by default on Windows 10 and Server 2016, which create another local account in the local administrators group during setup

**Guest**
- Disabled by default
- Allows users without accounts to log in temporarily with limited access
- Has blank password by default
- Should remain disabled due to anonymous access security risks

**SYSTEM** (`NT AUTHORITY\SYSTEM`)
- Default OS account for internal functions
- Service account, not a regular user context (unlike Linux Root)
- Runs many processes and services
- No user profile but has permissions over nearly everything
- Doesn't appear in User Manager and cannot join groups
- Highest permission level on Windows hosts with Full Control over all files

**Network Service**
- Predefined local account for Service Control Manager (SCM)
- Runs Windows services and presents credentials to remote services

**Local Service**
- Another predefined SCM account for Windows services
- Minimal privileges on the computer
- Presents anonymous credentials to the network

--- 

## Domain Users

Domain users differ from local users by receiving rights from the domain to access resources like file servers, printers, intranet hosts, and other objects based on their account permissions or group memberships. Unlike local users, domain user accounts can log into any host within the domain.

**KRBTGT Account**

A critical account to understand is `KRBTGT`, a built-in local account within the AD infrastructure. It acts as a service account for the Key Distribution Service, providing authentication and access for domain resources. 

This account is a high-value target for attackers because gaining control provides unconstrained domain access. It can be exploited for privilege escalation and persistence through attacks like Golden Ticket attacks.

---

## User Naming Attributes

Security in Active Directory can be improved using a set of user naming attributes to help identify user objects like logon name or ID. The following are a few important Naming Attributes in AD:

|||
|-|-|
|`UserPrincipalName (UPN)`	|This is the primary logon name for the user. By convention, the UPN uses the email address of the user.|
|`ObjectGUID`	|This is a unique identifier of the user. In AD, the ObjectGUID attribute name never changes and remains unique even if the user is removed.|
|`SAMAccountName`	|This is a logon name that supports the previous version of Windows clients and servers.|
|`objectSID`	|The user's Security Identifier (SID). This attribute identifies a user and its group memberships during security interactions with the server.|
|`sIDHistory`	|This contains previous SIDs for the user object if moved from another domain and is typically seen in migration scenarios from domain to domain. After a migration occurs, the last SID will be added to the `sIDHistory` property, and the new SID will become its `objectSID`.|

**Common User Attributes:**
```
PS C:\htb Get-ADUser -Identity htb-student

DistinguishedName : CN=htb student,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
Enabled           : True
GivenName         : htb
Name              : htb student
ObjectClass       : user
ObjectGUID        : aa799587-c641-4c23-a2f7-75850b4dd7e3
SamAccountName    : htb-student
SID               : S-1-5-21-3842939050-3880317879-2865463114-1111
Surname           : student
UserPrincipalName : htb-student@INLANEFREIGHT.LOCAL
```

---

## Domain-joined vs. Non-Domain-joined Machines

**Domain Joined**
Hosts joined to a domain benefit from easier information sharing and centralized management through the Domain Controller (DC), which provides resources, policies, and updates. Domain-joined hosts acquire configurations and changes via Group Policy. Users can log into any domain-joined host and access resources across the enterprise—the typical setup in enterprise environments.

**Non-domain Joined (Workgroup)**
Non-domain joined computers in workgroups aren't managed by domain policy. Sharing resources outside the local network is more complicated than in domains. This setup suits home use or small business clusters on the same LAN. Users control changes to their hosts, but user accounts exist only locally and profiles don't migrate to other workgroup hosts.

**Machine Account Security Significance**

A machine account (`NT AUTHORITY\SYSTEM`) in AD environments has most of the same rights as a standard domain user account. This is critical because valid user credentials aren't always necessary to enumerate and attack a domain.

`SYSTEM` level access can be obtained through remote code execution exploits or privilege escalation. While often viewed as useful only for extracting sensitive data (passwords, SSH keys, files) from a specific host, `SYSTEM` account access actually provides read access to much domain data—an excellent launching point for information gathering before executing AD-related attacks.

---

# Active Directory Groups

Groups are significant AD objects that place similar users together for mass-assigning rights and access. They're key targets for attackers and penetration testers because the privileges they grant may not be readily apparent and can provide excessive or unintended access if misconfigured.

Active Directory contains many built-in groups, and organizations typically create custom groups to define rights, privileges, and manage domain access. Group numbers can snowball and become unwieldy, potentially leading to unintended access if left unchecked.

Organizations must periodically **audit** existing groups, the privileges they grant members, and check for excessive membership beyond what users need for daily work. Understanding the impact of different group types and their scopes is essential.

**Groups vs. Organizational Units (OUs):**

- **OUs**: Group users, groups, and computers to ease management and deploy Group Policy settings to specific domain objects. Can delegate administrative tasks (like password resets or unlocking accounts) without granting additional admin rights through group membership.

- **Groups**: Primarily used to assign permissions for accessing resources.

---

## Types of Groups

Groups organize users, computers, and contact objects into management units for easier permission administration and resource assignment (like printers and file shares). 

**Example Use Case:**
Instead of individually granting 50 department members access to a new share drive (time-consuming and difficult to audit), a sysadmin uses or creates a group and grants that group permissions. All group members inherit these permissions through membership. Permissions can be modified or revoked by simply removing users from the group, leaving others unaffected.

**Group Characteristics:**

Groups in Active Directory have two fundamental characteristics:

1. **Group Type**: Defines the group's purpose
2. **Group Scope**: Shows how the group can be used within the domain or forest

**Main Group Types:**
- **Security groups**
- **Distribution groups**

<img width="1018" height="510" alt="image" src="https://github.com/user-attachments/assets/e1c30967-755a-4576-984b-dbd6ec1982b8" />

The `Security groups` type is primarily for ease of assigning permissions and rights to a collection of users instead of one at a time. They simplify management and reduce overhead when assigning permissions and rights for a given resource. All users added to a security group will inherit any permissions assigned to the group, making it easier to move users in and out of groups while leaving the group's permissions unchanged.

The `Distribution groups` type is used by email applications such as Microsoft Exchange to distribute messages to group members. They function much like mailing lists and allow for auto-adding emails in the "To" field when creating an email in Microsoft Outlook. This type of group cannot be used to assign permissions to resources in a domain environment.

---

## Group Scopes

3 different **group scopes** can be assigned when creating a new group:

**1. Domain Local Group**
- Can only manage permissions to domain resources in the domain where it was created
- Cannot be used in other domains
- **CAN** contain users from **OTHER** domains
- Can be nested into other local groups but **NOT** into global groups

**2. Global Group**
- Can grant access to resources in **another domain**
- Can only contain accounts from the domain where it was created
- Can be added to both other global groups and local groups

**3. Universal Group**
- Can manage resources distributed across **multiple domains**
- Can be given permissions to any object within the same **forest**
- Available to all domains within an organization
- Can contain users from any domain
- Stored in the Global Catalog (GC)

**Universal Group Best Practices:**
Adding or removing objects from universal groups triggers **forest-wide replication**. Administrators should maintain other groups (like global groups) as members of universal groups rather than individual users, because:
- Global group membership within universal groups changes less frequently than individual user membership
- Replication is only triggered at the domain level when users are removed from global groups
- Managing individual users/computers in universal groups triggers forest-wide replication for every change, creating excessive network overhead

### AD Group Scope Examples
```
PS C:\htb> Get-ADGroup  -Filter * |select samaccountname,groupscope

samaccountname                           groupscope
--------------                           ----------
Administrators                          DomainLocal
Users                                   DomainLocal
Guests                                  DomainLocal
Print Operators                         DomainLocal
Backup Operators                        DomainLocal
Replicator                              DomainLocal
Remote Desktop Users                    DomainLocal
Network Configuration Operators         DomainLocal
Distributed COM Users                   DomainLocal
IIS_IUSRS                               DomainLocal
Cryptographic Operators                 DomainLocal
Event Log Readers                       DomainLocal
Certificate Service DCOM Access         DomainLocal
RDS Remote Access Servers               DomainLocal
RDS Endpoint Servers                    DomainLocal
RDS Management Servers                  DomainLocal
Hyper-V Administrators                  DomainLocal
Access Control Assistance Operators     DomainLocal
Remote Management Users                 DomainLocal
Storage Replica Administrators          DomainLocal
Domain Computers                             Global
Domain Controllers                           Global
Schema Admins                             Universal
Enterprise Admins                         Universal
Cert Publishers                         DomainLocal
Domain Admins                                Global
Domain Users                                 Global
Domain Guests                                Global

<SNIP>
```

Group scopes can be changed, but there are a few caveats:
- A Global Group can only be converted to a Universal Group if it is NOT part of another Global Group.
- A Domain Local Group can only be converted to a Universal Group if the Domain Local Group does NOT contain any other Domain Local Groups as members.
- A Universal Group can be converted to a Domain Local Group without any restrictions.
- A Universal Group can only be converted to a Global Group if it does NOT contain any other Universal Groups as members.

---

## Built-in vs. Custom Groups

Several built-in security groups with **Domain Local Group** scope are created when a domain is established. These groups serve specific administrative purposes and **only allow user accounts**—group nesting (groups within groups) is not permitted.

**Examples:**
- **Domain Admins**: A **Global** security group containing only accounts from its own domain
- **Administrators**: A **Domain Local** group used when cross-domain administration is needed (e.g., allowing a domain B account to perform administrative functions on a domain A controller)

**Custom Groups:**
While Active Directory includes many prepopulated groups, most organizations create additional security and distribution groups for their own purposes. 

**Automated Group Creation:**
Changes or additions to the AD environment can trigger automatic group creation. For example, adding Microsoft Exchange creates various security groups—some highly privileged—that can be exploited for privileged domain access if not properly managed.

---

## Nested Group Membership

Nested group membership is a critical AD concept. A Domain Local Group can be a member of another Domain Local Group in the same domain. Through this membership, users may inherit privileges not directly assigned to their account or even their immediate group, but rather from the parent group their group belongs to.

This can lead to unintended privileges that are difficult to uncover without in-depth domain assessment. Tools like **BloodHound** are particularly useful for revealing privileges inherited through multiple group nestings—essential for penetration testers uncovering misconfigurations and for sysadmins gaining visual insights into domain security posture.

**Example:**

Though `DCorner` is not a direct member of `Helpdesk Level 1`, their membership in `Help Desk` grants them the same privileges as any `Helpdesk Level 1` member. In this case, they inherit the ability to add members to the `Tier 1 Admins` group (`GenericWrite` privilege).

If `Tier 1 Admins` has elevated domain privileges, it becomes a key penetration testing target. An attacker could add their account to this group and obtain privileges like local administrator access to hosts for further lateral movement.

**Examining Nested Groups via BloodHound:**
<img width="1370" height="494" alt="image" src="https://github.com/user-attachments/assets/8008963e-a16e-45fb-8458-0cd4bacdbec8" />

---

## Important Group Attributes

Like users, groups have many `attributes`. Some of the most `important group attributes` include:
- `cn`: The cn or Common-Name is the name of the group in Active Directory Domain Services.
- `member`: Which user, group, and contact objects are members of the group.
- `groupType`: An integer that specifies the group type and scope.
- `memberOf`: A listing of any groups that contain the group as a member (nested group membership).
- `objectSid`: This is the security identifier or SID of the group, which is the unique value used to identify the group as a security principal.

---
