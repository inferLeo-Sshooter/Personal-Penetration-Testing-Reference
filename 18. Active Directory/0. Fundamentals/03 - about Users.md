
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
















