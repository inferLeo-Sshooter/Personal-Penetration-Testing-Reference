

# 1. Active Directory Overview

## Concept

Active Directory (AD) is a directory service for Windows networks that enables centralized management of organizational resources—users, computers, groups, network devices, file shares, group policies, and trusts. AD handles authentication and authorization within Windows domains but has become an increasing attack target. Designed for backward-compatibility, many features are not "secure by default" and can be easily misconfigured, allowing attackers to move laterally and vertically within networks.

AD is essentially a large read-only database accessible to all domain users, regardless of privilege level. Any basic user account can enumerate most AD objects, making proper security crucial. Multiple attacks can be executed with just a standard domain account, emphasizing the need for defense-in-depth strategies, careful security planning, AD hardening, network segmentation, and least privilege principles. Despite these challenges, AD makes information easily accessible for administrators and users while being highly scalable, supporting millions of objects per domain and allowing additional domains as organizations grow.

<img width="1026" height="857" alt="image" src="https://github.com/user-attachments/assets/4008e950-3d0e-4f72-b79c-d829e054d369" />

---

# 2. Active Directory Fundamentals

## Active Directory Structure

**Active Directory** (AD) is a directory service for Windows networks that provides centralized management of organizational resources through a distributed, hierarchical structure. It manages users, computers, groups, network devices, file shares, group policies, servers, workstations, and trusts, while providing authentication and authorization within Windows domain environments.

**Active Directory Domain Services** (AD DS) stores directory data like usernames and passwords and controls access rights for authorized users and administrators. First released with Windows Server 2000, AD has become an increasing attack target due to its backward-compatible design, features that aren't secure by default, and management complexity that often leads to misconfigurations, especially in large environments.

Active Directory flaws and misconfigurations can be exploited to gain initial access, move laterally and vertically across networks, and access protected resources like databases, file shares, and source code. 

AD functions as a large database accessible to all domain users, regardless of privilege level. Even a basic user account with no special privileges can enumerate most AD objects, including but not limited to: 

| | |
|-|-|
|Domain Computers	|Domain Users|
|Domain Group Information	|Organizational Units (OUs)|
|Default Domain Policy	|Functional Domain Levels|
|Password Policy	|Group Policy Objects (GPOs)|
|Domain Trusts	|Access Control Lists (ACLs)|

---

Active Directory uses a hierarchical tree structure with a forest at the top containing one or more domains, which can have nested subdomains. The forest serves as the security boundary for all objects under administrative control.

A domain is a structure providing access to contained objects like users, computers, and groups. Domains include built-in Organizational Units (OUs) such as `Domain Controllers`, `Users`, and `Computers`, with the ability to create additional OUs as needed. OUs can contain objects and sub-OUs, enabling different group policy assignments.

At a very (simplistic) high level, an AD structure may look as follows:
```
INLANEFREIGHT.LOCAL/
├── ADMIN.INLANEFREIGHT.LOCAL
│   ├── GPOs
│   └── OU
│       └── EMPLOYEES
│           ├── COMPUTERS
│           │   └── FILE01
│           ├── GROUPS
│           │   └── HQ Staff
│           └── USERS
│               └── barbara.jones
├── CORP.INLANEFREIGHT.LOCAL
└── DEV.INLANEFREIGHT.LOCAL
```

Here we could say that `INLANEFREIGHT.LOCAL` is the root domain and contains the subdomains (either child or tree root domains) `ADMIN.INLANEFREIGHT.LOCAL`, `CORP.INLANEFREIGHT.LOCAL`, and `DEV.INLANEFREIGHT.LOCAL` as well as the other objects that make up a domain such as users, groups, computers, ...

It is common to see multiple domains (or forests) linked together via trust relationships in organizations that perform a lot of acquisitions. It is often quicker and easier to create a trust relationship with another domain/forest than recreate all new users in the current domain.

<img width="1125" height="743" alt="image" src="https://github.com/user-attachments/assets/2b1ba6e3-3368-441c-9f2e-6ec19c9f2420" />

The graphic illustrates two forests, `INLANEFREIGHT.LOCAL` and `FREIGHTLOGISTICS.LOCAL`, connected by a bidirectional trust that allows users in either forest to access resources in the other. Each forest contains multiple child domains under its root domain.

While root domains trust their respective child domains, **child domains across forests don't automatically trust each other**. For example, a user in `admin.dev.freightlogistics.local` cannot authenticate to `wh.corp.inlanefreight.local` by default, despite the bidirectional trust between the top-level domains. Direct communication between these child domains would require establishing a separate trust relationship.

---

## Active Directory Terminology

> - `schema` : "Blueprint" of an Active Directory environment
> - `Service Principal Name` : uniquely identifies a Service instance
> - `tombstone` : holds deleted objects
> - `ntds.dit` : contains the hashes of passwords for all users in a domain


**Object** - Any resource in an AD environment (OUs, printers, users, domain controllers, etc.).

**Attributes** - Characteristics defining each object. For example, computer objects have hostname and DNS name attributes. All attributes have associated LDAP names for queries (e.g., displayName, givenName).

**Schema** - The blueprint defining what object types can exist in AD and their attributes. Objects are created from classes (instantiation); for example, computer RDS01 is an instance of the "computer" class.

**Domain** - A logical group of objects (computers, users, OUs, groups). Domains can operate independently or connect via trust relationships.

**Forest** - A collection of AD domains and the topmost container holding all AD objects. Forests operate independently but may have trust relationships with other forests.

**Tree** - A collection of AD domains beginning at a single root domain. Domains in a tree share boundaries with parent-child trust relationships. Trees in the same forest cannot share namespaces. Let's say we have two trees in an AD forest: `inlanefreight.local` and `ilfreight.local`. A child domain of the first would be `corp.inlanefreight.local` while a child domain of the second could be `corp.ilfreight.local`. All domains in a tree share a standard Global Catalog which contains all information about objects that belong to the tree.

**Container** - Objects that hold other objects with a defined place in the directory hierarchy.

**Leaf** - Objects that don't contain other objects; found at the end of the subtree hierarchy.

**GUID (Global Unique Identifier)** - A unique 128-bit value assigned to every AD object upon creation. GUIDs never change and provide the most accurate way to search for objects.

**Security Principals** - Anything the OS can authenticate (users, computer accounts, processes/threads). These domain objects manage access to resources within the domain.

**SID (Security Identifier)** - A unique identifier for security principals or groups, issued by the domain controller. SIDs are used once and never reused, even after deletion.

**Distinguished Name (DN)** - The full path to an AD object (e.g., `cn=bjones`, `ou=IT`, `ou=Employees`, `dc=inlanefreight`, `dc=local`), describing its location in the directory hierarchy.

**Relative Distinguished Name (RDN)** - A single component of the Distinguished Name identifying an object as unique at its current hierarchy level. In `cn=bjones,ou=IT,dc=inlanefreight,dc=local`, "bjones" is the RDN. AD doesn't allow duplicate names under the same parent container, but objects with identical RDNs can exist in different locations with different DNs (e.g., `cn=bjones,dc=dev,dc=inlanefreight,dc=local` would be recognized as different from `cn=bjones,dc=inlanefreight,dc=local`).

<img width="1149" height="714" alt="image" src="https://github.com/user-attachments/assets/17dba273-7f1e-4b57-be53-7d13657c6591" />

**sAMAccountName** - The user's logon name (e.g., `bjones`). Must be unique and 20 or fewer characters.

**userPrincipalName** - Alternative user identifier in prefix@suffix format (e.g., `bjones@inlanefreight.local`). Not mandatory.

**FSMO Roles** - Flexible Single Master Operation roles that prevent conflicts between Domain Controllers. Five roles exist: `Schema Master` and `Domain Naming Master` (one per forest), and `RID Master`, `PDC Emulator`, and `Infrastructure Master` (one per domain). These ensure smooth replication and uninterrupted authentication/authorization. All five roles are assigned to the first DC in the forest root domain in a new AD forest. Each time a new domain is added to a forest, only the RID Master, PDC Emulator, and Infrastructure Master roles are assigned to the new domain. FSMO roles are typically set when domain controllers are created, but sysadmins can transfer these roles if needed. These roles help replication in AD to run smoothly and ensure that critical services are operating correctly.

**Global Catalog (GC)** - A domain controller storing copies of all objects in an AD forest: full copies of current domain objects and partial copies from other domains. Enables authentication and forest-wide object searches.

**Read-Only Domain Controller (RODC)** - Has a read-only AD database with no cached passwords (except its own). No changes are pushed from an RODC, providing security for branch offices with reduced replication traffic.

**Replication** - The process of updating and transferring AD objects between Domain Controllers, managed by the Knowledge Consistency Checker (KCC) service to ensure synchronization and backup.

**Service Principal Name (SPN)** - Uniquely identifies a service instance for Kerberos authentication, allowing client applications to request service authentication without knowing the account name.

**Group Policy Object (GPO)** - Virtual collections of policy settings with unique GUIDs. Can contain local file system or AD settings applied to users and computers domain-wide or at the OU level.

**Access Control List (ACL)** - Ordered collection of Access Control Entries (ACEs) that apply to an object.

**Access Control Entries (ACEs)** - Identifies trustees (users, groups, sessions) and lists their allowed, denied, or audited access rights.

**Discretionary Access Control List (DACL)** - Defines which security principals are granted or denied object access. Contains ACEs checked in sequence. Objects without DACLs grant full access to everyone; empty DACLs deny all access.

**System Access Control Lists (SACL)** - Enables administrators to log access attempts to secured objects by specifying which attempts generate security event log records.

**Fully Qualified Domain Name (FQDN)** - Complete name for a computer/host in [hostname].[domain].[tld] format (e.g., DC01.INLANEFREIGHT.LOCAL), used to locate hosts in AD without IP addresses.

**Tombstone** - Container holding deleted AD objects. Deleted objects remain for the Tombstone Lifetime (default 60-180 days) with isDeleted=TRUE, then are permanently removed. Objects can be recovered but lose most attributes.

**AD Recycle Bin** - Introduced in Windows Server 2008 R2 to preserve deleted objects (default 60 days) with most attributes intact, enabling easier restoration without backups or DC reboots.

**SYSVOL** - Folder/share storing public domain files (system policies, Group Policy settings, logon/logoff scripts). Contents replicate to all DCs via File Replication Services (FRS).

**AdminSDHolder** - Manages ACLs for privileged built-in group members. The SDProp process runs hourly on the PDC Emulator to ensure correct ACLs are applied to protected groups.

**dsHeuristics** - String value on the Directory Service object defining forest-wide configuration settings, including which groups to exclude from the Protected Groups list.

**adminCount** - Attribute determining SDProp protection. Value of 1 means protected; 0 or unspecified means unprotected. Attackers target accounts with adminCount=1 as they're often privileged.

**Active Directory Users and Computers (ADUC)** - GUI console for managing users, groups, computers, and contacts in AD.

**ADSI Edit** - GUI tool for managing AD objects with deeper access than ADUC. Can set/delete any attribute, add/remove/move objects. Requires careful use.

**sIDHistory** - Holds previous SIDs assigned to an object, typically used in migrations. Can be abused if insecure, allowing attackers to gain prior elevated access if SID Filtering isn't enabled.

**NTDS.DIT** - The heart of Active Directory, stored at `C:\Windows\NTDS\` on Domain Controllers. Database containing AD data including user/group objects and password hashes. Attackers target this for pass-the-hash attacks or offline cracking.

**MSBROWSE** - Obsolete Microsoft networking protocol from early Windows LANs for browsing services. Modern networks use SMB for file/printer sharing and CIFS for browsing.

---

## Active Directory Objects










