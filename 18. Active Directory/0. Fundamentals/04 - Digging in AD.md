# Table of Contents

- [Security in Active Directory](#security-in-active-directory)
  - [General Active Directory Hardening Measures](#general-active-directory-hardening-measures)
    - [LAPS](#laps)
    - [Audit Policy Settings (Logging and Monitoring)](#audit-policy-settings-logging-and-monitoring)
    - [Group Policy Security Settings](#group-policy-security-settings)
    - [Update Management (SCCM/WSUS)](#update-management-sccmwsus)
    - [Group Managed Service Accounts (gMSA)](#group-managed-service-accounts-gmsa)
    - [Security Groups](#security-groups)
    - [Account Separation](#account-separation)
    - [Password Complexity Policies + Passphrases + 2FA](#password-complexity-policies--passphrases--2fa)
    - [Limiting Domain Admin Account Usage](#limiting-domain-admin-account-usage)
    - [Periodically Auditing and Removing Stale Users and Objects](#periodically-auditing-and-removing-stale-users-and-objects)
    - [Auditing Permissions and Access](#auditing-permissions-and-access)
    - [Audit Policies & Logging](#audit-policies--logging)
    - [Using Restricted Groups](#using-restricted-groups)
    - [Limiting Server Roles](#limiting-server-roles)
    - [Limiting Local Admin and RDP Rights](#limiting-local-admin-and-rdp-rights)
- [Examining Group Policy](#examining-group-policy)
  - [Group Policy Objects (GPOs)](#group-policy-objects-gpos)
  - [Example GPOs](#example-gpos)
  - [GPO Order of Precedence](#gpo-order-of-precedence)
  - [Group Policy Refresh Frequency](#group-policy-refresh-frequency)

---

# Security in Active Directory

Active Directory is built around central management and rapid information sharing across large user bases. However, **AD can be considered insecure by design** because of this focus. A default AD installation lacks many hardening measures, settings, and tools needed to secure the implementation.

In cybersecurity, the balance between Confidentiality, Integrity, and Availability (the **CIA Triad**) is critical. AD leans heavily toward **Availability** and **Confidentiality** at its core, requiring additional hardening to achieve proper balance.

<img width="1121" height="667" alt="image" src="https://github.com/user-attachments/assets/eb62c90b-72b3-4566-842a-e0c7b04ec8ad" />

**Hardening Approach:**

Microsoft's built-in features can be enabled/tweaked to harden AD against common attacks. However, the following list represents only the bare minimum—a proper **defense-in-depth** approach requires many additional general security hardening principles:

- Accurate asset inventory
- Vulnerability patches
- Configuration management
- Endpoint protection
- Security awareness training
- Network segmentation

The measures below are general AD security best practices that benefit any organization, though comprehensive AD defense requires much more depth.

---

## General Active Directory Hardening Measures

The Microsoft Local Administrator Password Solution (LAPS) is used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement.

### LAPS

The Local Administrator Password Solution (LAPS) is a free tool that rotates local administrator account passwords on fixed intervals (e.g., 12 hours, 24 hours). This reduces the impact of individual compromised hosts in AD environments. While organizations shouldn't rely solely on LAPS, when combined with other hardening measures and security best practices, it's highly effective for local administrator password management.

### Audit Policy Settings (Logging and Monitoring)

Organizations must implement logging and monitoring to detect and respond to unexpected changes or activities indicating attacks. Effective logging and monitoring can detect:

- Unauthorized user or computer additions
- AD object modifications
- Account password changes
- Unauthorized or non-standard system access
- Attacks like password spraying
- Advanced attacks such as modern Kerberos exploits

### Group Policy Security Settings

Group Policy Objects (GPOs) are virtual collections of policy settings applied to specific users, groups, and computers at the OU level. They can apply various security policies to harden Active Directory.

**Key Security Policy Types:**

**Account Policies** - Manage user account interactions with the domain, including password policy, account lockout policy, and Kerberos settings (e.g., Kerberos ticket lifetime).

**Local Policies** - Apply to specific computers and include:
- Security event audit policy
- User rights assignments (privileges on hosts)
- Specific security settings: driver installation ability, administrator/guest account enablement, account renaming, printer installation restrictions, removable media usage, network access and security controls

**Software Restriction Policies** - Control what software can run on hosts.

**Application Control Policies** - Control which applications specific users/groups can run, including blocking executables, Windows Installer files, and scripts. Administrators use **AppLocker** to restrict application and file types. Organizations commonly block CMD and PowerShell access for users not requiring them for daily tasks. While these policies are imperfect and often bypassable, they're necessary for defense-in-depth strategies.

**Advanced Audit Policy Configuration** - Audit activities including file access/modification, account logon/logoff, policy changes, privilege usage, and more.

**Advanced Audit Policy:**
<img width="1410" height="727" alt="image" src="https://github.com/user-attachments/assets/b794e906-2fa4-4494-8441-796023f6ae78" />

### Update Management (SCCM/WSUS)

Proper patch management is critical for organizations running Windows/Active Directory systems. 

**Windows Server Update Service (WSUS)** - Installed as a Windows Server role to minimize manual patching tasks.

**System Center Configuration Manager (SCCM)** - Paid solution requiring WSUS role installation, offering more features than standalone WSUS.

Patch management solutions ensure timely deployment and maximize coverage, preventing hosts from missing critical security patches. Manual patching methods are time-consuming for large environments and risk leaving vulnerable systems unpatched.

### Group Managed Service Accounts (gMSA)

gMSAs are domain-managed accounts offering higher security than other service accounts for non-interactive applications, services, processes, and automated tasks requiring credentials. Features include:

- Automatic password management with 120-character domain controller-generated passwords
- Regular password changes without user knowledge required
- Credential use across multiple hosts

### Security Groups

Security groups provide easy network resource access assignment. They assign specific rights to groups (rather than individual users), determining what members can do within the AD environment.

Active Directory automatically creates default security groups during installation (e.g., Account Operators, Administrators, Backup Operators, Domain Admins, Domain Users). These groups also assign resource permissions (file shares, folders, printers, documents).

Security groups enable granular permission assignment en masse rather than individual user management.

**Built-in AD Security Groups:**
<img width="1349" height="736" alt="image" src="https://github.com/user-attachments/assets/a69f821c-5889-4fac-8811-82d8b208e30a" />

### Account Separation

Administrators must maintain two separate accounts:

1. **Day-to-day account** (e.g., `sjones`) - For email, document creation, and regular work
2. **Administrative account** (e.g., `sjones_adm`) - For administrative tasks on secure administrative hosts

This ensures that if a user's host is compromised (e.g., through phishing), attackers are limited to that host without obtaining highly privileged credentials with extensive domain access. Different passwords for each account are essential to mitigate password reuse attacks if the non-admin account is compromised.

### Password Complexity Policies + Passphrases + 2FA

Organizations should use passphrases or large randomly generated passwords via enterprise password managers. Standard 7-8 character passwords can be cracked offline very quickly using GPU-powered tools like Hashcat. Shorter, less complex passwords are also vulnerable to password spraying attacks.

**AD Password Complexity Rules Are Insufficient:**
The password `Welcome1` meets standard complexity rules (3 of 4: uppercase, lowercase, number, special character) but would be an early password spraying attempt. Organizations should implement password filters to disallow:
- Months/seasons
- Company names
- Common words (e.g., "password," "welcome")

**Minimum Password Length:**
- Standard users: At least 12 characters
- Administrators/service accounts: Ideally longer

**Multi-Factor Authentication (MFA):**
Implement MFA for Remote Desktop Access to all hosts to limit lateral movement attempts relying on GUI access.

### Limiting Domain Admin Account Usage

Domain Admin accounts should **only** log into Domain Controllers—not personal workstations, jump hosts, web servers, etc. This significantly reduces attack impact and cuts potential attack paths if hosts are compromised, ensuring Domain Admin passwords aren't left in memory across the environment.

### Periodically Auditing and Removing Stale Users and Objects

Organizations must periodically audit Active Directory to remove or disable unused accounts. Example: a privileged service account created years ago with a weak, unchanged password that's no longer in use. Even if password policies have since improved, such accounts provide easy footholds for lateral movement or privilege escalation.

### Auditing Permissions and Access

Perform regular access control audits to ensure users only have access required for daily work. Audit areas include:
- Local admin rights
- Number of Domain Admins (are 30 really necessary?)
- Enterprise Admins
- File share access
- User rights (privileged security group membership)

This limits the attack surface.

### Audit Policies & Logging

Domain visibility is essential. Achieve this through robust logging and rules detecting anomalous activity such as:
- Multiple failed login attempts (potential password spraying)
- Kerberoasting attack indicators
- Active Directory enumeration

Familiarize yourself with Microsoft's Audit Policy Recommendations for detecting compromise.

### Using Restricted Groups

Restricted Groups allow administrators to configure group membership via Group Policy for purposes such as:
- Controlling local administrator group membership on all domain hosts (restricting to only local Administrator account and Domain Admins)
- Controlling membership in highly privileged groups (Enterprise Admins, Schema Admins, and other key administrative groups)

### Limiting Server Roles

Avoid installing additional roles on sensitive hosts. Examples:
- Don't install Internet Information Server (IIS) on Domain Controllers—use separate standalone web servers instead
- Don't host web applications on Exchange mail servers
- Separate web servers and database servers onto different hosts

Role separation reduces the impact of successful attacks by limiting the attack surface.

### Limiting Local Admin and RDP Rights

Organizations must tightly control which users have local admin rights on which computers, achievable using Restricted Groups. 

**Common Mistake:** Granting the entire Domain Users group local admin rights on hosts. This allows attackers compromising **ANY** account (even low-privileged ones) to:
- Access hosts as local admin
- Obtain sensitive data
- Steal high-privileged domain account credentials from memory if other users are logged in

**RDP Rights:** Excessive Remote Desktop rights increase risks of:
- Sensitive data exposure
- Privilege escalation attacks leading to further compromise

---

# Examining Group Policy

Group Policy is a Windows feature providing administrators with advanced settings applicable to both user and computer accounts. Every Windows host has a Local Group Policy editor for managing local settings, but our focus is on Group Policy in a domain context for managing Active Directory users and computers.

Group Policy is powerful for managing and configuring user settings, operating systems, and applications. From a security perspective, it's one of the best tools for broadly affecting enterprise security posture. Active Directory is **not secure "out of the box,"** and properly used Group Policy is crucial for defense-in-depth strategies.

**Security Implications:**

**Defensive Use:** Excellent tool for managing domain security when properly configured.

**Offensive Abuse:** Attackers gaining rights over Group Policy Objects can achieve:
- Lateral movement
- Privilege escalation
- Full domain compromise (if leveraged to take over high-value users or computers)
- Persistence within networks

Understanding Group Policy mechanics provides advantages against attackers and helps penetration testers identify nuanced misconfigurations others might miss.

---

## Group Policy Objects (GPOs)

A Group Policy Object (GPO) is a virtual collection of policy settings applicable to **user(s)** or **computer(s)**. GPOs include policies such as:

- Screen lock timeout
- Disabling USB ports
- Enforcing custom domain password policies
- Installing software
- Managing applications
- Customizing remote access settings
- And much more

**GPO Characteristics:**

- Each GPO has a unique name and GUID (unique identifier)
- Can be linked to specific OUs, domains, or sites
- A single GPO can link to multiple containers
- Any container can have multiple GPOs applied
- Applied to individual users, hosts, or groups by applying directly to an OU
- Contains one or more Group Policy settings that apply at the local machine level or within Active Directory context

---

## Example GPOs

Some examples of things we can do with GPOs may include:

- Establishing different password policies for service accounts, admin accounts, and standard user accounts using separate GPOs
- Preventing the use of removable media devices (such as USB devices)
- Enforcing a screensaver with a password
- Restricting access to applications that a standard user may not need, such as cmd.exe and PowerShell
- Enforcing audit and logging policies
- Blocking users from running certain types of programs and scripts
- Deploying software across a domain
- Blocking users from installing unapproved software
- Displaying a logon banner whenever a user logs into a system
- Disallowing LM hash usage in the domain
- Running scripts when computers start/shutdown or when a user logs in/out of their machine

Let's use as example a default Windows Server 2008 Active Directory implementation, password complexity is enforced by default. The password complexity requirements are as follows:

- Passwords must be at least 7 characters long.
- Passwords must contain characters from at least three of the following four categories:
- Uppercase characters (A-Z)
- Lowercase characters (a-z)
- Numbers (0-9)
- Special characters (e.g. !@#$%^&*()_+|~-=`{}[]:";'<>?,./)

These are just a few examples of what can be done with Group Policy. There are hundreds of settings that can be applied within a GPO, which can get extremely granular. For example, below are some options that we can set for Remote Desktop sessions.

**RDP GPO Settings:**
<img width="1012" height="559" alt="image" src="https://github.com/user-attachments/assets/0990a930-24af-49dc-9994-002382e19dcf" />

GPO settings are processed using the hierarchical structure of AD and are applied using the `Order of Precedence` rule as seen in the table below:

**Order of Precedence:**
|Level|	Description|
|-|-|
|**Local Group Policy**|Policies defined directly to the host locally outside the domain. Any settings here are overwritten if similar settings are defined at higher levels.|
|**Site Policy**|Policies specific to the Enterprise Site where the host resides. Enterprise environments can span large campuses or countries, so sites may have differentiated policies. Example: A building performing secret/restricted research requiring higher authorization for resource access can specify site-level settings linked to prevent domain policy overwrites. Also useful for site-specific printer and share mapping.|
|**Domain-wide Policy**|Settings applied across the entire domain. Examples: password policy complexity, desktop backgrounds for all users, Notice of Use and Consent to Monitor banners at login screens.|
|**Organizational Unit (OU)**|Settings affecting users and computers belonging to specific OUs. Contains role-specific unique settings. Examples: HR-only share drive mapping, specific resource access (printers), IT admin PowerShell/command-prompt usage.|
|**Nested OU Policies**|Settings reflecting special permissions for objects within nested OUs. Example: Security Analysts receiving specific AppLocker policy settings differing from standard IT AppLocker settings.|

**Group Policy Management**

Group Policy can be managed through:
- Group Policy Management Console (found under Administrative Tools in the Start Menu on domain controllers)
- Custom applications
- PowerShell GroupPolicy module via command line

**Default Domain Policy**
The default GPO automatically created and linked to the domain. It has the highest precedence of all GPOs and applies by default to all users and computers. Best practice: use this default GPO to manage default settings applying domain-wide.

**Default Domain Controllers Policy**
Also automatically created with a domain, this GPO sets baseline security and auditing settings for all domain controllers in the domain. It can be customized as needed like any GPO.

---

## GPO Order of Precedence

GPOs are processed **top-down** from a domain organizational standpoint:

1. GPO linked at the highest level (e.g., domain level) is processed **first**
2. GPOs linked to child OUs are processed next
3. GPO linked directly to an OU containing user/computer objects is processed **last**

**Key Principle:** 
A GPO attached to a specific OU has **precedence** over a GPO attached at the domain level because it's processed last and can override settings in GPOs higher in the domain hierarchy.

**Computer vs. User Policy:**
A setting configured in **Computer policy** always has **higher priority** than the same setting applied to a user.

<img width="1106" height="595" alt="image" src="https://github.com/user-attachments/assets/9f4bd9ca-1cb0-4ebe-bc64-89f42876fba4" />

Let's look at another example using the Group Policy Management Console on a Domain Controller. In this image, we see several GPOs. The `Disabled Forced Restarts` GPO will have precedence over the `Logon Banner` GPO since it would be processed last. Any settings configured in the `Disabled Forced Restarts` GPO could potentially override settings in any GPOs higher up in the hierarchy (including those linked to the `Corp` OU).

<img width="1330" height="770" alt="image" src="https://github.com/user-attachments/assets/378e91ad-2c7f-4576-8894-82f4aa95cee2" />

This image also shows an example of several GPOs being linked to the `Corp` OU. When multiple GPOs are linked to an OU, they're processed based on **Link Order**:

- The GPO with the **lowest Link Order is processed last**
- **Link Order 1** has the **highest precedence**, then 2, 3, etc.

**Example:** If `Disallow LM Hash`, `Block Removable Media`, and `Disable Guest Account` GPOs are linked to the Corp OU, the `Disallow LM Hash` GPO (Link Order 1) has precedence and is processed first.

**Enforced Option**

The `Enforced` option can be specified to enforce settings in a specific GPO:

- When set, policy settings in GPOs linked to lower OUs **CANNOT** override the enforced settings
- If a GPO at the domain level has `Enforced` selected, its settings apply to all domain OUs and cannot be overridden by lower-level OU policies
- Previously called `No Override` (set on the container in Active Directory Users and Computers)

**Example:** An `Enforced` `Logon Banner` GPO takes precedence over GPOs linked to lower OUs and will not be overridden.

**Enforced GPO Policy Precedence:**
<img width="1023" height="399" alt="image" src="https://github.com/user-attachments/assets/aa9483dd-3bfa-4aef-a085-2a7b4e518178" />

Regardless of which GPO is set to enforced, if the `Default Domain Policy` GPO is enforced, it will take precedence over all GPOs at all levels.

**Default Domain Policy Override:**
<img width="1022" height="328" alt="image" src="https://github.com/user-attachments/assets/c97b6e1a-2833-4007-9ba2-16b91ecfb7b2" />

It is also possible to set the `Block inheritance` option on an OU. If this is specified for a particular OU, then policies higher up (such as at the domain level) will NOT be applied to this OU. If both options are set, the `No Override` option has precedence over the `Block inheritance` option. Here is a quick example. The `Computers` OU is inheriting GPOs set on the `Corp` OU in the below image.

<img width="1021" height="362" alt="image" src="https://github.com/user-attachments/assets/3ada562e-2ecc-4946-a1ee-6dc9522ff5a2" />

If the `Block Inheritance` option is chosen, we can see that the 3 GPOs applied higher up to the `Corp` OU are no longer enforced on the `Computers` OU.

**Block Inheritance:**
<img width="1022" height="383" alt="image" src="https://github.com/user-attachments/assets/910e6968-82f1-4b81-8b42-2b776410324b" />

---

## Group Policy Refresh Frequency

When a new GPO is created, settings aren't applied immediately. Windows performs periodic Group Policy updates with the following default intervals:

- **Users and computers**: Every 90 minutes with a randomized offset of +/- 30 minutes
- **Domain controllers**: Every 5 minutes

When a new GPO is created and linked, it could take up to **2 hours (120 minutes)** for settings to take effect. The random +/- 30 minute offset prevents overwhelming domain controllers by avoiding simultaneous Group Policy requests from all clients.

**Manual Update:**
The command `gpupdate /force` triggers an immediate update process, comparing currently applied GPOs against the domain controller and modifying or skipping them based on changes since the last automatic update.

**Modifying Refresh Interval:**
The default refresh interval can be changed via Group Policy at:
`Computer Configuration --> Policies --> Administrative Templates --> System --> Group Policy --> Set Group Policy refresh interval for computers`

**Important:** Don't set refresh intervals too frequently, as this can cause network congestion and replication issues.

<img width="1148" height="627" alt="image" src="https://github.com/user-attachments/assets/fa69d824-41a3-4f69-b315-b934fa1238d0" />
