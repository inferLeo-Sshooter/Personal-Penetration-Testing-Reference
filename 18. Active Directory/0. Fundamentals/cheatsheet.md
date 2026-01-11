
# Introduction to Active Directory - Cheat Sheet

## Basic Commands Needed

```bash
xfreerdp /v:<IP> /u:<User> /p:<Password>
ping <IP>
```

## General Commands

### Get-Module
Returns a list of loaded PowerShell Modules.

### Get-Command -Module ActiveDirectory
Lists commands for the module specified.

### Get-Help <cmd-let>
Shows help syntax for the cmd-let specified.

### Import-Module ActiveDirectory
Imports the Active Directory Module.

---

## Active Directory PowerShell Commands

### AD User Commands

**Add a user to AD and set attributes:**
```powershell
New-ADUser -Name "first last" -Accountpassword (Read-Host -AsSecureString "Super$ecurePassword!") -Enabled $true -OtherAttributes @{'title'="Analyst";'mail'="f.last@domain.com"}
```

**Remove a user from AD:**
```powershell
Remove-ADUser -Identity <name>
```

**Unlock a user account:**
```powershell
Unlock-ADAccount -Identity <name>
```

**Set the password of an AD user:**
```powershell
Set-ADAccountPassword -Identity <'name'> -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "NewP@ssw0rdReset!" -Force)
```

**Force a user to change their password at next logon:**
```powershell
Set-ADUser -Identity amasters -ChangePasswordAtLogon $true
```

---

### AD Group Commands

**Create a new AD OU container:**
```powershell
New-ADOrganizationalUnit -Name "name" -Path "OU=folder,DC=domain,DC=local"
```

**Create a new security group:**
```powershell
New-ADGroup -Name "name" -SamAccountName analysts -GroupCategory Security -GroupScope Global -DisplayName "Security Analysts" -Path "CN=Users,DC=domain,DC=local" -Description "Members of this group are Security Analysts under the IT OU"
```

**Add an AD user to a group:**
```powershell
Add-ADGroupMember -Identity 'group name' -Members 'ACepheus,OStarchaser,ACallisto'
```

---

### GPO Commands

**Copy a GPO:**
```powershell
Copy-GPO -SourceName "GPO to copy" -TargetName "Name"
```

**Link an existing GPO to a specific OU (creates new link):**
```powershell
New-GPLink -Name "Security Analysts Control" -Target "ou=Security Analysts,ou=IT,OU=HQ-NYC,OU=Employees,OU=Corp,dc=INLANEFREIGHT,dc=LOCAL" -LinkEnabled Yes
```
*The `-LinkEnabled Yes` ensures that once the link has been established, the GPO and its policies are actually enabled (as it is possible for a GPLink to exist but be disabled).*

**Set/modify an existing GPO link:**
```powershell
Set-GPLink -Name "Security Analysts Control" -Target "ou=Security Analysts,ou=IT,OU=HQ-NYC,OU=Employees,OU=Corp,dc=INLANEFREIGHT,dc=LOCAL" -LinkEnabled Yes
```

---

### Computer Commands

**Add a new computer to the domain:**
```powershell
Add-Computer -DomainName 'INLANEFREIGHT.LOCAL' -Credential 'INLANEFREIGHT\HTBstudent_adm' -Restart
```

**Remotely add a computer to a domain:**
```powershell
Add-Computer -ComputerName 'name' -LocalCredential '.\localuser' -DomainName 'INLANEFREIGHT.LOCAL' -Credential 'INLANEFREIGHT\htb-student_adm' -Restart
```

**Check for a computer and view its properties:**
```powershell
Get-ADComputer -Identity "name" -Properties * | select CN,CanonicalName,IPv4Address
```

---


